"""关联论文 Agent（富化维度②，PROJECT_PLAN.md §5.6 ``paper_linker.py``）。

流程（L3 允许 LLM，但**只做相关性判定**，不做检索决策）：

1. 由漏洞事实生成检索关键词（:func:`~aisec_intel.enrich.tools.search_tools.paper_search_keywords`，纯函数）；
2. 检索论文（:func:`~aisec_intel.enrich.tools.search_tools.search_papers`，只读 ``raw_item``）；
3. LLM 判定相关性（``with_structured_output(PaperRelevanceBatch)``，闸门①+②）；
4. 产出 ``PaperVulnLink`` 列表（相关且置信度达阈值），写入 ``EnrichedVuln.related_papers``。

**降级路径（无 LLM / 判定失败）**：按检索命中分（``PaperHit.score`` / ``matched``）确定性折算置信度，
``relation`` 固定 ``mentions``，并在 ``errors`` 留痕——保证断网 / 无 Key 时链路仍可走通（§3.3 思路），
且**不写任何猜测性结论**（置信度上限 0.6）。
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.enrich.tools.search_tools import paper_search_keywords
from aisec_intel.llm.schemas import StructuredOutputError, invoke_structured
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import PaperRelevanceBatch
from aisec_intel.models.enriched_vuln import AgentStep
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.repositories.paper_repo import PaperHit

logger = get_logger(__name__)

AGENT_NAME: str = "paper_linker"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG_DEGRADED: str = "retrieval-only"
"""降级路径的模型标识（未调用 LLM 时使用）。"""

SearchFn = Callable[[Sequence[str], int], Awaitable[list[PaperHit]]]
"""论文检索函数签名：``(keywords, limit) -> list[PaperHit]``。"""

DEFAULT_MIN_CONFIDENCE: float = 0.4
"""采纳关联的最低置信度（低于该值的候选被丢弃）。"""

DEGRADED_CONFIDENCE_CAP: float = 0.6
"""降级路径的置信度上限（无 LLM 判定时不得给出高置信结论）。"""

SYSTEM_PROMPT: str = (
    "你是漏洞情报分析员。判断给定候选论文是否与目标漏洞**直接相关**（同一漏洞、同一组件或同一攻击技术）。"
    "仅依据给定标题与摘要判断，不得臆测；无关候选一律 relevant=false。"
    "每篇给出 relation（mentions/proposes-attack/proposes-defense/evaluates/surveys）、"
    "confidence（0-1）与 evidence（可引用的摘要片段）。"
)


def degraded_confidence(hit: PaperHit, *, max_keywords: int = 6) -> float:
    """按检索命中情况折算置信度（降级路径，纯函数）。

    规则：``0.3 + 0.3 * (命中关键词数 / 关键词总数)``，上限 :data:`DEGRADED_CONFIDENCE_CAP`。

    Args:
        hit: 检索命中。
        max_keywords: 关键词总数（归一化用）。

    Returns:
        置信度，区间 ``[0.3, 0.6]``。
    """
    ratio = min(1.0, len(hit.matched) / max(1, max_keywords))
    return round(min(DEGRADED_CONFIDENCE_CAP, 0.3 + 0.3 * ratio), 3)


def build_link(
    *,
    paper_id: str,
    vuln_id: str,
    confidence: float,
    relation: str,
    evidence: str | None,
    evidence_refs: Sequence[str],
) -> PaperVulnLink:
    """构造「论文 ↔ 漏洞」关联边（统一入口，便于复用与测试）。

    Args:
        paper_id: 论文主键。
        vuln_id: 漏洞主键。
        confidence: 关联置信度。
        relation: 关联类型（``PaperRelation`` 字面量）。
        evidence: 支撑原文片段。
        evidence_refs: 证据标识（``trace_id`` / URL）。

    Returns:
        :class:`~aisec_intel.models.paper.PaperVulnLink`。
    """
    return PaperVulnLink(
        paper_id=paper_id,
        vuln_id=vuln_id,
        relation=relation,  # type: ignore[arg-type]
        confidence=confidence,
        evidence=evidence,
        evidence_refs=[str(ref) for ref in evidence_refs],
    )


class PaperLinkerAgent:
    """关联论文节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        limit: 单次检索返回的候选论文数上限。
        min_confidence: 采纳关联的最低置信度。
    """

    def __init__(
        self,
        *,
        search: SearchFn,
        structured_llm: Any | None = None,
        limit: int = 5,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        max_keywords: int = 6,
        model_tag: str = MODEL_TAG_DEGRADED,
    ) -> None:
        """初始化节点。

        Args:
            search: 论文检索函数（生产环境绑定只读 ``paper_repo``）。
            structured_llm: 结构化输出 Runnable（``provider.structured(PaperRelevanceBatch)``）；
                ``None`` 时走降级路径（仅按检索命中折算）。
            limit: 候选上限。
            min_confidence: 采纳阈值。
            max_keywords: 关键词上限。
            model_tag: 写入 ``AgentStep.model_used`` 的模型标识。
        """
        self._search = search
        self._llm = structured_llm
        self._limit = max(1, limit)
        self._min_confidence = min_confidence
        self._max_keywords = max_keywords
        self._model_tag = model_tag

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """执行论文检索与关联判定，返回状态增量。

        Args:
            state: 富化图状态（只读 ``unified_vuln``）。

        Returns:
            含 ``paper_hits`` / ``related_papers`` / ``agent_steps`` / ``errors`` 的增量字典。
        """
        started = time.perf_counter()
        vuln = state["unified_vuln"]
        keywords = paper_search_keywords(
            cwe_ids=vuln.cwe_ids,
            title=vuln.title,
            description=vuln.description,
            max_keywords=self._max_keywords,
        )
        errors: list[str] = []
        hits: list[PaperHit] = []
        if keywords:
            try:
                hits = await self._search(keywords, self._limit)
            except Exception as exc:  # noqa: BLE001 - 检索失败降级为空结果，不阻断链路
                errors.append(f"{AGENT_NAME}: 论文检索失败（{type(exc).__name__}: {exc}）")
                logger.warning(f"论文检索失败：{exc!r}")
        else:
            errors.append(f"{AGENT_NAME}: 关键词为空，跳过论文检索")

        links = await self._link(state, hits, errors)
        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=_aggregate_confidence(links),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used=self._model_tag if self._llm is not None else MODEL_TAG_DEGRADED,
            output_digest=f"keywords={len(keywords)} hits={len(hits)} links={len(links)}",
            error=errors[0] if errors else None,
        )
        return {
            "paper_hits": hits,
            "related_papers": links,
            "agent_steps": [step],
            "errors": errors,
        }

    async def _link(self, state: EnrichmentState, hits: list[PaperHit], errors: list[str]) -> list[PaperVulnLink]:
        """把候选论文判定为关联边（LLM 判定 + 失败降级）。

        Args:
            state: 富化图状态。
            hits: 检索候选。
            errors: 错误收集列表（原地追加）。

        Returns:
            关联边列表。
        """
        if not hits:
            return []
        if self._llm is None:
            return self._degraded_links(state, hits)

        from langchain_core.messages import HumanMessage, SystemMessage

        vuln = state["unified_vuln"]
        messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=_build_prompt(vuln, hits))]
        try:
            batch: PaperRelevanceBatch = await invoke_structured(self._llm, PaperRelevanceBatch, messages)
        except StructuredOutputError as exc:
            errors.append(f"{AGENT_NAME}: 相关性判定失败，降级为检索折算（{exc}）")
            logger.warning(f"论文相关性判定失败（降级）：{exc}")
            return self._degraded_links(state, hits)

        by_id = {hit.paper.paper_id: hit for hit in hits}
        links: list[PaperVulnLink] = []
        for item in batch.items:
            hit = by_id.get(item.paper_id)
            if hit is None or not item.relevant or item.confidence < self._min_confidence:
                continue
            links.append(
                build_link(
                    paper_id=item.paper_id,
                    vuln_id=vuln.vuln_id,
                    confidence=item.confidence,
                    relation=item.relation,
                    evidence=item.evidence or _abstract_of(hit),
                    evidence_refs=_evidence_refs(state, hit),
                )
            )
        return links

    def _degraded_links(self, state: EnrichmentState, hits: list[PaperHit]) -> list[PaperVulnLink]:
        """按检索命中折算关联（降级路径，无 LLM）。

        Args:
            state: 富化图状态。
            hits: 检索候选。

        Returns:
            关联边列表（置信度上限 ``DEGRADED_CONFIDENCE_CAP``）。
        """
        vuln = state["unified_vuln"]
        links = [
            build_link(
                paper_id=hit.paper.paper_id,
                vuln_id=vuln.vuln_id,
                confidence=degraded_confidence(hit, max_keywords=self._max_keywords),
                relation="mentions",
                evidence=_abstract_of(hit),
                evidence_refs=_evidence_refs(state, hit),
            )
            for hit in hits
        ]
        return [link for link in links if link.confidence >= self._min_confidence]


def _abstract_of(hit: PaperHit) -> str | None:
    """取论文摘要片段（截断 200 字符，避免大段入库）。

    Args:
        hit: 检索命中。

    Returns:
        摘要片段；无摘要时 ``None``。
    """
    abstract = hit.paper.abstract
    return abstract[:200] if abstract else None


def _evidence_refs(state: EnrichmentState, hit: PaperHit) -> list[str]:
    """组装证据标识（``trace_id`` + 论文链接，§10.2 不变式 5）。

    Args:
        state: 富化图状态。
        hit: 检索命中。

    Returns:
        证据标识列表。
    """
    refs = [state.get("trace_id") or state["unified_vuln"].vuln_id]
    if hit.paper.url:
        refs.append(hit.paper.url)
    return refs


def _build_prompt(vuln: UnifiedVuln, hits: Sequence[PaperHit]) -> str:
    """构造相关性判定提示（确定性拼装）。

    Args:
        vuln: 漏洞实体。
        hits: 候选论文。

    Returns:
        提示文本。
    """
    lines = [
        f"漏洞：{vuln.vuln_id}",
        f"标题：{vuln.title or '(无)'}",
        f"CWE：{', '.join(vuln.cwe_ids) or '(无)'}",
        f"描述：{vuln.description[:600]}",
        "",
        "候选论文：",
    ]
    for index, hit in enumerate(hits, start=1):
        lines.append(
            f"{index}. paper_id={hit.paper.paper_id}\n"
            f"   title: {hit.paper.title}\n"
            f"   abstract: {(hit.paper.abstract or '')[:400]}\n"
            f"   检索命中: {', '.join(hit.matched)}"
        )
    return "\n".join(lines)


def _aggregate_confidence(links: Sequence[PaperVulnLink]) -> float:
    """由关联边聚合节点级置信度（纯函数）。

    规则：有关联时取最高关联置信度；无关联时为 ``0.0``（**无结论**）。

    Args:
        links: 关联边列表。

    Returns:
        置信度，区间 ``[0.0, 1.0]``。
    """
    return round(max((link.confidence for link in links), default=0.0), 3)
