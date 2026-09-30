"""交叉验证 Agent（PROJECT_PLAN.md §5.6 ``reviewer.py`` 的 P5 MVP 形态）。

四道交叉验证（**全部确定性，不调用 LLM**）：

1. **URL 可达性**：对 PoC / 论文 / 参考链接做 HEAD（失败退回 GET）探活；
   不可达的 PoC 记录被降权（``reliability × 0.5``、``verified=False``）并记冲突；
2. **CVSS 向量校验**：用 ``normalize/cvss`` 的公式**复算**基础分，与源侧分数偏差 > 0.1 记冲突
   （v4.0 不自行评分，跳过并留 note）；
3. **来源可信度评分**：按源白名单加权平均（NVD > GHSA > OSV > KEV > EPSS > 官方模板 > 社区）；
4. **Pydantic 二次校验**：组装 ``EnrichedVuln`` 后再次 ``model_validate``，失败则不产出富化结果
   （**绝不写脏数据**，§6.2 P5 ③）。

输出：``confidence``（0–1）+ 冲突标记（``review_notes``），写入 ``state["verification"]`` 与
``state["enriched_vuln"]``；置信度低于阈值时由图的**条件边**回流到 PoCSeeker（最多 2 轮）。
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.agents.risk_scorer import score_risk
from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.enrich.tools.search_tools import check_url_reachable
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import VerificationReport
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import AgentStep, ExploitRecord
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.normalize.cvss import CVSS_V4_0, parse_cvss_vector, severity_rank_max

logger = get_logger(__name__)

AGENT_NAME: str = "verifier"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG: str = "no-llm"
"""本节点不使用 LLM，固定模型标识。"""

DEFAULT_MIN_CONFIDENCE: float = 0.7
"""自动通过阈值（低于该值触发回流，§3.2 闸门④）。"""

CVSS_SCORE_TOLERANCE: float = 0.1
"""CVSS 复算与源侧分数的允许偏差（四舍五入口径差异）。"""

UNREACHABLE_PENALTY: float = 0.5
"""URL 不可达时 PoC 记录的可靠性折损系数。"""

CONFLICT_PENALTY: float = 0.1
"""单条冲突标记的置信度扣减。"""

MAX_CONFLICT_PENALTY: float = 0.4
"""冲突扣减上限（避免单类问题把置信度压到 0）。"""

SOURCE_TRUST: dict[str, float] = {
    "nvd": 1.0,
    "ghsa": 0.9,
    "osv": 0.85,
    "kev": 0.8,
    "epss": 0.7,
    "nuclei": 0.8,
    "arxiv": 0.75,
    "openalex": 0.75,
    "github": 0.6,
    "exploitdb": 0.55,
    "exploitdb-search": 0.3,
}
"""来源可信度白名单（未列出的源按 :data:`DEFAULT_TRUST`）。"""

DEFAULT_TRUST: float = 0.5
"""未登记来源的默认可信度。"""

COMPONENT_WEIGHTS: dict[str, float] = {
    "source_trust": 0.40,
    "poc_strength": 0.25,
    "paper_strength": 0.15,
    "reachability": 0.20,
}
"""置信度各分量权重（合计 1.0；缺失分量按剩余权重归一化，避免"没检查"被当成"检查通过"）。"""


def trust_score(sources: Sequence[str]) -> float:
    """来源可信度加权平均（纯函数）。

    Args:
        sources: 来源标识集合（可含重复）。

    Returns:
        平均可信度，区间 ``[0.0, 1.0]``；空集合返回 ``0.0``。
    """
    unique = [source.strip().lower() for source in sources if source and source.strip()]
    if not unique:
        return 0.0
    return round(sum(SOURCE_TRUST.get(source, DEFAULT_TRUST) for source in unique) / len(unique), 3)


def verify_cvss(vuln: UnifiedVuln) -> tuple[list[str], list[str]]:
    """复算 CVSS 基础分（交叉验证第 2 项，纯函数）。

    Args:
        vuln: 漏洞实体（提供 ``cvss``）。

    Returns:
        ``(conflicts, notes)``：偏差超阈值记冲突；v4.0 或无向量时记 note。
    """
    conflicts: list[str] = []
    notes: list[str] = []
    if not vuln.cvss:
        notes.append("无 CVSS 向量，跳过复算")
        return conflicts, notes

    for vector in vuln.cvss:
        if vector.version == CVSS_V4_0:
            notes.append(f"CVSS v4.0（{vector.vector[:32]}…）不自行评分，跳过复算")
            continue
        try:
            recomputed = parse_cvss_vector(vector.vector)
        except ValueError as exc:
            conflicts.append(f"CVSS 向量无法解析：{vector.vector!r}（{exc}）")
            continue
        if abs(recomputed.base_score - vector.base_score) > CVSS_SCORE_TOLERANCE:
            conflicts.append(
                f"CVSS 复算不一致：{vector.version} 源侧={vector.base_score} 复算={recomputed.base_score}"
            )
    return conflicts, notes


def verify_severity(vuln: UnifiedVuln) -> list[str]:
    """校验 ``severity`` 与 ``cvss`` 的自洽性（纯函数）。

    Args:
        vuln: 漏洞实体。

    Returns:
        冲突标记列表（无冲突时为空）。
    """
    if not vuln.severity or not vuln.cvss:
        return []
    expected = severity_rank_max(vector.severity for vector in vuln.cvss)
    if expected is not None and expected != vuln.severity:
        return [f"severity 与 cvss 不一致：字段={vuln.severity} 向量推导={expected}"]
    return []


def compute_confidence(
    *,
    source_trust: float,
    poc_strength: float,
    paper_strength: float,
    reachability: float | None,
    conflicts: Sequence[str],
) -> float:
    """按加权公式计算综合置信度（纯函数，确定性）。

    分量权重见 :data:`COMPONENT_WEIGHTS`；``reachability=None``（未做可达性检查）时该分量
    **不参与**，剩余权重按比例归一化 —— 避免「没检查」被当成「检查通过」。
    最后按冲突数扣减（每条 :data:`CONFLICT_PENALTY`，上限 :data:`MAX_CONFLICT_PENALTY`）。

    Args:
        source_trust: 来源可信度分量（0–1）。
        poc_strength: PoC 证据强度分量（0–1）。
        paper_strength: 论文证据强度分量（0–1）。
        reachability: 可达性比例（0–1）；``None`` 表示未检查。
        conflicts: 冲突标记列表。

    Returns:
        综合置信度，区间 ``[0.0, 1.0]``。
    """
    components = {
        "source_trust": max(0.0, min(1.0, source_trust)),
        "poc_strength": max(0.0, min(1.0, poc_strength)),
        "paper_strength": max(0.0, min(1.0, paper_strength)),
    }
    if reachability is not None:
        components["reachability"] = max(0.0, min(1.0, reachability))

    weight_sum = sum(COMPONENT_WEIGHTS[name] for name in components)
    base = sum(COMPONENT_WEIGHTS[name] * value for name, value in components.items()) / weight_sum
    penalty = min(MAX_CONFLICT_PENALTY, CONFLICT_PENALTY * len(conflicts))
    return round(max(0.0, min(1.0, base - penalty)), 3)


def poc_strength_of(exploits: Sequence[ExploitRecord]) -> float:
    """由 PoC 记录计算证据强度（纯函数）。

    仅统计 ``maturity`` 属于「可执行证据」（``poc`` / ``functional`` / ``high``）的记录，
    2 条即饱和；``exploitdb-search`` 这类**检索入口候选不计入**（避免虚高）。

    Args:
        exploits: PoC 记录。

    Returns:
        强度，区间 ``[0.0, 1.0]``。
    """
    actionable = [record for record in exploits if record.maturity in {"poc", "functional", "high"}]
    return round(min(1.0, len(actionable) / 2), 3)


class VerifierAgent:
    """交叉验证节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        min_confidence: 自动通过阈值（低于该值触发回流）。
    """

    def __init__(
        self,
        *,
        http: HttpClient | None = None,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        max_url_checks: int = 6,
        check_urls: bool = True,
    ) -> None:
        """初始化节点。

        Args:
            http: HTTP 客户端（可达性检查用）；``None`` 时跳过该检查并记录 note。
            min_confidence: 自动通过阈值。
            max_url_checks: 单次最多检查的 URL 数（控制耗时与对源站压力）。
            check_urls: ``False`` 时完全跳过可达性检查（离线演示 / 单测）。
        """
        self._http = http
        self._min_confidence = min_confidence
        self._max_url_checks = max(1, max_url_checks)
        self._check_urls = check_urls
        self._last_checked = 0
        self._last_reachable = 0

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """执行四项交叉验证并产出 ``EnrichedVuln``。

        Args:
            state: 富化图状态（读取 ``unified_vuln`` / ``related_papers`` / ``exploits``）。

        Returns:
            含 ``verification`` / ``confidence`` / ``enriched_vuln`` / ``agent_steps`` /
            ``errors`` / ``exploits``（可达性降权后的版本）的增量字典。
        """
        started = time.perf_counter()
        vuln = state["unified_vuln"]
        papers = list(state.get("related_papers") or [])
        exploits = list(state.get("exploits") or [])
        conflicts: list[str] = []
        errors: list[str] = []

        cvss_conflicts, notes = verify_cvss(vuln)
        conflicts.extend(cvss_conflicts)
        conflicts.extend(verify_severity(vuln))

        exploits, reachability, url_notes = await self._verify_urls(state, exploits)
        notes.extend(url_notes)

        source_trust = trust_score([*vuln.sources, *(record.source for record in exploits)])
        paper_strength = min(1.0, len(papers) / 1.0) if papers else 0.0
        confidence = compute_confidence(
            source_trust=source_trust,
            poc_strength=poc_strength_of(exploits),
            paper_strength=paper_strength,
            reachability=reachability,
            conflicts=conflicts,
        )
        report = VerificationReport(
            confidence=confidence,
            conflicts=conflicts,
            checked_urls=self._last_checked,
            reachable_urls=self._last_reachable,
            source_trust=source_trust,
            notes=notes,
        )

        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=confidence,
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used=MODEL_TAG,
            output_digest=(
                f"confidence={confidence} conflicts={len(conflicts)} "
                f"urls={report.reachable_urls}/{report.checked_urls}"
            ),
            error=errors[0] if errors else None,
        )
        enriched = self._build_enriched(state, exploits, papers, confidence, conflicts, step, errors)
        return {
            "verification": report,
            "confidence": confidence,
            "enriched_vuln": enriched,
            "exploits": exploits,
            "agent_steps": [step],
            "errors": errors,
        }

    async def _verify_urls(
        self, state: EnrichmentState, exploits: list[ExploitRecord]
    ) -> tuple[list[ExploitRecord], float | None, list[str]]:
        """URL 可达性检查并对不可达的 PoC 记录降权。

        Args:
            state: 富化图状态。
            exploits: PoC 记录。

        Returns:
            ``(调整后的 PoC 记录, 可达性比例或 None, notes)``。
        """
        self._last_checked = 0
        self._last_reachable = 0
        if not self._check_urls or self._http is None:
            return exploits, None, ["未执行 URL 可达性检查（未注入 HTTP 客户端或已关闭检查）"]

        urls: list[str] = []
        for record in exploits:
            if record.url and record.url not in urls:
                urls.append(record.url)
        urls.extend(ref.url for ref in state["unified_vuln"].references if ref.url)
        urls = urls[: self._max_url_checks]
        if not urls:
            return exploits, None, ["无可检查的 URL（PoC 与参考链接均为空）"]

        reachable: set[str] = set()
        for url in urls:
            ok, status = await check_url_reachable(url, http=self._http)
            self._last_checked += 1
            if ok:
                reachable.add(url)
            else:
                logger.info(f"URL 不可达：{url}（status={status}）")

        adjusted: list[ExploitRecord] = []
        for record in exploits:
            if record.url in urls and record.url not in reachable:
                adjusted.append(
                    record.model_copy(
                        update={
                            "reliability": round(record.reliability * UNREACHABLE_PENALTY, 3),
                            "verified": False,
                        }
                    )
                )
            else:
                adjusted.append(record)
        self._last_reachable = len(reachable)
        return adjusted, round(len(reachable) / len(urls), 3), [
            f"URL 可达性：{len(reachable)}/{len(urls)} 可访问（不可达的 PoC 记录已降权）"
        ]

    def _build_enriched(
        self,
        state: EnrichmentState,
        exploits: list[ExploitRecord],
        papers: list[Any],
        confidence: float,
        conflicts: list[str],
        step: AgentStep,
        errors: list[str],
    ) -> Any:
        """组装并二次校验 ``EnrichedVuln``（闸门④：失败则不产出结论）。

        Args:
            state: 富化图状态。
            exploits: 调整后的 PoC 记录。
            papers: 关联论文边。
            confidence: 综合置信度。
            conflicts: 冲突标记。
            step: 本节点轨迹。
            errors: 错误收集列表（原地追加）。

        Returns:
            ``EnrichedVuln`` 实例；二次校验失败时返回 ``None``（**不写脏数据**）。
        """
        from aisec_intel.models.enriched_vuln import EnrichedVuln

        vuln = state["unified_vuln"]
        risk = score_risk(vuln, exploits)
        passed = confidence >= self._min_confidence
        if passed and not conflicts:
            status = "auto_pass"
        elif passed:
            status = "revised"
        else:
            status = "needs_human"

        payload = {
            **vuln.model_dump(),
            "related_papers": [link.model_dump() for link in papers],
            "exploits": [record.model_dump() for record in exploits],
            "affected_assets": [],
            "risk_score": risk.score,
            "risk_level": risk.level,
            "risk_breakdown": risk.breakdown,
            "attack_chain": None,
            "confidence": confidence,
            "review_status": status,
            "review_notes": list(conflicts),
            "agent_trace": [*(item.model_dump() for item in state["agent_steps"]), step.model_dump()],
            "model_used": state.get("model_used") or "unset",
            "enriched_at": utc_now(),
        }
        try:
            enriched = EnrichedVuln(**payload)
            return EnrichedVuln.model_validate(enriched.model_dump())  # 闸门④：二次校验
        except Exception as exc:  # noqa: BLE001 - 校验失败必须降级为「无结论」
            errors.append(f"{AGENT_NAME}: EnrichedVuln 二次校验失败（{type(exc).__name__}: {exc}）")
            logger.error(f"EnrichedVuln 二次校验失败，不产出富化结果：{exc!r}")
            return None

