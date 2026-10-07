"""Synthesizer Agent（Day11 任务 3；PROJECT_PLAN.md §5.8 ``qa/agents/synthesizer.py``）。

职责：把 **检索结果 + 推理链** 合成为面向用户的 :class:`QAResponse`
（``answer`` + ``citations`` + ``reasoning_chain`` + ``confidence``）。

设计要点：

1. **模型分层**：使用 ``LLM_MODEL_FAST``（``deepseek-chat``）——写作类任务用便宜模型（§3.2）；
2. **每条论断强制带引用**：LLM 只输出 ``claims[].evidence_doc_ids``，由 :func:`synthesize`
   在候选集内查表生成 :class:`Citation`；**没有任何有效证据的论断被整条丢弃**
   （宁缺毋滥：验收要求「引用可回溯率 100%」）；
3. **禁止编造引用**：URL / locator / quote 全部来自检索结果，模型无法注入新链接；
4. **降级可用**：无 LLM / 全部论断被丢弃 / 无检索结果时，用模板化答案 + 真实引用兜底，
   并在 ``QAResponse.degraded`` 上标明（该字段为 ``True`` 时才允许无引用）；
5. **只引用相关证据**（Day24 修复）：提示词要求「证据中的 CVE 与用户指定 CVE 不一致时必须
   丢弃」，并由 :func:`~aisec_intel.qa.agents.reasoner.filter_cve_relevant` 在进模型前
   确定性剔除冲突证据（双保险，避免无关 CVE 进入答案）；
6. **缺口声明**（Day25 任务 1.3）：提示词注入证据缺口清单，且由 :func:`ensure_gap_notice`
   确定性兜底——缺 ``fixed_version`` 时答案必含「知识库暂无修复版本信息」。

Note:
    ``QAResponse`` 的模型校验（``answer`` 非空且 ``degraded=False`` ⇒ 必须至少 1 条引用）
    是本模块的**最后一道闸门**——写错会直接抛 ``ValidationError``，不会流出脏回答。
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from aisec_intel.config import Settings, get_settings
from aisec_intel.llm.provider import LLMError, build_provider
from aisec_intel.llm.schemas import DEFAULT_MAX_RETRIES, StructuredOutputError, invoke_structured
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import AnswerDraft, Citation, QAResponse, ReasoningStep
from aisec_intel.qa.agents.reasoner import citation_of, filter_cve_relevant
from aisec_intel.qa.evidence_gap import GapReport
from aisec_intel.qa.state import QAState, QueryIntent, RetrievalResult
from aisec_intel.security.prompt_guard import sanitize_for_llm

logger = get_logger(__name__)

AGENT_NAME: str = "synthesizer"
"""节点名（写入状态留痕）。"""

MAX_CLAIMS: int = 6
"""答案最多保留的论断条数（避免回答冗长）。"""

MAX_EVIDENCE_PER_CLAIM: int = 3
"""单条论断最多挂的引用数。"""

NOT_FOUND_ANSWER: str = "未找到相关信息：本次检索在知识库中没有返回与该问题相关的证据。"
"""空结果时的标准答复（任务 4 条件边的落点）。"""

SYSTEM_PROMPT: str = (
    "你是安全情报报告撰写员。基于给定的**检索证据**与**推理链**，写一份面向运维/安全工程师的回答。\n"
    "硬性要求：\n"
    "1. claims 中每一条论断都必须填 evidence_doc_ids，且只能从候选 doc_id 中挑选；"
    "没有证据支撑的话不要写；\n"
    "2. 不得出现候选证据之外的任何事实、CVE 编号、版本号或链接；\n"
    "3. 只引用与用户问题**直接相关**的证据：证据中的 CVE 与用户问题指定的 CVE "
    "不一致时，必须丢弃该证据，不得用无关 CVE 的事实回答用户问题；\n"
    "4. 若给出「证据缺口」清单，必须在答案中如实说明缺口，**不得用常识或推测补齐**"
    "（尤其缺「修复版本」时必须明说「知识库暂无修复版本信息」）；\n"
    "5. summary 用一句话给结论（含关键 CVE / 组件 / 风险级别）；claims 用短句陈述事实；\n"
    "6. confidence 取 0~1，证据越直接越高；\n"
    "7. 只输出 JSON 对象，不要输出解释文字或 Markdown 代码块。"
)
"""Synthesizer 系统提示词（含 ``json`` 字样，兼容 ``json_mode``；第 4 条为 Day25 缺口声明约束）。"""

FIXED_VERSION_PHRASE: str = "知识库暂无修复版本信息"
"""缺 ``fixed_version`` 时答案必须包含的固定表述（Day25 任务 1.3 硬性要求）。"""

GAP_EXTERNAL_NOTE: str = (
    "；下方修复版本线索来自受控外部权威源（NVD / GHSA / OSV / CISA KEV），请以厂商公告为准。"
)
"""缺口由外部证据补齐时的补充说明。"""

GAP_LOCAL_ONLY_NOTE: str = "（本地知识库与受控外部源均未给出修复版本），请勿臆测升级目标版本。"
"""缺口未被任何来源补齐时的补充说明。"""


@dataclass(slots=True)
class SynthesisOutcome:
    """一次合成的执行结果。

    Attributes:
        response: 最终问答响应（含引用与推理链）。
        dropped_claims: 因缺少有效证据被丢弃的论断数（可观测性指标）。
        model_used: 实际使用的模型标识（降级时为 ``no-llm``）。
        latency_ms: 耗时（毫秒）。
        error: 降级原因（成功时为 ``None``）。
    """

    response: QAResponse
    dropped_claims: int = 0
    model_used: str = "unset"
    latency_ms: int = 0
    error: str | None = None


def _gap_line(gap_report: GapReport | None) -> str:
    """渲染提示词里的「证据缺口」行（纯函数）。

    Args:
        gap_report: 证据缺口报告；``None`` 表示未检测。

    Returns:
        提示词用的一行文本。
    """
    if gap_report is None:
        return "证据缺口：（未检测）"
    if not gap_report.missing:
        return "证据缺口：（无，本地证据已足够）"
    return "证据缺口（必须如实说明，不得臆测）：" + "、".join(gap_report.missing_labels)


def ensure_gap_notice(
    answer: str,
    gap_report: GapReport | None,
    *,
    external_fixed_version: bool = False,
) -> str:
    r"""缺口声明（纯函数）：缺 ``fixed_version`` 时保证答案含「知识库暂无修复版本信息」。

    提示词已要求模型自行声明缺口；本函数是**确定性兜底**——模型漏说时补上，
    保证「知识库缺修复版本」这一事实不会因为模型措辞而被掩盖。

    Args:
        answer: 合成后的答案文本。
        gap_report: 证据缺口报告；``None`` 或缺 ``fixed_version`` 以外的事实时不改动答案。
        external_fixed_version: 受控外部源是否已给出修复版本（决定补充说明措辞）。

    Returns:
        保证含缺口声明的答案文本。

    Examples:
        >>> from aisec_intel.qa.evidence_gap import GapReport
        >>> report = GapReport(missing=["fixed_version"], has_enough=False)
        >>> ensure_gap_notice("CVE 影响 X。", report)
        'CVE 影响 X。\\n\\n知识库暂无修复版本信息（本地知识库与受控外部源均未给出修复版本），请勿臆测升级目标版本。'
        >>> ensure_gap_notice("CVE 影响 X。", GapReport(has_enough=True))
        'CVE 影响 X。'
    """
    if gap_report is None or not gap_report.lacks_fixed_version:
        return answer
    if FIXED_VERSION_PHRASE in answer:
        return answer
    notice = FIXED_VERSION_PHRASE + (GAP_EXTERNAL_NOTE if external_fixed_version else GAP_LOCAL_ONLY_NOTE)
    body = answer.strip()
    return f"{body}\n\n{notice}" if body else notice


def build_prompt(
    intent: QueryIntent,
    results: Sequence[RetrievalResult],
    reasoning: Sequence[ReasoningStep],
    gap_report: GapReport | None = None,
) -> str:
    """构造合成提示（确定性拼装，含证据清单 / 推理链 / 证据缺口）。

    Args:
        intent: 查询理解结果。
        results: 候选检索结果（``doc_id`` 为可选项）。
        reasoning: Reasoner 产出的推理链。
        gap_report: 证据缺口报告（Day25；``None`` 时提示词不含缺口段落）。

    Returns:
        提示文本。
    """
    evidence_lines = [
        f"[{index}] doc_id={result.doc_id} source={result.source} "
        f"cve={result.metadata.get('cve_id') or '-'}"
        f"{'｜外部不可信内容' if result.metadata.get('untrusted_external_content') else ''}\n"
        f"    {(result.content or '').strip()[:300]}"
        for index, result in enumerate(results[:12], start=1)
    ]
    chain_lines = [
        f"跳{step.hop}｜{step.question} ⇒ {step.conclusion}"
        f"（证据：{', '.join(item.locator for item in step.evidence) or '无'}）"
        for step in reasoning
    ]
    return "\n".join(
        [
            f"用户问题：{intent.query}",
            f"意图：{intent.intent}",
            f"用户指定 CVE：{'、'.join(intent.entities.cve_ids) or '（无，不约束）'}"
            "——引用约束：只引用与用户问题直接相关的证据，证据中的 CVE 与之不一致时必须丢弃。",
            _gap_line(gap_report),
            "",
            "检索证据（doc_id 只能从这里选）：",
            *(evidence_lines or ["（无）"]),
            "",
            "推理链：",
            *(chain_lines or ["（无）"]),
            "",
            "输出 JSON（严格符合下列结构，不要额外字段）：",
            '{"summary": "<一句话结论>", "claims": [{"claim": "<论断>",',
            ' "evidence_doc_ids": ["<候选 doc_id>"]}], "confidence": 0.8}',
        ]
    )


def synthesize(
    draft: AnswerDraft,
    results: Sequence[RetrievalResult],
    *,
    max_claims: int = MAX_CLAIMS,
    max_evidence_per_claim: int = MAX_EVIDENCE_PER_CLAIM,
) -> tuple[str, list[Citation], int]:
    """把 LLM 草稿合成为「答案 + 引用」（纯函数，强制每条论断可回溯）。

    规则：
        1. 论断的 ``evidence_doc_ids`` 必须命中候选集，否则该论断**整条丢弃**；
        2. 引用按 ``locator`` 去重并保持命中顺序；
        3. 答案由 ``summary`` + 带行内依据标注的论断列表**确定性拼装**（模型不直接产出最终文本，
           从而无法把不存在的链接写进回答）。

    Args:
        draft: LLM 输出。
        results: 候选检索结果。
        max_claims: 最多保留的论断数。
        max_evidence_per_claim: 单条论断最多引用数。

    Returns:
        ``(answer, citations, dropped_claims)``。
    """
    by_id = {result.doc_id: result for result in results}
    kept: list[tuple[str, list[str]]] = []
    citations: list[Citation] = []
    seen: set[str] = set()
    dropped = 0
    for item in draft.claims:
        locators = [doc_id for doc_id in item.evidence_doc_ids if doc_id in by_id][:max_evidence_per_claim]
        if not locators:
            dropped += 1
            continue
        for doc_id in locators:
            if doc_id in seen:
                continue
            seen.add(doc_id)
            citations.append(citation_of(by_id[doc_id]))
        kept.append((item.claim.strip(), locators))
        if len(kept) >= max(1, max_claims):
            break

    lines = [draft.summary.strip()]
    for claim, locators in kept:
        lines.append(f"- {claim}（依据：{', '.join(locators)}）")
    if not kept:
        lines.append("- （LLM 未给出可回溯论断，请以引用列表为准）")
    return "\n".join(line for line in lines if line), citations, dropped


def degraded_answer(results: Sequence[RetrievalResult]) -> tuple[str, list[Citation]]:
    """无 LLM / 无有效论断时的模板化答复（纯函数，仍带真实引用）。

    Args:
        results: 候选检索结果。

    Returns:
        ``(answer, citations)``；无结果时返回 :data:`NOT_FOUND_ANSWER` 与空引用。
    """
    if not results:
        return NOT_FOUND_ANSWER, []
    citations = [citation_of(result) for result in results[:MAX_EVIDENCE_PER_CLAIM]]
    lines = ["以下为知识库中与问题最相关的检索结果（未经 LLM 归纳）："]
    for result in results[:5]:
        body = " ".join((result.content or "").split())[:160] or "(空)"
        lines.append(f"- [{result.source}] {body}（依据：{result.doc_id}）")
    return "\n".join(lines), citations


class SynthesizerAgent:
    """答案合成节点（可调用对象，供 LangGraph 注册）。

    Attributes:
        model_tag: 实际使用的模型标识（降级时为 ``no-llm``）。
    """

    def __init__(
        self,
        *,
        structured_llm: Any | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        model_tag: str = "no-llm",
        max_claims: int = MAX_CLAIMS,
    ) -> None:
        """初始化节点。

        Args:
            structured_llm: ``provider.structured(AnswerDraft, role="fast")``；``None`` 时走模板化兜底。
            max_retries: 结构化输出失败重试次数（闸门②）。
            model_tag: 模型标识。
            max_claims: 最多保留的论断数。
        """
        self._llm = structured_llm
        self._max_retries = max(0, max_retries)
        self._model_tag = model_tag if structured_llm is not None else "no-llm"
        self._max_claims = max(1, max_claims)

    @property
    def model_tag(self) -> str:
        """当前模型标识。"""
        return self._model_tag

    def _response(
        self,
        answer: str,
        citations: list[Citation],
        reasoning: Sequence[ReasoningStep],
        confidence: float,
        *,
        degraded: bool,
        gap_report: GapReport | None = None,
        external_fixed_version: bool = False,
    ) -> QAResponse:
        """构造 ``QAResponse``（无引用时自动置 ``degraded``；缺修复版本时保证缺口声明）。

        Args:
            answer: 答案正文。
            citations: 引用列表。
            reasoning: 推理链。
            confidence: 置信度。
            degraded: 是否降级链路。
            gap_report: 证据缺口报告（Day25 任务 1.3）。
            external_fixed_version: 外部源是否已给出修复版本。

        Returns:
            通过契约校验的 :class:`QAResponse`。
        """
        final_answer = ensure_gap_notice(answer, gap_report, external_fixed_version=external_fixed_version)
        return QAResponse(
            answer=final_answer,
            citations=citations,
            reasoning_chain=list(reasoning),
            confidence=max(0.0, min(1.0, confidence)),
            degraded=degraded or not citations,
        )

    async def synthesize(
        self,
        intent: QueryIntent,
        results: Sequence[RetrievalResult],
        reasoning: Sequence[ReasoningStep] = (),
        gap_report: GapReport | None = None,
        *,
        external_fixed_version: bool = False,
    ) -> SynthesisOutcome:
        """执行合成（LLM 优先，失败 / 无证据时模板化兜底）。

        Args:
            intent: 查询理解结果。
            results: 候选检索结果。
            reasoning: 推理链（写入 ``QAResponse.reasoning_chain``）。
            gap_report: 证据缺口报告（写入提示词，并强制缺口声明；Day25 任务 1.3）。
            external_fixed_version: 受控外部源是否已给出修复版本（决定缺口声明措辞）。

        Returns:
            :class:`SynthesisOutcome`。

        Note:
            Day24 任务 4：进模型前先按用户指定的 CVE 过滤候选证据
            （:func:`~aisec_intel.qa.agents.reasoner.filter_cve_relevant`），
            提示词里的同一约束因此有了确定性兜底。
        """
        started = time.perf_counter()
        results = filter_cve_relevant(results, intent.entities.cve_ids)
        notice_kwargs: dict[str, Any] = {
            "gap_report": gap_report,
            "external_fixed_version": external_fixed_version,
        }
        if not results:
            answer, citations = degraded_answer(results)
            return SynthesisOutcome(
                response=self._response(answer, citations, reasoning, 0.0, degraded=True, **notice_kwargs),
                model_used="no-llm",
                error="检索结果为空，返回未找到相关信息",
            )
        if self._llm is None:
            answer, citations = degraded_answer(results)
            return SynthesisOutcome(
                response=self._response(answer, citations, reasoning, 0.3, degraded=True, **notice_kwargs),
                model_used="no-llm",
                latency_ms=int((time.perf_counter() - started) * 1000),
                error="未启用 LLM，使用模板化答案",
            )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            # Day18 任务 1：检索片段 / 推理链入模前软清洗
            HumanMessage(content=sanitize_for_llm(build_prompt(intent, results, reasoning, gap_report))),
        ]
        try:
            draft: AnswerDraft = await invoke_structured(
                self._llm, AnswerDraft, messages, max_retries=self._max_retries
            )
        except StructuredOutputError as exc:
            logger.warning(f"答案合成结构化输出失败，改用模板化答案：{exc}")
            answer, citations = degraded_answer(results)
            return SynthesisOutcome(
                response=self._response(answer, citations, reasoning, 0.3, degraded=True, **notice_kwargs),
                model_used="no-llm",
                latency_ms=int((time.perf_counter() - started) * 1000),
                error=f"结构化输出失败：{exc}",
            )

        answer, citations, dropped = synthesize(draft, results, max_claims=self._max_claims)
        degrade_reason: str | None = None
        if not citations:
            answer, citations = degraded_answer(results)
            degrade_reason = "LLM 论断均缺少可回溯证据，改用模板化答案"
            logger.warning(degrade_reason)
        return SynthesisOutcome(
            response=self._response(
                answer,
                citations,
                reasoning,
                draft.confidence,
                degraded=degrade_reason is not None,
                **notice_kwargs,
            ),
            dropped_claims=dropped,
            model_used=self._model_tag,
            latency_ms=int((time.perf_counter() - started) * 1000),
            error=degrade_reason,
        )

    async def __call__(self, state: QAState) -> dict[str, Any]:
        """LangGraph 节点入口：读 ``intent`` / ``fused`` / ``reasoning_chain`` / ``gap_report``。

        Args:
            state: 问答图状态。

        Returns:
            含 ``answer`` / ``citations``（必要时含 ``degraded`` / ``errors``）的增量字典。
        """
        intent = state.get("intent")
        results = list(state.get("fused") or state.get("results") or [])
        reasoning = list(state.get("reasoning_chain") or [])
        gap_report = state.get("gap_report")
        verification = state.get("external_verification")
        external_fixed_version = bool(
            verification is not None and "fixed_version" in verification.verified_facts
        )
        if intent is None:
            return {
                "answer": NOT_FOUND_ANSWER,
                "citations": [],
                "degraded": True,
                "errors": [f"{AGENT_NAME}: 状态缺少 intent（请先执行查询理解节点）"],
            }
        outcome = await self.synthesize(
            intent,
            results,
            reasoning,
            gap_report,
            external_fixed_version=external_fixed_version,
        )
        payload: dict[str, Any] = {
            "answer": outcome.response.answer,
            "citations": outcome.response.citations,
            "degraded": outcome.response.degraded,
        }
        if outcome.error:
            payload["errors"] = [f"{AGENT_NAME}: {outcome.error}"]
        return payload


def build_synthesizer(
    settings: Settings | None = None,
    *,
    use_llm: bool | None = None,
) -> SynthesizerAgent:
    """按配置构建 Synthesizer（唯一工厂；``DEGRADED_MODE=true`` 时走模板化答案）。

    Args:
        settings: 全局配置；``None`` 时使用进程级单例。
        use_llm: 显式开关；``None`` 时按配置推断。

    Returns:
        可用的 :class:`SynthesizerAgent`（构造过程**不发起网络请求**）。
    """
    resolved = settings or get_settings()
    enabled = (not resolved.degraded_mode and resolved.has_llm_api_key) if use_llm is None else use_llm
    if not enabled:
        logger.info("Synthesizer 走模板化答案（未启用 LLM 或处于降级模式）")
        return SynthesizerAgent(structured_llm=None, max_retries=resolved.llm_max_retries)
    try:
        provider = build_provider(resolved)
        runnable = provider.structured(AnswerDraft, role="fast")
    except LLMError as exc:
        logger.warning(f"LLM 不可用，Synthesizer 走模板化答案：{exc}")
        return SynthesizerAgent(structured_llm=None, max_retries=resolved.llm_max_retries)
    return SynthesizerAgent(
        structured_llm=runnable,
        max_retries=resolved.llm_max_retries,
        model_tag=provider.model_for("fast"),
    )
