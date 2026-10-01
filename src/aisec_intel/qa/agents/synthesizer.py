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
   并在 ``QAResponse.degraded`` 上标明（该字段为 ``True`` 时才允许无引用）。

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
from aisec_intel.qa.agents.reasoner import citation_of
from aisec_intel.qa.state import QAState, QueryIntent, RetrievalResult

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
    "3. summary 用一句话给结论（含关键 CVE / 组件 / 风险级别）；claims 用短句陈述事实；\n"
    "4. confidence 取 0~1，证据越直接越高；\n"
    "5. 只输出 JSON 对象，不要输出解释文字或 Markdown 代码块。"
)
"""Synthesizer 系统提示词（含 ``json`` 字样，兼容 ``json_mode``）。"""


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


def build_prompt(
    intent: QueryIntent,
    results: Sequence[RetrievalResult],
    reasoning: Sequence[ReasoningStep],
) -> str:
    """构造合成提示（确定性拼装，含证据清单与推理链）。

    Args:
        intent: 查询理解结果。
        results: 候选检索结果（``doc_id`` 为可选项）。
        reasoning: Reasoner 产出的推理链。

    Returns:
        提示文本。
    """
    evidence_lines = [
        f"[{index}] doc_id={result.doc_id} source={result.source} "
        f"cve={result.metadata.get('cve_id') or '-'}\n    {(result.content or '').strip()[:300]}"
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
    ) -> QAResponse:
        """构造 ``QAResponse``（无引用时自动置 ``degraded``，满足契约校验）。"""
        return QAResponse(
            answer=answer,
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
    ) -> SynthesisOutcome:
        """执行合成（LLM 优先，失败 / 无证据时模板化兜底）。

        Args:
            intent: 查询理解结果。
            results: 候选检索结果。
            reasoning: 推理链（写入 ``QAResponse.reasoning_chain``）。

        Returns:
            :class:`SynthesisOutcome`。
        """
        started = time.perf_counter()
        if not results:
            answer, citations = degraded_answer(results)
            return SynthesisOutcome(
                response=self._response(answer, citations, reasoning, 0.0, degraded=True),
                model_used="no-llm",
                error="检索结果为空，返回未找到相关信息",
            )
        if self._llm is None:
            answer, citations = degraded_answer(results)
            return SynthesisOutcome(
                response=self._response(answer, citations, reasoning, 0.3, degraded=True),
                model_used="no-llm",
                latency_ms=int((time.perf_counter() - started) * 1000),
                error="未启用 LLM，使用模板化答案",
            )

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=build_prompt(intent, results, reasoning)),
        ]
        try:
            draft: AnswerDraft = await invoke_structured(
                self._llm, AnswerDraft, messages, max_retries=self._max_retries
            )
        except StructuredOutputError as exc:
            logger.warning(f"答案合成结构化输出失败，改用模板化答案：{exc}")
            answer, citations = degraded_answer(results)
            return SynthesisOutcome(
                response=self._response(answer, citations, reasoning, 0.3, degraded=True),
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
                answer, citations, reasoning, draft.confidence, degraded=degrade_reason is not None
            ),
            dropped_claims=dropped,
            model_used=self._model_tag,
            latency_ms=int((time.perf_counter() - started) * 1000),
            error=degrade_reason,
        )

    async def __call__(self, state: QAState) -> dict[str, Any]:
        """LangGraph 节点入口：读 ``intent`` / ``fused`` / ``reasoning_chain``，写答案与引用。

        Args:
            state: 问答图状态。

        Returns:
            含 ``answer`` / ``citations``（必要时含 ``degraded`` / ``errors``）的增量字典。
        """
        intent = state.get("intent")
        results = list(state.get("fused") or state.get("results") or [])
        reasoning = list(state.get("reasoning_chain") or [])
        if intent is None:
            return {
                "answer": NOT_FOUND_ANSWER,
                "citations": [],
                "degraded": True,
                "errors": [f"{AGENT_NAME}: 状态缺少 intent（请先执行查询理解节点）"],
            }
        outcome = await self.synthesize(intent, results, reasoning)
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
