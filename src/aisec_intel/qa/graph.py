"""问答 LangGraph 主干（Day11 任务 4 / Day25 阶段 1-2；PROJECT_PLAN.md §5.8 ``qa/graph.py``）。

链路（Day25：缺口检测 + 受控外部检索）::

    START → query_understander → supervisor → gap_checker ─┬─(证据足够)→ reasoner → synthesizer → END
                                                            └─(证据缺口)→ external_retriever → verifier → reasoner

设计要点：

1. **依赖注入**：查询理解 / 检索调度 / 缺口检测 / 外部检索 / 复核 / 推理 / 合成七个节点由
   :class:`QADeps` 注入，「在线（LLM + 权威源）」与「离线（降级）」走**同一张图**；
2. **证据缺口驱动路由**（Day25 阶段 1）：``gap_checker`` 用纯规则判断「问题所需事实是否具备」，
   足够则直达 Reasoner；有缺口才进入受控外部检索——**不把「要查什么」的自由裁量权交给模型**；
3. **受控外部检索 + 复核**（Day25 阶段 2）：只查 NVD / GHSA / OSV / CISA KEV 四个权威源，
   内容先清洗（去 HTML / 截断 ≤2000 / 注入检测）再复核（trust_score 阈值 + 多源冲突裁决），
   ``verified=True`` 才并入 ``fused`` 供引用；``unified_vuln`` / ``enriched_vuln`` 永不被写入；
4. **可插拔 checkpointer**：``checkpointer=None`` 不持久化（无需 ``thread_id``）；
   传入 ``InMemorySaver`` 后可用 :func:`thread_config` 做多轮会话 / 断点续跑；
5. **异常隔离**：每个节点把非致命错误写入 ``state["errors"]``，单点失败不中断整条链路；
6. **置信度口径**（Day24 修复）：:func:`calculate_confidence` 把「引用与用户指定 CVE 的
   一致占比」与「检索面是否完备」计入打分——``(0.5 + ratio×0.5) × 0.6(降级) × 0.6(缺路)``。
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from langgraph.graph import END, START, StateGraph

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import Citation, QAResponse
from aisec_intel.qa.agents.external_retriever import ExternalRetrieverAgent, build_external_retriever
from aisec_intel.qa.agents.query_understander import QueryUnderstander, build_query_understander
from aisec_intel.qa.agents.reasoner import MAX_HOPS, ReasonerAgent, build_reasoner
from aisec_intel.qa.agents.supervisor import Supervisor
from aisec_intel.qa.agents.synthesizer import SynthesizerAgent, build_synthesizer
from aisec_intel.qa.agents.verifier import ExternalEvidenceVerifier, build_external_verifier
from aisec_intel.qa.evidence_gap import GapChecker
from aisec_intel.qa.state import DEFAULT_TOP_K, QAState, new_qa_state
from aisec_intel.services.retrieval_service import RetrievalService

logger = get_logger(__name__)

NODE_UNDERSTANDER: str = "query_understander"
"""节点①：查询理解（意图 / 实体 / 过滤 / 检索计划）。"""

NODE_SUPERVISOR: str = "supervisor"
"""节点②：检索调度（并发三路 + RRF 融合）。"""

NODE_GAP_CHECKER: str = "gap_checker"
"""节点③：证据缺口检测（判断问题所需事实是否已具备；Day25 阶段 1）。"""

NODE_EXTERNAL_RETRIEVER: str = "external_retriever"
"""节点④：受控外部检索（仅权威源 NVD / GHSA / OSV / KEV；Day25 阶段 2）。"""

NODE_VERIFIER: str = "verifier"
"""节点⑤：外部证据复核（可信度评分 + 多源冲突裁决；Day25 阶段 2）。"""

NODE_REASONER: str = "reasoner"
"""节点⑥：跨文档推理（≤2 跳，带证据引用）。"""

NODE_SYNTHESIZER: str = "synthesizer"
"""节点⑦：答案合成（强制引用 + 缺口声明）。"""

NODE_SEQUENCE: tuple[str, ...] = (
    NODE_UNDERSTANDER,
    NODE_SUPERVISOR,
    NODE_GAP_CHECKER,
    NODE_EXTERNAL_RETRIEVER,
    NODE_VERIFIER,
    NODE_REASONER,
    NODE_SYNTHESIZER,
)
"""主干节点顺序（文档 / 测试断言用；``external_retriever`` / ``verifier`` 仅在缺口分支执行）。"""


@dataclass(slots=True)
class QADeps:
    """问答图的依赖集合（全部可注入桩实现，便于离线测试）。

    Attributes:
        settings: 全局配置。
        understander: 查询理解 Agent。
        supervisor: 检索调度 Agent。
        gap_checker: 证据缺口检测节点（Day25 阶段 1）。
        external_retriever: 受控外部检索 Agent（Day25 阶段 2）。
        verifier: 外部证据复核节点（Day25 阶段 2）。
        reasoner: 推理 Agent。
        synthesizer: 答案合成 Agent（含缺口声明）。
    """

    settings: Settings
    understander: QueryUnderstander
    supervisor: Supervisor
    reasoner: ReasonerAgent
    synthesizer: SynthesizerAgent
    gap_checker: GapChecker
    external_retriever: ExternalRetrieverAgent
    verifier: ExternalEvidenceVerifier


def build_qa_deps(
    retrieval: RetrievalService,
    *,
    settings: Settings | None = None,
    use_llm: bool | None = None,
    top_k: int = DEFAULT_TOP_K,
    max_hops: int = MAX_HOPS,
    session_factory: Callable[[], Any] | None = None,
    external_http: Any | None = None,
    enable_external: bool | None = None,
) -> QADeps:
    """按配置装配七个节点（唯一装配入口；``use_llm=False`` 时全链路降级）。

    Args:
        retrieval: 混合检索服务（唯一数据出口）。
        settings: 全局配置；``None`` 时使用进程级单例。
        use_llm: 显式开关；``None`` 时由各工厂按配置推断。
        top_k: 单路召回条数上限（写入 Supervisor）。
        max_hops: 多跳上限（写入 Reasoner）。
        session_factory: 返回异步上下文管理器的会话工厂（外部证据落库用）；``None`` 时不落库。
        external_http: 注入的 HTTP 客户端（外部检索测试用）；``None`` 时按超时自建。
        enable_external: 显式开关外部检索；``None`` 时按配置（``DEGRADED_MODE`` 自动关闭）。

    Returns:
        :class:`QADeps`。
    """
    resolved = settings or get_settings()
    return QADeps(
        settings=resolved,
        understander=build_query_understander(resolved, use_llm=use_llm),
        supervisor=Supervisor(retrieval, top_k=top_k),
        reasoner=build_reasoner(resolved, use_llm=use_llm, max_hops=max_hops),
        synthesizer=build_synthesizer(resolved, use_llm=use_llm),
        gap_checker=GapChecker(),
        external_retriever=build_external_retriever(
            resolved, http=external_http, session_factory=session_factory, enabled=enable_external
        ),
        verifier=build_external_verifier(resolved, session_factory=session_factory),
    )


def route_after_gap_checker(state: QAState) -> str:
    """条件边：证据足够 → Reasoner；有缺口 → 受控外部检索（纯函数）。

    Args:
        state: 问答图状态（读取 ``gap_report``）。

    Returns:
        下一个节点名（``reasoner`` 或 ``external_retriever``）。

    Note:
        缺口报告缺失（节点异常 / 未执行）时按「足够」处理，直接进入 Reasoner——
        保证链路永不因缺口检测而中断。

    Examples:
        >>> from aisec_intel.qa.evidence_gap import GapReport
        >>> state = new_qa_state("q")
        >>> state["gap_report"] = GapReport(has_enough=True)
        >>> route_after_gap_checker(state)
        'reasoner'
        >>> state["gap_report"] = GapReport(missing=["fixed_version"], has_enough=False)
        >>> route_after_gap_checker(state)
        'external_retriever'
    """
    report = state.get("gap_report")
    if report is None or report.has_enough:
        return NODE_REASONER
    return NODE_EXTERNAL_RETRIEVER


CONFIDENCE_BASE_WITH_CITATIONS: float = 0.5
"""有引用时的置信度基础分（Day24 新口径）。"""

CONFIDENCE_RELEVANCE_WEIGHT: float = 0.5
"""相关性权重：与用户指定 CVE 一致的引用占比 × 该权重。"""

CONFIDENCE_DEGRADED_FACTOR: float = 0.6
"""降级链路（无 LLM / 模板化答案 / 无引用）的整体折扣系数。"""

CONFIDENCE_PARTIAL_RETRIEVAL_FACTOR: float = 0.6
"""检索面不完备（计划中某路 0 命中 / 抛出异常）时的折扣系数。

数据缺口（如知识库缺修复版本 → 向量路 0 命中）本就不该给满分：即使引用
全部与问题相关，证据面也只有部分通路覆盖，因此与「降级」同档打折。
"""


def calculate_confidence(
    citations: Sequence[Citation],
    query_cve_ids: Sequence[str] = (),
    *,
    degraded: bool = False,
    incomplete_retrieval: bool = False,
) -> float:
    """按「引用相关性」加权计算答案置信度（纯函数，Day24 检索层修复）。

    旧口径 ``0.3 if (degraded or not citations) else 1.0`` 只看「有没有引用」：
    4 条引用里 3 条无关（哈希嵌入 / OR 语义全文的误召回）也会给 100%。
    新口径把「引用是否真正针对用户指定的 CVE」「检索面是否完备」计入打分::

        confidence = (base + relevance_ratio × 0.5) × degraded? × incomplete?

    - ``base``：有引用 ``0.5``，无引用 ``0``；
    - ``relevance_ratio``：``citations`` 中 ``cve_id`` 命中 ``query_cve_ids`` 的占比；
      查询未指定 CVE 时无从判定，按 ``1.0`` 计（不因缺少约束而降分）；
      ``cve_id`` 为 ``None``（如论文证据）在指定了 CVE 时计为不相关；
    - ``degraded``：整体 ×0.6；
    - ``incomplete_retrieval``：整体再 ×0.6（计划中有通路 0 命中 / 失败）。

    Args:
        citations: 最终引用列表。
        query_cve_ids: 用户问题中指定的 CVE 编号（大小写不敏感）。
        degraded: 是否走了降级链路（无 LLM / 模板化答案 / 无引用）。
        incomplete_retrieval: 检索面是否不完备（见
            :attr:`~aisec_intel.qa.agents.supervisor.SupervisorOutcome.partial`）。

    Returns:
        置信度（``[0.0, 1.0]``，保留 4 位小数）。

    Examples:
        >>> rel = Citation(source_type="pg", locator="unified_vuln:CVE-2024-34359", cve_id="CVE-2024-34359")
        >>> noise = Citation(source_type="chroma", locator="doc-1", cve_id="CVE-2026-71379")
        >>> calculate_confidence([rel, noise, noise, noise], ["CVE-2024-34359"])
        0.625
        >>> calculate_confidence([rel], ["CVE-2024-34359"])
        1.0
        >>> calculate_confidence([rel], ["CVE-2024-34359"], degraded=True)
        0.6
        >>> calculate_confidence([rel], ["CVE-2024-34359"], incomplete_retrieval=True)
        0.6
        >>> calculate_confidence([], ["CVE-2024-34359"])
        0.0
    """
    wanted = {str(item).strip().upper() for item in query_cve_ids if str(item).strip()}
    if not citations:
        score = 0.0
    else:
        matched = sum(1 for item in citations if item.cve_id and str(item.cve_id).strip().upper() in wanted)
        ratio = (matched / len(citations)) if wanted else 1.0
        score = CONFIDENCE_BASE_WITH_CITATIONS + ratio * CONFIDENCE_RELEVANCE_WEIGHT
    if degraded:
        score *= CONFIDENCE_DEGRADED_FACTOR
    if incomplete_retrieval:
        score *= CONFIDENCE_PARTIAL_RETRIEVAL_FACTOR
    return round(max(0.0, min(1.0, score)), 4)


def thread_config(thread_id: str, *, run_id: str | None = None) -> dict[str, Any]:
    """构造 LangGraph 运行配置（checkpointer 必需 ``thread_id``）。

    ``run_id`` 缺省为**每次运行唯一**（UUID），避免同 thread 复用旧检查点导致回答被跳过；
    多轮会话沿用同一 ``thread_id`` 即可（``run_id`` 保持默认）。

    Args:
        thread_id: 会话 ID（多轮对话用同一值）。
        run_id: 指定运行 ID；``None`` 时自动生成。

    Returns:
        形如 ``{"configurable": {"thread_id": ..., "run_id": ...}}`` 的配置字典。
    """
    return {"configurable": {"thread_id": thread_id, "run_id": run_id or uuid.uuid4().hex}}


class QAGraph:
    """问答图门面（编译产物 + 便捷调用）。

    Attributes:
        deps: 依赖集合。
    """

    def __init__(
        self,
        deps: QADeps,
        *,
        checkpointer: Any | None = None,
        top_k: int = DEFAULT_TOP_K,
        max_hops: int = MAX_HOPS,
    ) -> None:
        """装配并编译状态图。

        Args:
            deps: 四个 Agent 的依赖集合。
            checkpointer: LangGraph checkpointer；``None`` 表示不持久化中间状态。
            top_k: 默认召回条数（写入初始状态）。
            max_hops: 多跳上限（写入初始状态）。
        """
        self.deps = deps
        self._top_k = top_k
        self._max_hops = max_hops
        self._checkpointer = checkpointer
        builder = StateGraph(QAState)
        builder.add_node(NODE_UNDERSTANDER, deps.understander)
        builder.add_node(NODE_SUPERVISOR, deps.supervisor)
        builder.add_node(NODE_GAP_CHECKER, deps.gap_checker)
        builder.add_node(NODE_EXTERNAL_RETRIEVER, deps.external_retriever)
        builder.add_node(NODE_VERIFIER, deps.verifier)
        builder.add_node(NODE_REASONER, deps.reasoner)
        builder.add_node(NODE_SYNTHESIZER, deps.synthesizer)
        builder.add_edge(START, NODE_UNDERSTANDER)
        builder.add_edge(NODE_UNDERSTANDER, NODE_SUPERVISOR)
        builder.add_edge(NODE_SUPERVISOR, NODE_GAP_CHECKER)
        builder.add_conditional_edges(
            NODE_GAP_CHECKER,
            route_after_gap_checker,
            {NODE_REASONER: NODE_REASONER, NODE_EXTERNAL_RETRIEVER: NODE_EXTERNAL_RETRIEVER},
        )
        builder.add_edge(NODE_EXTERNAL_RETRIEVER, NODE_VERIFIER)
        builder.add_edge(NODE_VERIFIER, NODE_REASONER)
        builder.add_edge(NODE_REASONER, NODE_SYNTHESIZER)
        builder.add_edge(NODE_SYNTHESIZER, END)
        self.graph = builder.compile(checkpointer=checkpointer)

    async def ainvoke(
        self,
        question: str,
        *,
        thread_id: str | None = None,
        top_k: int | None = None,
        max_hops: int | None = None,
        session_context: Sequence[str] | None = None,
    ) -> tuple[QAResponse, QAState]:
        """执行一次完整问答（多轮：同一 ``thread_id`` 自动继承上一轮上下文）。

        Args:
            question: 用户问题。
            thread_id: 会话 ID（多轮对话用同一值）；``None`` 时为单轮。
            top_k: 覆盖默认召回条数。
            max_hops: 覆盖默认跳数。
            session_context: 显式提供的会话历史；``None`` 且有 checkpointer 时
                自动从上一轮检查点还原（Day12 任务 6）。

        Returns:
            ``(QAResponse, 最终状态)``。

        Raises:
            ValueError: 图执行完成但没有产出 ``answer``（属于缺陷，显式暴露）。
        """
        context = list(session_context or [])
        if not context and thread_id:
            context = await self.session_context(thread_id)
        state = new_qa_state(question, session_context=context)
        state["top_k"] = top_k or self._top_k
        state["max_hops"] = max_hops or self._max_hops
        # 挂载 checkpointer 时 langgraph 强制要求 ``thread_id``：单轮请求用一次性 ID 兜底
        resolved_thread = thread_id or (uuid.uuid4().hex if self._checkpointer is not None else None)
        config = thread_config(resolved_thread) if resolved_thread else None
        final: QAState = await self.graph.ainvoke(state, config=config)  # type: ignore[arg-type]
        answer = str(final.get("answer") or "")
        if not answer:
            raise ValueError("问答图未产出 answer（请检查 synthesizer 节点）")
        citations = list(final.get("citations") or [])
        degraded = bool(final.get("degraded"))
        # Day24 任务 3：置信度按「引用相关性」加权（不再只看有无引用）
        intent = final.get("intent")
        response = QAResponse(
            answer=answer,
            citations=citations,
            reasoning_chain=list(final.get("reasoning_chain") or []),
            confidence=calculate_confidence(
                citations,
                list(intent.entities.cve_ids) if intent is not None else [],
                degraded=degraded or not citations,
                incomplete_retrieval=bool(final.get("partial_retrieval")),
            ),
            degraded=degraded or not citations,
        )
        return response, final

    async def session_context(self, thread_id: str) -> list[str]:
        """从会话检查点还原上一轮的「问题 / 答案」文本（多轮上下文）。

        Args:
            thread_id: 会话 ID。

        Returns:
            历史文本列表（时间正序）；无检查点 / 无历史时为空列表。

        Note:
            读取失败（无 checkpointer、langgraph 版本差异、状态为空）一律返回空列表，
            **不阻断**当前问答（多轮上下文是增强项，不是必需项）。
        """
        if self._checkpointer is None:
            return []
        try:
            snapshot = await self.graph.aget_state(thread_config(thread_id))
        except Exception as exc:  # noqa: BLE001 - 上下文还原失败不影响单轮问答
            logger.warning(f"会话上下文还原失败（thread={thread_id}）：{type(exc).__name__}: {exc}")
            return []
        values: dict[str, Any] = dict(getattr(snapshot, "values", {}) or {})
        history = list(values.get("session_context") or [])
        previous_question = str(values.get("question") or "").strip()
        previous_answer = str(values.get("answer") or "").strip()
        if previous_question:
            history.append(f"上一轮问题：{previous_question}")
        if previous_answer:
            history.append(f"上一轮回答：{previous_answer}")
        return history


def build_qa_graph(
    deps: QADeps,
    *,
    checkpointer: Any | None = None,
    top_k: int = DEFAULT_TOP_K,
    max_hops: int = MAX_HOPS,
) -> QAGraph:
    """构建问答图（唯一入口）。

    Args:
        deps: 依赖集合。
        checkpointer: 可插拔检查点（``None`` 表示不持久化）。
        top_k: 默认召回条数。
        max_hops: 多跳上限。

    Returns:
        :class:`QAGraph` 实例。
    """
    return QAGraph(deps, checkpointer=checkpointer, top_k=top_k, max_hops=max_hops)


def graph_mermaid() -> str:
    """返回问答图的 Mermaid 源码（文档 / 答辩用，渲染无需真实依赖）。

    Returns:
        Mermaid ``graph TD`` 源码字符串。
    """
    return "\n".join(
        [
            "graph TD",
            f"  START --> {NODE_UNDERSTANDER}[query_understander 查询理解]",
            f"  {NODE_UNDERSTANDER} --> {NODE_SUPERVISOR}[supervisor 三路检索+RRF]",
            f"  {NODE_SUPERVISOR} --> {NODE_GAP_CHECKER}[gap_checker 证据缺口检测]",
            f"  {NODE_GAP_CHECKER} -->|证据足够| {NODE_REASONER}[reasoner 跨文档推理 ≤2 跳]",
            f"  {NODE_GAP_CHECKER} -->|证据缺口| {NODE_EXTERNAL_RETRIEVER}[external_retriever 受控外部检索]",
            f"  {NODE_EXTERNAL_RETRIEVER} --> {NODE_VERIFIER}[verifier 可信度评分+冲突裁决]",
            f"  {NODE_VERIFIER} --> {NODE_REASONER}",
            f"  {NODE_REASONER} --> {NODE_SYNTHESIZER}[synthesizer 强制引用+缺口声明]",
            f"  {NODE_SYNTHESIZER} --> END",
        ]
    )


def node_sequence() -> Sequence[str]:
    """返回主干节点顺序（文档与测试断言用）。

    Returns:
        节点名元组。
    """
    return NODE_SEQUENCE


async def run_qa(
    retrieval: RetrievalService,
    question: str,
    *,
    settings: Settings | None = None,
    use_llm: bool | None = None,
    top_k: int = DEFAULT_TOP_K,
    max_hops: int = MAX_HOPS,
    thread_id: str | None = None,
    session_context: Sequence[str] | None = None,
    session_factory: Callable[[], Any] | None = None,
    external_http: Any | None = None,
    enable_external: bool | None = None,
) -> tuple[QAResponse, QAState]:
    """一站式问答（CLI / API / 测试复用的最简入口）。

    Args:
        retrieval: 混合检索服务。
        question: 用户问题。
        settings: 全局配置。
        use_llm: 显式开关。
        top_k: 召回条数。
        max_hops: 多跳上限。
        thread_id: 会话 ID（多轮会话时传入）。
        session_context: 多轮会话历史（Day12 任务 6）；``None`` 时按需从检查点还原。
        session_factory: 外部证据落库的会话工厂；``None`` 时不落库。
        external_http: 外部检索 HTTP 客户端（测试注入）。
        enable_external: 显式开关外部检索；``None`` 时按配置。

    Returns:
        ``(QAResponse, 最终状态)``。
    """
    deps = build_qa_deps(
        retrieval,
        settings=settings,
        use_llm=use_llm,
        top_k=top_k,
        max_hops=max_hops,
        session_factory=session_factory,
        external_http=external_http,
        enable_external=enable_external,
    )
    return await build_qa_graph(deps, top_k=top_k, max_hops=max_hops).ainvoke(
        question, thread_id=thread_id, session_context=session_context
    )
