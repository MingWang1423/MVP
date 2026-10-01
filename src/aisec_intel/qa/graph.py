"""问答 LangGraph 主干（Day11 任务 4；PROJECT_PLAN.md §5.8 ``qa/graph.py``）。

链路::

    START → query_understander → supervisor ─┬─(有检索结果)→ reasoner → synthesizer → END
                                             └─(无检索结果)→ synthesizer（未找到相关信息）→ END

设计要点：

1. **依赖注入**：查询理解 / 检索调度 / 推理 / 合成四个 Agent 由 :class:`QADeps` 注入，
   「在线（LLM）」与「离线（降级）」走**同一张图**（与 ``enrich/graph.py`` 同构）；
2. **条件边**：检索为空时**跳过 Reasoner**（无证据不推理），直接由 Synthesizer 产出
   「未找到相关信息」并标记 ``degraded``——既省 token 又避免幻觉；
3. **可插拔 checkpointer**：``checkpointer=None`` 不持久化（无需 ``thread_id``）；
   传入 ``InMemorySaver`` 后可用 :func:`thread_config` 做多轮会话 / 断点续跑；
4. **异常隔离**：每个节点把非致命错误写入 ``state["errors"]``，单点失败不中断整条链路。
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from langgraph.graph import END, START, StateGraph

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import QAResponse
from aisec_intel.qa.agents.query_understander import QueryUnderstander, build_query_understander
from aisec_intel.qa.agents.reasoner import MAX_HOPS, ReasonerAgent, build_reasoner
from aisec_intel.qa.agents.supervisor import Supervisor
from aisec_intel.qa.agents.synthesizer import SynthesizerAgent, build_synthesizer
from aisec_intel.qa.state import DEFAULT_TOP_K, QAState, new_qa_state
from aisec_intel.services.retrieval_service import RetrievalService

logger = get_logger(__name__)

NODE_UNDERSTANDER: str = "query_understander"
"""节点①：查询理解（意图 / 实体 / 过滤 / 检索计划）。"""

NODE_SUPERVISOR: str = "supervisor"
"""节点②：检索调度（并发三路 + RRF 融合）。"""

NODE_REASONER: str = "reasoner"
"""节点③：跨文档推理（≤2 跳，带证据引用）。"""

NODE_SYNTHESIZER: str = "synthesizer"
"""节点④：答案合成（强制引用）。"""

NODE_SEQUENCE: tuple[str, ...] = (NODE_UNDERSTANDER, NODE_SUPERVISOR, NODE_REASONER, NODE_SYNTHESIZER)
"""主干节点顺序（文档 / 测试断言用）。"""


@dataclass(slots=True)
class QADeps:
    """问答图的依赖集合（全部可注入桩实现，便于离线测试）。

    Attributes:
        settings: 全局配置。
        understander: 查询理解 Agent。
        supervisor: 检索调度 Agent。
        reasoner: 推理 Agent。
        synthesizer: 答案合成 Agent。
    """

    settings: Settings
    understander: QueryUnderstander
    supervisor: Supervisor
    reasoner: ReasonerAgent
    synthesizer: SynthesizerAgent


def build_qa_deps(
    retrieval: RetrievalService,
    *,
    settings: Settings | None = None,
    use_llm: bool | None = None,
    top_k: int = DEFAULT_TOP_K,
    max_hops: int = MAX_HOPS,
) -> QADeps:
    """按配置装配四个 Agent（唯一装配入口；``use_llm=False`` 时全链路降级）。

    Args:
        retrieval: 混合检索服务（唯一数据出口）。
        settings: 全局配置；``None`` 时使用进程级单例。
        use_llm: 显式开关；``None`` 时由各工厂按配置推断。
        top_k: 单路召回条数上限（写入 Supervisor）。
        max_hops: 多跳上限（写入 Reasoner）。

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
    )


def route_after_supervisor(state: QAState) -> str:
    """条件边：有检索证据才进入 Reasoner，否则直达 Synthesizer（纯函数）。

    Args:
        state: 问答图状态（读取 ``fused`` / ``results``）。

    Returns:
        下一个节点名（``reasoner`` 或 ``synthesizer``）。
    """
    has_evidence = bool(state.get("fused") or state.get("results"))
    return NODE_REASONER if has_evidence else NODE_SYNTHESIZER


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
        builder = StateGraph(QAState)
        builder.add_node(NODE_UNDERSTANDER, deps.understander)
        builder.add_node(NODE_SUPERVISOR, deps.supervisor)
        builder.add_node(NODE_REASONER, deps.reasoner)
        builder.add_node(NODE_SYNTHESIZER, deps.synthesizer)
        builder.add_edge(START, NODE_UNDERSTANDER)
        builder.add_edge(NODE_UNDERSTANDER, NODE_SUPERVISOR)
        builder.add_conditional_edges(
            NODE_SUPERVISOR,
            route_after_supervisor,
            {NODE_REASONER: NODE_REASONER, NODE_SYNTHESIZER: NODE_SYNTHESIZER},
        )
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
    ) -> tuple[QAResponse, QAState]:
        """执行一次完整问答。

        Args:
            question: 用户问题。
            thread_id: 会话 ID；``None`` 时不带 checkpointer 配置。
            top_k: 覆盖默认召回条数。
            max_hops: 覆盖默认跳数。

        Returns:
            ``(QAResponse, 最终状态)``。

        Raises:
            ValueError: 图执行完成但没有产出 ``answer``（属于缺陷，显式暴露）。
        """
        state = new_qa_state(question)
        state["top_k"] = top_k or self._top_k
        state["max_hops"] = max_hops or self._max_hops
        config = thread_config(thread_id) if thread_id else None
        final: QAState = await self.graph.ainvoke(state, config=config)  # type: ignore[arg-type]
        answer = str(final.get("answer") or "")
        if not answer:
            raise ValueError("问答图未产出 answer（请检查 synthesizer 节点）")
        citations = list(final.get("citations") or [])
        degraded = bool(final.get("degraded"))
        response = QAResponse(
            answer=answer,
            citations=citations,
            reasoning_chain=list(final.get("reasoning_chain") or []),
            confidence=0.3 if (degraded or not citations) else 1.0,
            degraded=degraded or not citations,
        )
        return response, final


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
            f"  {NODE_SUPERVISOR} -->|有证据| {NODE_REASONER}[reasoner 跨文档推理 ≤2 跳]",
            f"  {NODE_SUPERVISOR} -->|无证据| {NODE_SYNTHESIZER}",
            f"  {NODE_REASONER} --> {NODE_SYNTHESIZER}[synthesizer 强制引用]",
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

    Returns:
        ``(QAResponse, 最终状态)``。
    """
    deps = build_qa_deps(retrieval, settings=settings, use_llm=use_llm, top_k=top_k, max_hops=max_hops)
    return await build_qa_graph(deps, top_k=top_k, max_hops=max_hops).ainvoke(question, thread_id=thread_id)
