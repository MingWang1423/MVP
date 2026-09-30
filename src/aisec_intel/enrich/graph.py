"""富化 LangGraph 状态图（PROJECT_PLAN.md §5.6 ``enrich/graph.py``）。

图结构（P5 MVP，对应 §5.6 的 7-Agent 主干子集）::

    START → paper_linker → poc_seeker → verifier ─┬─(confidence ≥ 0.7 或 round ≥ max_rounds)─→ END
                                                  └─(confidence < 0.7 且 round < max_rounds)
                                                        → round_bump（计数 +1）→ poc_seeker

设计要点：

1. **显式状态机**（``StateGraph`` + 条件边）：回流次数上限 ``max_rounds``（默认 2），
   超过即结束并由 Verifier 标记 ``review_status="needs_human"`` —— **防死循环**；
2. **可插拔 checkpointer**：默认 ``InMemorySaver``（单进程演示 / 测试），
   生产切 PostgreSQL / SQLite 版 Saver 只需换一个参数；
3. **依赖注入**：检索器、LLM、HTTP 客户端全部由 :class:`EnrichmentDeps` 注入，
   因此「离线（无 Key / 无网络）」与「在线」走**同一张图**；
4. **异常隔离**：节点内部把非致命错误写入 ``state["errors"]``，单点失败不中断整条链路。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from langgraph.graph import END, START, StateGraph

from aisec_intel.config import Settings, get_settings
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.agents.paper_linker import PaperLinkerAgent
from aisec_intel.enrich.agents.poc_seeker import PoCSearcher, PoCSeekerAgent
from aisec_intel.enrich.agents.verifier import VerifierAgent
from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_MAX_ROUNDS: int = 2
"""最大回流次数（§3.2 闸门④ ``max_rounds=2``）。"""

NODE_PAPER_LINKER: str = "paper_linker"
"""节点名：关联论文。"""

NODE_POC_SEEKER: str = "poc_seeker"
"""节点名：PoC / EXP 检索。"""

NODE_VERIFIER: str = "verifier"
"""节点名：交叉验证 + 置信度裁决。"""

NODE_RETRY: str = "round_bump"
"""节点名：回流计数 +1（``verifier → round_bump → poc_seeker``，保证有限回流）。"""


@dataclass(slots=True)
class EnrichmentDeps:
    """富化图的依赖集合（全部可注入，便于离线与单测）。

    Attributes:
        settings: 全局配置。
        paper_search: 论文检索函数 ``(keywords, limit) -> list[PaperHit]``。
        structured_llm: PaperLinker 用的结构化输出 Runnable；``None`` 时走检索折算降级。
        searchers: PoC 检索器列表 ``[(源名, 检索器), ...]``；``None`` 时用默认三源。
        http: HTTP 客户端（PoC 抓取 + URL 可达性检查共用）。
        model_tag: 写入 ``AgentStep.model_used`` 的模型标识。
    """

    settings: Settings = field(default_factory=get_settings)
    paper_search: Callable[[Sequence[str], int], Any] | None = None
    structured_llm: Any | None = None
    searchers: Sequence[tuple[str, PoCSearcher]] | None = None
    http: HttpClient | None = None
    model_tag: str = "unset"


def build_enrichment_graph(
    deps: EnrichmentDeps,
    *,
    checkpointer: Any | None = None,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    min_confidence: float = 0.7,
) -> Any:
    """装配富化状态图（返回可 ``ainvoke`` 的编译产物）。

    Args:
        deps: 依赖集合（检索 / LLM / HTTP）。
        checkpointer: LangGraph checkpointer；``None`` 表示**不持久化中间状态**
            （无需 ``thread_id``，适合一次性富化）。需要断点续跑时传入
            ``InMemorySaver`` / PostgreSQL Saver，并用 :func:`thread_config` 生成配置。
        max_rounds: 最大回流次数（``verifier → poc_seeker``）。
        min_confidence: 自动通过阈值，低于该值触发回流。

    Returns:
        编译后的 ``CompiledStateGraph``。

    Raises:
        ValueError: ``deps.paper_search`` 未提供（论文检索是必需依赖）。
    """
    if deps.paper_search is None:
        raise ValueError("EnrichmentDeps.paper_search 未提供：富化图需要论文检索函数（可注入离线桩）")

    paper_linker = PaperLinkerAgent(
        search=deps.paper_search,
        structured_llm=deps.structured_llm,
        model_tag=deps.model_tag,
    )
    poc_seeker = PoCSeekerAgent(searchers=deps.searchers, settings=deps.settings, http=deps.http)
    verifier = VerifierAgent(http=deps.http, min_confidence=min_confidence)

    graph: StateGraph = StateGraph(EnrichmentState)
    graph.add_node(NODE_PAPER_LINKER, paper_linker)
    graph.add_node(NODE_POC_SEEKER, poc_seeker)
    graph.add_node(NODE_VERIFIER, verifier)
    graph.add_node(NODE_RETRY, increment_round)

    graph.add_edge(START, NODE_PAPER_LINKER)
    graph.add_edge(NODE_PAPER_LINKER, NODE_POC_SEEKER)
    graph.add_edge(NODE_POC_SEEKER, NODE_VERIFIER)
    graph.add_conditional_edges(
        NODE_VERIFIER,
        make_retry_router(max_rounds=max_rounds, min_confidence=min_confidence),
        {NODE_RETRY: NODE_RETRY, END: END},
    )
    # 回流路径：先「计数 +1」，再重跑 PoCSeeker（保证有限次回流，防死循环）
    graph.add_edge(NODE_RETRY, NODE_POC_SEEKER)
    return graph.compile(checkpointer=checkpointer)


def thread_config(cve_id: str, *, run_id: str | None = None) -> dict[str, Any]:
    """构造 LangGraph 运行配置（checkpointer 必需 ``thread_id``）。

    ``run_id`` 缺省为 **每次运行唯一**（用 UUID），避免「同 thread 复用旧检查点」
    导致富化被跳过；如需断点续跑，请显式传入上次的 ``run_id``。

    Args:
        cve_id: 漏洞主键（写入 thread_id 便于排查）。
        run_id: 指定运行 ID；``None`` 时自动生成。

    Returns:
        形如 ``{"configurable": {"thread_id": "enrich:CVE-2024-3400:xxxx"}}`` 的配置。
    """
    import uuid

    resolved = run_id or uuid.uuid4().hex[:8]
    return {"configurable": {"thread_id": f"enrich:{cve_id}:{resolved}"}}


def make_retry_router(
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    min_confidence: float = 0.7,
) -> Callable[[EnrichmentState], str]:
    """生成「是否回流」的路由函数（纯函数，便于单测直接调用）。

    回流条件：``confidence < min_confidence`` **且** ``round < max_rounds``；
    回流目标是 :data:`NODE_RETRY`（先计数 +1，再进入 ``poc_seeker``，见 :func:`build_enrichment_graph`），
    否则返回 :data:`~langgraph.graph.END`（由 Verifier 决定 ``review_status``）。

    Args:
        max_rounds: 最大回流次数。
        min_confidence: 通过阈值。

    Returns:
        形如 ``route(state) -> NODE_RETRY | END`` 的可调用对象。
    """

    def route(state: EnrichmentState) -> str:
        """决定下一步节点。"""
        confidence = float(state.get("confidence") or 0.0)
        round_no = int(state.get("round") or 0)
        if confidence >= min_confidence:
            return END
        if round_no >= max_rounds:
            logger.info(f"回流次数已达上限（round={round_no}，confidence={confidence}），结束富化")
            return END
        logger.info(
            f"置信度不足（{confidence} < {min_confidence}），回流到 {NODE_POC_SEEKER}（经 {NODE_RETRY} 计数）"
        )
        return NODE_RETRY

    return route


def increment_round(state: EnrichmentState) -> dict[str, int]:
    """回流计数 +1（纯函数，供边函数 / 扩展图使用）。

    Args:
        state: 富化图状态。

    Returns:
        ``{"round": state["round"] + 1}``。
    """
    return {"round": int(state.get("round") or 0) + 1}


def graph_mermaid(*, max_rounds: int = DEFAULT_MAX_ROUNDS, min_confidence: float = 0.7) -> str:
    """返回状态图的 Mermaid 源码（文档 / 答辩用，渲染无需真实依赖）。

    Args:
        max_rounds: 最大回流次数（写入标注）。
        min_confidence: 通过阈值（写入标注）。

    Returns:
        Mermaid ``graph TD`` 源码字符串。
    """
    return "\n".join(
        [
            "graph TD",
            "  START((START)) --> paper_linker[paper_linker 关联论文]",
            "  paper_linker --> poc_seeker[poc_seeker PoC/EXP 检索]",
            "  poc_seeker --> verifier[verifier 交叉验证]",
            f"  verifier -->|confidence >= {min_confidence}| DONE((END))",
            f"  verifier -->|confidence < {min_confidence} 且 round < {max_rounds}| round_bump[round_bump]",
            "  round_bump --> poc_seeker",
            f"  verifier -.->|round >= {max_rounds}（防死循环）| DONE",
        ]
    )
