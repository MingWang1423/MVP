"""Supervisor Agent 骨架（Day10 P6 收尾；PROJECT_PLAN.md §5.8 ``qa/agents/supervisor.py``）。

职责：读 :class:`~aisec_intel.qa.state.QueryIntent` 的 ``retrieval_plan``，
用 ``asyncio.gather`` **并发**调度各路检索，RRF 融合后返回 ``list[RetrievalResult]``。

与 :class:`~aisec_intel.services.retrieval_service.RetrievalService` 的分工：

====================  =========================================================
组件                   职责
====================  =========================================================
``RetrievalService``  单路检索实现 + 融合算法（纯传统代码，无 LLM、无编排）
``Supervisor``        **编排**：读意图 → 组并发 → 逐路计时 → 融合 → 写回 ``QAState``
====================  =========================================================

设计要点：
    1. 并发用 ``asyncio.gather(return_exceptions=True)``：**单路失败不影响其它路**，
       失败原因写入 ``errors`` 与状态，前端可据此提示「某路降级」；
    2. 融合复用 :func:`~aisec_intel.services.retrieval_service.reciprocal_rank_fusion`
       （避免两处口径漂移）；
    3. 作为 LangGraph 节点时（:meth:`Supervisor.__call__`）只返回状态增量，
       ``results`` 通道带 ``operator.add`` 归约器，天然支持后续回流追加检索。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from aisec_intel.logging_config import get_logger
from aisec_intel.qa.multi_hop import extract_cve_ids
from aisec_intel.qa.state import (
    DEFAULT_TOP_K,
    QAState,
    QueryIntent,
    RetrievalResult,
)
from aisec_intel.services.retrieval_service import (
    DEFAULT_WEIGHTS,
    FusionOutcome,
    RetrievalService,
    boost_entity_matches,
    reciprocal_rank_fusion,
    vector_where_from_filters,
    with_cve_filter,
)
from aisec_intel.storage.vector_store import (
    COLLECTION_REMEDIATION_TEXTS,
    COLLECTION_VULN_DESCRIPTIONS,
)

logger = get_logger(__name__)

REMEDIATION_INTENTS: frozenset[str] = frozenset({"remediation"})
"""需要额外检索「处置要点」集合的意图（``remediation``）。"""

REMEDIATION_KEYWORDS: tuple[str, ...] = (
    "修复",
    "升级",
    "缓解",
    "补丁",
    "建议",
    "版本",
    "remediation",
    "fix",
    "upgrade",
    "mitigat",
    "patch",
)
"""修复类问题的关键词（命中即同时检索 ``remediation_texts``，Day18 任务 4 增强）。"""


def vector_collections_for(intent: QueryIntent) -> list[str]:
    """按意图选择向量集合（纯函数）。

    默认只检索 ``vuln_descriptions``（漏洞事实）；当问题是「修复 / 升级 / 缓解」类
    （意图为 ``remediation`` 或问句命中 :data:`REMEDIATION_KEYWORDS`）时，
    额外加入 ``remediation_texts``，使富化维度⑦的修复结论可被检索与引用
    （该集合由 ``render_remediation_text`` 渲染，含修复版本 / 缓解措施 / 白名单补丁链接）。

    Args:
        intent: 查询理解结果。

    Returns:
        向量集合名列表（保序、去重）。

    Examples:
        >>> intent = QueryIntent(intent="remediation", query="CVE-2024-3400 该升级到哪个版本？")
        >>> COLLECTION_REMEDIATION_TEXTS in vector_collections_for(intent)
        True
    """
    targets = [COLLECTION_VULN_DESCRIPTIONS]
    haystack = " ".join(
        [intent.intent, intent.rewritten_query, *intent.entities.keywords]
    ).lower()
    if intent.intent in REMEDIATION_INTENTS or any(keyword in haystack for keyword in REMEDIATION_KEYWORDS):
        targets.append(COLLECTION_REMEDIATION_TEXTS)
    return targets


AGENT_NAME: str = "supervisor"
"""节点名（日志与状态留痕）。"""


@dataclass(slots=True)
class SupervisorOutcome:
    """一次调度的完整结果（供 Reasoner / 调试台消费）。

    Attributes:
        intent: 本次调度的查询意图。
        plan: 实际执行的检索计划。
        results: 融合后的结果列表。
        route_counts: 各路命中条数。
        route_ms: 各路耗时（毫秒）。
        errors: 非致命错误 / 降级说明。
        elapsed_ms: 总耗时（毫秒）。
    """

    intent: QueryIntent
    plan: list[str] = field(default_factory=list)
    results: list[RetrievalResult] = field(default_factory=list)
    route_counts: dict[str, int] = field(default_factory=dict)
    route_ms: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    def as_fusion(self) -> FusionOutcome:
        """转换为 :class:`FusionOutcome`（复用同一出参结构）。

        Returns:
            等价的服务层结果对象。
        """
        return FusionOutcome(
            query=self.intent.rewritten_query or self.intent.query,
            results=list(self.results),
            route_counts=dict(self.route_counts),
            errors=list(self.errors),
            elapsed_ms=self.elapsed_ms,
            plan=list(self.plan),
        )


class Supervisor:
    """检索调度 Agent（并发执行检索计划 + RRF 融合）。

    Attributes:
        retrieval: 检索服务（可注入桩实现以便单测）。
    """

    def __init__(
        self,
        retrieval: RetrievalService,
        *,
        top_k: int = DEFAULT_TOP_K,
        weights: Mapping[str, float] | None = None,
    ) -> None:
        """初始化。

        Args:
            retrieval: 混合检索服务（唯一数据出口）。
            top_k: 单路召回与最终返回条数上限。
            weights: RRF 通路权重；``None`` 时等权（:data:`DEFAULT_WEIGHTS`）。
        """
        self.retrieval = retrieval
        self._top_k = max(1, top_k)
        self._weights = dict(weights or DEFAULT_WEIGHTS)

    @property
    def weights(self) -> dict[str, float]:
        """当前 RRF 权重（副本）。"""
        return dict(self._weights)

    async def run(
        self,
        intent: QueryIntent,
        *,
        top_k: int | None = None,
        collections: Sequence[str] | None = None,
    ) -> SupervisorOutcome:
        """按意图并发执行检索计划并融合（带逐路计时与错误留痕）。

        Args:
            intent: 查询理解结果（提供 ``retrieval_plan`` / 实体 / 过滤器 / 改写 query）。
            top_k: 覆盖默认召回条数。
            collections: 向量集合白名单（``None`` 用服务默认）。

        Returns:
            :class:`SupervisorOutcome`。
        """
        started = time.perf_counter()
        cap = max(1, top_k or self._top_k)
        plan = intent.resolved_plan()
        query = intent.rewritten_query.strip() or intent.query
        keywords = list(intent.entities.keywords)
        cve_ids = list(intent.entities.cve_ids)
        components = list(intent.entities.components)
        techniques = list(intent.entities.techniques)
        entity_cves = cve_ids or extract_cve_ids(query)
        # Day18 任务 4：明确 CVE 的问句把向量检索收敛到该 CVE（提升修复建议召回精度）
        where = with_cve_filter(vector_where_from_filters(intent.filters), entity_cves)
        vector_targets = list(collections) if collections else vector_collections_for(intent)

        async def _timed(route: str) -> tuple[list[RetrievalResult], int]:
            """执行单路检索并计时（毫秒）。"""
            route_started = time.perf_counter()
            results = await self.retrieval.dispatch(
                route,
                query,
                top_k=cap,
                cve_ids=cve_ids,
                components=components,
                techniques=techniques,
                collections=vector_targets,
                where=where,
                keywords=keywords,
            )
            return list(results), max(0, int((time.perf_counter() - route_started) * 1000))

        gathered = await asyncio.gather(*(_timed(route) for route in plan), return_exceptions=True)

        channels: dict[str, list[RetrievalResult]] = {}
        counts: dict[str, int] = {}
        route_ms: dict[str, int] = {}
        errors: list[str] = []
        for route, outcome in zip(plan, gathered, strict=True):
            if isinstance(outcome, BaseException):
                channels[route] = []
                counts[route] = 0
                route_ms[route] = 0
                errors.append(f"{route}: {type(outcome).__name__}: {outcome}")
                logger.warning(f"[{AGENT_NAME}] 检索通路失败（已降级继续）：{route} -> {outcome!r}")
                continue
            results, elapsed = outcome
            channels[route] = results
            counts[route] = len(results)
            route_ms[route] = elapsed
            if not results:
                errors.append(f"{route}: 0 命中（可能缺少实体、索引未建或数据未就绪）")

        fused = reciprocal_rank_fusion(channels, weights=self._weights, top_k=cap)
        boosted = boost_entity_matches(fused, cve_ids=entity_cves)
        return SupervisorOutcome(
            intent=intent,
            plan=plan,
            results=boosted,
            route_counts=counts,
            route_ms=route_ms,
            errors=errors,
            elapsed_ms=max(0, int((time.perf_counter() - started) * 1000)),
        )

    async def dispatch(
        self,
        intent: QueryIntent,
        *,
        top_k: int | None = None,
        collections: Sequence[str] | None = None,
    ) -> list[RetrievalResult]:
        """调度并直接返回融合结果（最常用的入口）。

        Args:
            intent: 查询理解结果。
            top_k: 覆盖默认召回条数。
            collections: 向量集合白名单。

        Returns:
            融合排序后的结果列表。
        """
        outcome = await self.run(intent, top_k=top_k, collections=collections)
        return outcome.results

    async def __call__(self, state: QAState) -> dict[str, Any]:
        """LangGraph 节点入口：读状态中的 ``intent``，返回状态增量。

        Args:
            state: 问答图状态。

        Returns:
            含 ``results``（增量）与必要 ``errors`` 的字典。
        """
        intent = state.get("intent")
        if intent is None:
            return {"errors": [f"{AGENT_NAME}: 状态缺少 intent（请先执行查询理解节点）"]}
        outcome = await self.run(intent)
        payload: dict[str, Any] = {"results": list(outcome.results), "fused": list(outcome.results)}
        if outcome.errors:
            payload["errors"] = [f"{AGENT_NAME}: {item}" for item in outcome.errors]
        return payload
