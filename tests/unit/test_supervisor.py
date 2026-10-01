"""Day10 Supervisor Agent 单元测试（``aisec_intel.qa.agents.supervisor``，§5.8）。

用检索服务桩替换真实四路检索，验证：计划调度、并发执行、单路失败隔离、RRF 融合与节点增量。
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from aisec_intel.qa.agents import supervisor as sup
from aisec_intel.qa.state import QueryEntities, QueryIntent, RetrievalResult, new_qa_state


class StubRetrieval:
    """检索服务桩：记录调用、可按路由注入结果 / 故障 / 延迟。"""

    def __init__(
        self,
        results: dict[str, list[RetrievalResult]] | None = None,
        *,
        fail: set[str] | None = None,
        delay: float = 0.0,
    ) -> None:
        """初始化桩。

        Args:
            results: 路由 → 预置结果。
            fail: 需要抛异常的路由集合。
            delay: 每次调用的模拟耗时（秒，用于并发断言）。
        """
        self.results = results or {}
        self.fail = fail or set()
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def dispatch(self, route: str, query: str, **kwargs: Any) -> list[RetrievalResult]:
        """桩实现：记录参数 → 可选延迟 → 返回预置结果或抛异常。"""
        self.calls.append({"route": route, "query": query, **kwargs})
        if self.delay:
            await asyncio.sleep(self.delay)
        if route in self.fail:
            raise RuntimeError(f"{route} 故障")
        return list(self.results.get(route, []))


def _result(route: str, cve: str, *, content: str = "content") -> RetrievalResult:
    """构造一条检索结果。"""
    return RetrievalResult(source=route, doc_id=f"{route}:{cve}", content=content, metadata={"cve_id": cve})


def _intent(*, plan: list[str] | None = None, **overrides: Any) -> QueryIntent:
    """构造查询意图（默认三路计划 + 一个 CVE 实体 + 一个技术实体）。"""
    payload: dict[str, Any] = {
        "query": "CVE-2024-3400 详情",
        "intent": "vuln_lookup",
        "entities": QueryEntities(cve_ids=["CVE-2024-3400"], techniques=["T1190"], keywords=["pan"]),
        "retrieval_plan": plan if plan is not None else ["vector", "fulltext", "graph"],
        "rewritten_query": "CVE-2024-3400",
        "confidence": 0.8,
        "parser": "rules",
    }
    payload.update(overrides)
    return QueryIntent(**payload)


class TestSupervisorDispatch:
    """计划调度与并发执行。"""

    async def test_dispatches_every_planned_route_with_entities(self) -> None:
        """按计划逐路调度，并把实体 / 过滤器透传给检索服务。"""
        stub = StubRetrieval({"vector": [_result("vector", "CVE-2024-3400")]})
        outcome = await sup.Supervisor(stub).run(_intent())  # type: ignore[arg-type]
        assert [call["route"] for call in stub.calls] == ["vector", "fulltext", "graph"]
        assert all(call["query"] == "CVE-2024-3400" for call in stub.calls)
        assert all(call["cve_ids"] == ["CVE-2024-3400"] for call in stub.calls)
        assert all(call["techniques"] == ["T1190"] for call in stub.calls)
        assert outcome.plan == ["vector", "fulltext", "graph"]
        assert set(outcome.route_counts) == {"vector", "fulltext", "graph"}

    async def test_runs_routes_concurrently(self) -> None:
        """三路并发执行（顺序执行耗时约为并发的 3 倍）。"""
        stub = StubRetrieval(delay=0.1)
        started = time.perf_counter()
        await sup.Supervisor(stub).run(_intent())  # type: ignore[arg-type]
        elapsed = time.perf_counter() - started
        assert elapsed < 0.25

    async def test_results_are_fused_by_entity(self) -> None:
        """同一 CVE 在向量 / 全文两路命中时融合为一条（多路加分）。"""
        stub = StubRetrieval(
            {
                "vector": [_result("vector", "CVE-2024-3400", content="short")],
                "fulltext": [_result("fulltext", "CVE-2024-3400", content="a longer snippet")],
            }
        )
        outcome = await sup.Supervisor(stub).run(_intent())  # type: ignore[arg-type]
        assert len(outcome.results) == 1
        assert {"vector", "fulltext"} <= set(outcome.results[0].route_scores)
        assert outcome.results[0].content == "a longer snippet"

    async def test_top_k_limits_results(self) -> None:
        """``top_k`` 覆盖默认召回条数。"""
        stub = StubRetrieval({"vector": [_result("vector", f"CVE-{index}") for index in range(9)]})
        outcome = await sup.Supervisor(stub, top_k=8).run(_intent(plan=["vector"]), top_k=2)  # type: ignore[arg-type]
        assert len(outcome.results) == 2

    async def test_route_failure_is_isolated(self) -> None:
        """单路异常不影响其它路，且错误可观测。"""
        stub = StubRetrieval({"vector": [_result("vector", "CVE-2024-3400")]}, fail={"graph"})
        outcome = await sup.Supervisor(stub).run(_intent())  # type: ignore[arg-type]
        assert outcome.route_counts["graph"] == 0
        assert outcome.results  # 其余路仍产出
        assert any(item.startswith("graph: RuntimeError") for item in outcome.errors)

    async def test_zero_hit_routes_are_reported(self) -> None:
        """全空结果时留下说明（前端可提示「索引未建」）。"""
        outcome = await sup.Supervisor(StubRetrieval()).run(_intent())  # type: ignore[arg-type]
        assert outcome.results == []
        assert len(outcome.errors) == 3

    async def test_weights_are_exposed(self) -> None:
        """权重可注入（评测调参）。"""
        supervisor = sup.Supervisor(StubRetrieval(), weights={"graph": 2.0})  # type: ignore[arg-type]
        assert supervisor.weights["graph"] == 2.0

    async def test_as_fusion_conversion(self) -> None:
        """``SupervisorOutcome`` 可转换为服务层 ``FusionOutcome``。"""
        stub = StubRetrieval({"vector": [_result("vector", "CVE-2024-3400")]})
        outcome = await sup.Supervisor(stub).run(_intent())  # type: ignore[arg-type]
        fusion = outcome.as_fusion()
        assert fusion.query == "CVE-2024-3400"
        assert fusion.results == outcome.results and fusion.plan == outcome.plan


    async def test_entity_boost_ranks_exact_cve_first(self) -> None:
        """带 CVE 的查询：精确命中的 CVE 排在融合首位（实体加成生效）。"""
        stub = StubRetrieval(
            {
                "vector": [_result("vector", "CVE-2024-33331", content="CVE-2024-33331 无关内容")],
                "graph": [_result("graph", "CVE-2024-3400", content="CVE-2024-3400 结构化情报")],
            }
        )
        outcome = await sup.Supervisor(stub).run(_intent(plan=["vector", "graph"]))  # type: ignore[arg-type]
        assert outcome.results[0].metadata["cve_id"] == "CVE-2024-3400"
        assert outcome.results[0].route_scores["entity_match"] == 0.5


class TestSupervisorNode:
    """LangGraph 节点入口。"""

    async def test_missing_intent_reports_error(self) -> None:
        """状态缺少意图时不抛异常，返回可观测错误。"""
        payload = await sup.Supervisor(StubRetrieval()).__call__(new_qa_state("随便问问"))  # type: ignore[arg-type]
        assert "results" not in payload
        assert payload["errors"][0].startswith(sup.AGENT_NAME)

    async def test_returns_incremental_results(self) -> None:
        """节点返回 ``results`` 增量（由 ``operator.add`` 归约器累积）。"""
        stub = StubRetrieval({"vector": [_result("vector", "CVE-2024-3400")]})
        state = new_qa_state("CVE-2024-3400 详情")
        state["intent"] = _intent()
        payload = await sup.Supervisor(stub).__call__(state)  # type: ignore[arg-type]
        assert payload["results"][0].metadata["cve_id"] == "CVE-2024-3400"
        assert payload["errors"]  # 两路 0 命中的说明

    async def test_dispatch_returns_plain_list(self) -> None:
        """``dispatch`` 直接返回融合结果列表。"""
        stub = StubRetrieval({"vector": [_result("vector", "CVE-2024-3400")]})
        results = await sup.Supervisor(stub).dispatch(_intent(plan=["vector"]))  # type: ignore[arg-type]
        assert isinstance(results, list) and results[0].source == "vector"
