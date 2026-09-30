"""Day7 富化图路由与装配测试（PROJECT_PLAN.md §5.6 ``enrich/graph.py``）。

覆盖：回流条件边（含**防死循环**上限）、checkpointer 生效、状态工厂、
以及「用桩节点跑通整图」的装配正确性（不触网、不调 LLM）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.enrich.graph import (
    DEFAULT_MAX_ROUNDS,
    END,
    NODE_ORDER,
    NODE_RETRY,
    EnrichmentDeps,
    build_enrichment_graph,
    graph_mermaid,
    increment_round,
    make_retry_router,
    thread_config,
)
from aisec_intel.enrich.state import EnrichmentState, new_state, state_summary
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.unified_vuln import CVSSVector, UnifiedVuln

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造一条用于富化测试的漏洞实体。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "title": "PAN-OS Command Injection",
        "cwe_ids": ["CWE-77"],
        "severity": "CRITICAL",
        "cvss": [CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")],
        "sources": ["nvd", "kev"],
        "trace_ids": ["trace-nvd"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


async def empty_searcher(cve_id: str) -> list[ExploitRecord]:
    """空检索器（模块级，供装配测试复用）。"""
    return []


class TestStateFactory:
    """状态工厂与摘要。"""

    def test_new_state_initializes_all_channels(self) -> None:
        """初始状态包含全部必需键，且置信度为 0（无结论）。"""
        state = new_state(make_vuln())
        assert state["trace_id"] == "trace-nvd"  # 取 vuln.trace_ids[0]
        assert state["round"] == 0
        assert state["confidence"] == 0.0
        assert state["agent_steps"] == []
        assert state["errors"] == []
        assert state["enriched_vuln"] is None
        assert state["paper_hits"] == [] and state["exploits"] == []

    def test_new_state_falls_back_to_vuln_id(self) -> None:
        """无 ``trace_ids`` 时用 ``vuln_id`` 作为追踪 ID。"""
        assert new_state(make_vuln(trace_ids=[]))["trace_id"] == "CVE-2024-3400"

    def test_state_summary_is_compact(self) -> None:
        """摘要只含计数与置信度，便于日志与断言。"""
        assert state_summary(new_state(make_vuln())) == {
            "cve_id": "CVE-2024-3400",
            "round": 0,
            "confidence": 0.0,
            "papers": 0,
            "exploits": 0,
            "assets": 0,
            "cvss_inferred": 0,
            "attack_steps": 0,
            "remediation": False,
            "steps": 0,
            "errors": 0,
        }


class TestRetryRouter:
    """回流条件边（纯函数）。"""

    @staticmethod
    def _state(*, confidence: float, round_no: int) -> EnrichmentState:
        """构造指定置信度与轮次的状态。"""
        state = new_state(make_vuln())
        state["confidence"] = confidence
        state["round"] = round_no
        return state

    def test_passes_when_confidence_high(self) -> None:
        """置信度达标 → 结束（END）。"""
        assert make_retry_router()(self._state(confidence=0.9, round_no=0)) == END

    def test_retries_when_confidence_low(self) -> None:
        """置信度不足且仍有回流余量 → 进入回流计数节点（其后接 ``poc_seeker``）。"""
        assert make_retry_router()(self._state(confidence=0.5, round_no=0)) == NODE_RETRY

    @pytest.mark.parametrize("round_no", [DEFAULT_MAX_ROUNDS, DEFAULT_MAX_ROUNDS + 1])
    def test_stops_at_max_rounds(self, round_no: int) -> None:
        """到达上限即结束（**防死循环**）。"""
        assert make_retry_router()(self._state(confidence=0.0, round_no=round_no)) == END

    def test_custom_threshold_and_rounds(self) -> None:
        """阈值与上限可配置。"""
        router = make_retry_router(max_rounds=1, min_confidence=0.5)
        assert router(self._state(confidence=0.5, round_no=0)) == END
        assert router(self._state(confidence=0.49, round_no=0)) == NODE_RETRY
        assert router(self._state(confidence=0.49, round_no=1)) == END

    def test_increment_round(self) -> None:
        """回流计数 +1。"""
        state = new_state(make_vuln())
        state["round"] = 1
        assert increment_round(state) == {"round": 2}


class TestGraphAssembly:
    """状态图装配（桩节点跑通整图）。"""

    async def test_graph_runs_all_nodes_and_finishes(self) -> None:
        """离线图跑通：三节点轨迹 + 置信度达标 → 一次通过（无回流）。"""
        calls: list[str] = []

        async def paper_search(keywords: Any, limit: int) -> list[Any]:
            calls.append("search")
            return []

        async def poc(cve_id: str) -> list[ExploitRecord]:
            calls.append(f"poc:{cve_id}")
            return [
                ExploitRecord(
                    source="nuclei",
                    url="https://example.test/nuclei",
                    maturity="poc",
                    verified=True,
                    reliability=0.8,
                )
            ]

        deps = EnrichmentDeps(
            paper_search=paper_search, searchers=[("nuclei", poc)], model_tag="retrieval-only"
        )
        graph = build_enrichment_graph(deps, max_rounds=2, min_confidence=0.5)

        final: EnrichmentState = await graph.ainvoke(new_state(make_vuln()))

        assert calls == ["search", "poc:CVE-2024-3400"]
        assert [step.agent for step in final["agent_steps"]] == list(NODE_ORDER)
        assert final["confidence"] >= 0.5
        assert final["round"] == 0  # 无回流
        assert final["enriched_vuln"] is not None
        assert {step.agent for step in final["agent_steps"]} == set(NODE_ORDER)

    async def test_low_confidence_retries_then_stops(self) -> None:
        """置信度始终不足 → 回流至上限后结束（多轮轨迹且**有限**）。"""
        poc_calls = 0

        async def poc(cve_id: str) -> list[ExploitRecord]:
            nonlocal poc_calls
            poc_calls += 1
            return []

        async def paper_search(keywords: Any, limit: int) -> list[Any]:
            return []

        deps = EnrichmentDeps(paper_search=paper_search, searchers=[("empty", poc)], model_tag="retrieval-only")
        graph = build_enrichment_graph(deps, max_rounds=2, min_confidence=0.7)

        final: EnrichmentState = await graph.ainvoke(new_state(make_vuln(sources=["unknown-source"])))

        assert poc_calls == 3  # 首轮 + 2 次回流（上限）
        assert final["round"] == 2
        assert final["confidence"] < 0.7
        agents = [step.agent for step in final["agent_steps"]]
        assert agents.count("poc_seeker") == 3
        assert agents.count("verifier") == 3
        assert final["enriched_vuln"] is not None
        assert final["enriched_vuln"].review_status == "needs_human"

    async def test_checkpointer_allows_state_query(self) -> None:
        """传入 checkpointer 后可按 ``thread_id`` 查询状态（断点续跑能力）。"""
        from langgraph.checkpoint.memory import InMemorySaver

        async def paper_search(keywords: Any, limit: int) -> list[Any]:
            return []

        saver = InMemorySaver()
        deps = EnrichmentDeps(
            paper_search=paper_search, searchers=[("empty", empty_searcher)], model_tag="retrieval-only"
        )
        graph = build_enrichment_graph(deps, checkpointer=saver, max_rounds=0, min_confidence=0.0)

        config = thread_config("CVE-2024-3400", run_id="unit")
        await graph.ainvoke(new_state(make_vuln()), config=config)
        snapshot = await graph.aget_state(config)
        assert snapshot is not None
        assert snapshot.values["unified_vuln"].vuln_id == "CVE-2024-3400"
        assert config["configurable"]["thread_id"] == "enrich:CVE-2024-3400:unit"

    def test_thread_config_uses_unique_run_id(self) -> None:
        """未指定 ``run_id`` 时每次生成唯一 thread_id（避免复用旧检查点）。"""
        first = thread_config("CVE-2024-3400")["configurable"]["thread_id"]
        second = thread_config("CVE-2024-3400")["configurable"]["thread_id"]
        assert first != second
        assert first.startswith("enrich:CVE-2024-3400:")

    def test_missing_search_dependency_raises(self) -> None:
        """缺少论文检索依赖时装配即失败（早暴露）。"""
        with pytest.raises(ValueError, match="paper_search"):
            build_enrichment_graph(EnrichmentDeps(paper_search=None, model_tag="x"))

    def test_nodes_registered(self) -> None:
        """图中包含四个节点（三个业务节点 + 回流计数节点）。"""

        async def paper_search(keywords: Any, limit: int) -> list[Any]:
            return []

        graph = build_enrichment_graph(
            EnrichmentDeps(paper_search=paper_search, searchers=[("empty", empty_searcher)], model_tag="x")
        )
        assert set(graph.get_graph().nodes) >= {"paper_linker", "poc_seeker", "verifier", NODE_RETRY}

    def test_mermaid_mentions_retry_guard(self) -> None:
        """Mermaid 图包含回流边与防死循环标注。"""
        diagram = graph_mermaid(max_rounds=2, min_confidence=0.7)
        assert diagram.startswith("graph TD")
        assert "round_bump" in diagram
        assert "防死循环" in diagram
