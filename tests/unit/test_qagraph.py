"""Day11 任务 4：QA LangGraph 单元测试（``aisec_intel.qa.graph``）。

覆盖：条件边路由、Mermaid 源码、checkpointer 支持、离线全链路（真实四个 Agent + 检索服务桩）。
不断言内部调用次数，只断言可观测产出（answer / citations / degraded / reasoning_chain）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.models.agent_io import QAResponse
from aisec_intel.qa.agents.synthesizer import NOT_FOUND_ANSWER
from aisec_intel.qa.graph import (
    NODE_REASONER,
    NODE_SYNTHESIZER,
    build_qa_deps,
    build_qa_graph,
    graph_mermaid,
    node_sequence,
    route_after_supervisor,
    run_qa,
    thread_config,
)
from aisec_intel.qa.state import RetrievalResult, new_qa_state

QUESTION = "CVE-2024-3400 影响哪些资产"


def _settings(**overrides: Any) -> Settings:
    """测试配置（默认关掉 LLM，走确定性降级路径）。"""
    base: dict[str, Any] = {"llm_api_key": "", "embedding_backend": "hashing", "neo4j_enabled": False}
    base.update(overrides)
    return Settings(**base)


def _result(doc_id: str = "graph:CVE-2024-3400") -> RetrievalResult:
    """构造检索结果（测试夹具）。"""
    return RetrievalResult(
        source="graph",
        doc_id=doc_id,
        content="PAN-OS 受影响组件 paloaltonetworks:pan-os",
        score=0.5,
        rank=1,
        metadata={"cve_id": "CVE-2024-3400", "url": "https://example.test/x"},
    )


class _StubRetrieval:
    """检索服务桩：只实现 Supervisor 需要的 ``dispatch``。"""

    def __init__(self, results: list[RetrievalResult]) -> None:
        """初始化桩。

        Args:
            results: ``graph`` 路的返回结果（其余路返回空，模拟「仅图谱有命中」）。
        """
        self._results = results
        self.routes: list[str] = []

    async def dispatch(self, route: str, query: str, **_: Any) -> list[RetrievalResult]:
        """按路由返回预置结果。"""
        self.routes.append(route)
        return list(self._results) if route == "graph" else []


class TestRoutingAndStructure:
    """条件边与静态结构。"""

    @pytest.mark.parametrize(
        ("results", "expected"), [([_result()], NODE_REASONER), ([], NODE_SYNTHESIZER)]
    )
    def test_route_after_supervisor(self, results: list[RetrievalResult], expected: str) -> None:
        """有证据进 Reasoner，无证据直达 Synthesizer。"""
        state = new_qa_state("q")
        state["fused"] = results
        assert route_after_supervisor(state) == expected

    def test_mermaid_contains_all_nodes(self) -> None:
        """Mermaid 源码含全部主干节点与「无证据」分支。"""
        mermaid = graph_mermaid()
        assert "graph TD" in mermaid and "无证据" in mermaid
        for node in node_sequence():
            assert node in mermaid

    def test_thread_config_shape(self) -> None:
        """``thread_config`` 生成 checkpointer 所需的 ``thread_id`` / ``run_id``。"""
        assert thread_config("session-1")["configurable"]["thread_id"] == "session-1"
        assert thread_config("s", run_id="r1")["configurable"]["run_id"] == "r1"


class TestOfflinePipeline:
    """离线全链路（真实四个 Agent，全部走确定性降级路径）。"""

    async def test_with_evidence_returns_cited_answer(self) -> None:
        """有检索证据：答案带真实引用、推理链非空、降级留痕。"""
        response, state = await run_qa(
            _StubRetrieval([_result()]),  # type: ignore[arg-type]
            QUESTION,
            settings=_settings(),
            use_llm=False,
        )
        assert response.answer
        assert response.citations[0].locator == "graph:CVE-2024-3400"
        assert response.degraded is True
        assert response.reasoning_chain
        assert state["errors"]  # 降级原因（无 LLM）写入状态

    async def test_without_evidence_returns_not_found(self) -> None:
        """无检索证据：跳过 Reasoner，返回标准「未找到相关信息」。"""
        response, _ = await run_qa(
            _StubRetrieval([]),  # type: ignore[arg-type]
            "完全无关的问题",
            settings=_settings(),
            use_llm=False,
        )
        assert response.answer == NOT_FOUND_ANSWER
        assert response.degraded is True and response.reasoning_chain == []

    async def test_checkpointer_supports_threads(self) -> None:
        """传入 checkpointer 后可用 ``thread_id`` 运行（多轮会话基础）。"""
        from langgraph.checkpoint.memory import InMemorySaver

        deps = build_qa_deps(_StubRetrieval([_result()]), settings=_settings(), use_llm=False)  # type: ignore[arg-type]
        graph = build_qa_graph(deps, checkpointer=InMemorySaver())
        response, _ = await graph.ainvoke(QUESTION, thread_id="session-1")
        assert isinstance(response, QAResponse) and response.answer

    async def test_response_satisfies_contract(self) -> None:
        """产出的 ``QAResponse`` 通过契约校验（非降级必须有引用）。"""
        response, _ = await run_qa(
            _StubRetrieval([_result()]), QUESTION, settings=_settings(), use_llm=False  # type: ignore[arg-type]
        )
        assert QAResponse.model_validate(response.model_dump()).answer == response.answer

    async def test_build_deps_respects_llm_switch(self) -> None:
        """``build_qa_deps`` 按 ``use_llm`` 装配（降级时全部 Agent 确定性）。"""
        deps = build_qa_deps(_StubRetrieval([]), settings=_settings(), use_llm=False)  # type: ignore[arg-type]
        assert deps.understander.llm_enabled is False
        assert deps.reasoner.model_tag == "no-llm"
        assert deps.synthesizer.model_tag == "no-llm"
