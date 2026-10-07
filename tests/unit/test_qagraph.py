"""Day11 任务 4：QA LangGraph 单元测试（``aisec_intel.qa.graph``）。

覆盖：条件边路由、Mermaid 源码、checkpointer 支持、离线全链路（真实四个 Agent + 检索服务桩）。
不断言内部调用次数，只断言可观测产出（answer / citations / degraded / reasoning_chain）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.models.agent_io import Citation, QAResponse
from aisec_intel.qa.agents.synthesizer import NOT_FOUND_ANSWER
from aisec_intel.qa.graph import (
    NODE_REASONER,
    NODE_SYNTHESIZER,
    build_qa_deps,
    build_qa_graph,
    calculate_confidence,
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


class TestConfidenceFormula:
    """Day24 任务 3：置信度按「引用相关性」加权（纯函数）。

    旧口径 ``0.3 if (degraded or not citations) else 1.0`` 只看有无引用；
    新口径 ``(0.5 + 相关占比×0.5) × 0.6(降级)``。
    """

    @staticmethod
    def _citation(cve: str | None) -> Citation:
        """构造一条引用（``cve_id`` 为 ``None`` 时代表论文 / 组件类证据）。"""
        return Citation(source_type="pg", locator=f"unified_vuln:{cve or 'doc'}", cve_id=cve)

    def test_relevance_ratio_weights_confidence(self) -> None:
        """4 条引用中 1 条相关 → 0.5 + 0.25×0.5 = 0.625；全部相关 → 1.0。"""
        relevant = self._citation("CVE-2024-34359")
        noise = self._citation("CVE-2026-71379")
        assert calculate_confidence([relevant, noise, noise, noise], ["CVE-2024-34359"]) == 0.625
        assert calculate_confidence([relevant, relevant, noise, noise], ["cve-2024-34359"]) == 0.75
        assert calculate_confidence([relevant], ["CVE-2024-34359"]) == 1.0

    def test_missing_query_cve_or_citations(self) -> None:
        """未指定 CVE 时按「全部相关」计；无引用为 0；引用缺 CVE 视为不相关。"""
        assert calculate_confidence([self._citation("CVE-1")], []) == 1.0
        assert calculate_confidence([], ["CVE-1"]) == 0.0
        assert calculate_confidence([self._citation(None)], ["CVE-1"]) == 0.5

    def test_degraded_discount(self) -> None:
        """降级链路整体 ×0.6（→ 4 条中 1 条相关为 0.375）。"""
        relevant = self._citation("CVE-2024-34359")
        noise = self._citation("CVE-2026-71379")
        assert calculate_confidence([relevant, noise, noise, noise], ["CVE-2024-34359"], degraded=True) == 0.375
        assert calculate_confidence([], [], degraded=True) == 0.0

    def test_incomplete_retrieval_discount(self) -> None:
        """检索面不完备（计划中某路 0 命中 / 失败）再打 0.6 折。"""
        relevant = self._citation("CVE-2024-34359")
        assert calculate_confidence([relevant], ["CVE-2024-34359"], incomplete_retrieval=True) == 0.6
        assert (
            calculate_confidence(
                [relevant], ["CVE-2024-34359"], degraded=True, incomplete_retrieval=True
            )
            == 0.36
        )


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

    async def test_confidence_reflects_citation_relevance(self) -> None:
        """Day24 任务 3：置信度 = (0.5 + 相关占比×0.5) × 降级折扣 × 缺路折扣。

        离线全链路：引用全部相关（1.0）→ ×0.6（无 LLM 降级）→ ×0.6（``multi_hop`` 0 命中）
        ＝ 0.36 < 1.0，不再出现「有引用即 100%」。
        """
        response, state = await run_qa(
            _StubRetrieval([_result()]),  # type: ignore[arg-type]
            QUESTION,
            settings=_settings(),
            use_llm=False,
        )
        assert [item.cve_id for item in response.citations] == ["CVE-2024-3400"]
        assert state["partial_retrieval"] is True  # 桩只在 graph 路返回结果
        assert response.confidence == 0.36 < 1.0

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


class TestMultiTurnSession:
    """Day12 任务 6：同一 ``thread_id`` 的多轮对话与上下文注入。"""

    async def test_multi_turn_inherits_previous_context(self) -> None:
        """第二轮自动继承上一轮「问题 + 答案」作为会话上下文。"""
        from langgraph.checkpoint.memory import InMemorySaver

        deps = build_qa_deps(_StubRetrieval([_result()]), settings=_settings(), use_llm=False)  # type: ignore[arg-type]
        graph = build_qa_graph(deps, checkpointer=InMemorySaver())
        _, first_state = await graph.ainvoke(QUESTION, thread_id="s-1")
        assert first_state["session_context"] == []  # 首轮无历史
        history = await graph.session_context("s-1")
        assert any("上一轮回答" in item for item in history)
        _, second_state = await graph.ainvoke("那它的修复方案呢？", thread_id="s-1")
        assert any("上一轮问题" in item for item in second_state["session_context"])
        assert await graph.session_context("unknown-thread") == []  # 未知会话不抛异常
        other = await build_qa_graph(deps).session_context("s-1")
        assert other == []  # 未挂 checkpointer 时无历史（不阻断问答）

    async def test_session_context_normalization_and_prompt(self) -> None:
        """上下文规范化（去空 / 截断 / 限长）与提示词注入；规则路径不受影响。"""
        from aisec_intel.qa.agents.query_understander import (
            SESSION_CONTEXT_MAX_ITEMS,
            build_prompt,
            normalize_session_context,
        )

        assert normalize_session_context(["  ", "", "a"]) == ["a"]
        assert normalize_session_context([f"h{index}" for index in range(10)]) == [
            f"h{index}" for index in range(10 - SESSION_CONTEXT_MAX_ITEMS, 10)
        ]
        assert normalize_session_context(["x" * 500])[0].__len__() == 300
        prompt = build_prompt(QUESTION, context=["上一轮问题：PAN-OS 漏洞"])
        assert "会话历史" in prompt and "上一轮问题：PAN-OS 漏洞" in prompt
        assert "会话历史" not in build_prompt(QUESTION)
        state = new_qa_state(QUESTION, session_context=["  ", "ctx"])
        assert state["session_context"] == ["ctx"]
