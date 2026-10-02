"""Day11 任务 2：Reasoner Agent 单元测试（``aisec_intel.qa.agents.reasoner``）。

只断言公开行为：引用必须来自候选集、跳数受控、失败降级、节点状态增量。
LLM 用 conftest 的 ``stub_structured_model`` 桩替换（不联网）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.models.agent_io import ReasoningDraft, ReasoningStepDraft
from aisec_intel.qa.agents.reasoner import (
    MAX_HOPS,
    ReasonerAgent,
    citation_of,
    degraded_steps,
    normalize_steps,
)
from aisec_intel.qa.state import QueryEntities, QueryIntent, RetrievalResult, new_qa_state


def _intent(query: str = "CVE-2024-3400 影响哪些资产") -> QueryIntent:
    """构造查询意图（测试夹具）。"""
    return QueryIntent(
        query=query,
        intent="asset_lookup",
        entities=QueryEntities(cve_ids=["CVE-2024-3400"]),
        rewritten_query="CVE-2024-3400",
        confidence=0.8,
    )


def _result(
    route: str, doc_id: str, *, content: str = "证据正文", cve: str | None = "CVE-2024-3400"
) -> RetrievalResult:
    """构造检索结果（测试夹具）。"""
    metadata: dict[str, Any] = {}
    if cve:
        metadata["cve_id"] = cve
    if route == "graph":
        metadata["url"] = f"https://example.test/{doc_id}"
    return RetrievalResult(source=route, doc_id=doc_id, content=content, score=0.5, rank=1, metadata=metadata)


def _draft(*steps: tuple[str, list[str]]) -> ReasoningDraft:
    """由 ``(结论, 证据 id)`` 序列构造 LLM 草稿。"""
    return ReasoningDraft(
        steps=[
            ReasoningStepDraft(hop=index, question=f"子问题 {index}", conclusion=conclusion, evidence_doc_ids=ids)
            for index, (conclusion, ids) in enumerate(steps, start=1)
        ]
    )


class TestCitationOf:
    """引用构造口径（可回溯性基础）。"""

    @pytest.mark.parametrize(
        ("route", "expected_source"),
        [("vector", "chroma"), ("graph", "neo4j"), ("multi_hop", "neo4j"), ("fulltext", "pg")],
    )
    def test_route_maps_to_citation_source(self, route: str, expected_source: str) -> None:
        assert citation_of(_result(route, "doc-1")).source_type == expected_source

    def test_quote_and_locator_come_from_result(self) -> None:
        """``locator`` 用文档主键、``quote`` 取正文片段（全部来自真实检索结果）。"""
        citation = citation_of(_result("graph", "graph:CVE-2024-3400", content="x" * 500))
        assert citation.locator == "graph:CVE-2024-3400"
        assert citation.cve_id == "CVE-2024-3400"
        assert citation.url == "https://example.test/graph:CVE-2024-3400"
        assert citation.quote is not None and len(citation.quote) == 200


class TestNormalizeSteps:
    """LLM 草稿 → 带真实引用的推理链（禁止编造引用）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_accepts_only_known_doc_ids()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_accepts_only_known_doc_ids: {type(exc).__name__}: {exc}")
        try:
            self._case_test_truncates_to_max_hops_and_renumbers()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_truncates_to_max_hops_and_renumbers: {type(exc).__name__}: {exc}")
        try:
            self._case_test_min_evidence_filters_steps()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_min_evidence_filters_steps: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_draft()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_draft: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_accepts_only_known_doc_ids(self) -> None:
        """候选集之外的 doc_id 被丢弃，整步无证据时该步被删除。"""
        results = [_result("graph", "graph:A"), _result("vector", "vector:B")]
        draft = _draft(("结论一", ["graph:A", "bogus-id"]), ("结论二", ["bogus-id"]))
        steps = normalize_steps(draft, results)
        assert len(steps) == 1
        assert [item.locator for item in steps[0].evidence] == ["graph:A"]

    def _case_test_truncates_to_max_hops_and_renumbers(self) -> None:
        """超过 ``max_hops`` 的步骤被截断，跳号连续。"""
        results = [_result("graph", "graph:A")]
        draft = _draft(("一", ["graph:A"]), ("二", ["graph:A"]), ("三", ["graph:A"]))
        steps = normalize_steps(draft, results, max_hops=MAX_HOPS)
        assert [step.hop for step in steps] == [1, 2]

    def _case_test_min_evidence_filters_steps(self) -> None:
        """要求两步以上证据时，单证据步骤被丢弃。"""
        results = [_result("graph", "graph:A"), _result("vector", "vector:B")]
        draft = _draft(("一", ["graph:A"]), ("二", ["graph:A", "vector:B"]))
        steps = normalize_steps(draft, results, min_evidence=2)
        assert len(steps) == 1 and len(steps[0].evidence) == 2

    def _case_test_empty_draft(self) -> None:
        assert normalize_steps(_draft(), [_result("graph", "graph:A")]) == []


class TestDegradedSteps:
    """无 LLM 的确定性推理链。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_empty_results_yield_no_steps()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_results_yield_no_steps: {type(exc).__name__}: {exc}")
        try:
            self._case_test_picks_graph_first_then_cross_check()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_picks_graph_first_then_cross_check: {type(exc).__name__}: {exc}")
        try:
            self._case_test_max_hops_one_keeps_single_step()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_max_hops_one_keeps_single_step: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_empty_results_yield_no_steps(self) -> None:
        assert degraded_steps(_intent(), []) == []

    def _case_test_picks_graph_first_then_cross_check(self) -> None:
        """第 1 跳取图谱证据，第 2 跳交叉印证其余来源。"""
        results = [_result("vector", "vector:A"), _result("graph", "graph:B"), _result("fulltext", "pg:C")]
        steps = degraded_steps(_intent(), results)
        assert [step.hop for step in steps] == [1, 2]
        assert steps[0].evidence[0].locator == "graph:B"
        assert {item.locator for item in steps[1].evidence} == {"vector:A", "pg:C"}

    def _case_test_max_hops_one_keeps_single_step(self) -> None:
        steps = degraded_steps(_intent(), [_result("graph", "graph:A"), _result("vector", "vector:B")], max_hops=1)
        assert len(steps) == 1


class TestReasonerAgent:
    """Agent 公开行为：LLM 成功 / 失败降级 / 空结果 / 节点增量。"""

    async def test_llm_success_uses_only_real_evidence(self, stub_structured_model: type) -> None:
        """LLM 成功：输出推理链，证据全部命中候选集。"""
        results = [_result("graph", "graph:A"), _result("fulltext", "pg:B")]
        model = stub_structured_model([_draft(("A 影响 pan-os", ["graph:A"]), ("因此资产受影响", ["graph:A", "pg:B"]))])
        agent = ReasonerAgent(structured_llm=model, model_tag="deepseek-reasoner")
        outcome = await agent.reason(_intent(), results)
        assert outcome.degraded is False and outcome.model_used == "deepseek-reasoner"
        assert [step.hop for step in outcome.steps] == [1, 2]

    async def test_llm_failure_falls_back(self, stub_structured_model: type) -> None:
        """结构化失败：降级为确定性推理链且带 ``error`` 说明。"""
        model = stub_structured_model([ValueError("解析失败")])
        agent = ReasonerAgent(structured_llm=model, max_retries=0)
        outcome = await agent.reason(_intent(), [_result("graph", "graph:A")])
        assert outcome.degraded is True and outcome.model_used == "no-llm"
        assert outcome.error and outcome.steps

    async def test_hallucinated_evidence_falls_back(self, stub_structured_model: type) -> None:
        """LLM 只给不存在的 doc_id：不产出无据推理，降级处理。"""
        model = stub_structured_model([_draft(("编造结论", ["not-retrieved-id"]))])
        agent = ReasonerAgent(structured_llm=model, max_retries=0)
        outcome = await agent.reason(_intent(), [_result("graph", "graph:A")])
        assert outcome.degraded is True
        assert outcome.error is not None and "可回溯证据" in outcome.error

    async def test_no_results_skips_reasoning(self) -> None:
        """无检索结果时不调用 LLM，直接返回空链 + 说明。"""
        outcome = await ReasonerAgent(structured_llm=object()).reason(_intent(), [])
        assert outcome.steps == [] and "为空" in (outcome.error or "")

    async def test_node_payload_writes_chain_and_degrade(self, stub_structured_model: type) -> None:
        """LangGraph 节点：返回 ``reasoning_chain`` 增量，降级时带 ``degraded`` 与 ``errors``。"""
        model = stub_structured_model([ValueError("失败")])
        state = new_qa_state("CVE-2024-3400 影响哪些资产")
        state["intent"] = _intent()
        state["fused"] = [_result("graph", "graph:A")]
        payload = await ReasonerAgent(structured_llm=model, max_retries=0).__call__(state)
        assert payload["reasoning_chain"]
        assert payload["degraded"] is True
        assert payload["errors"][0].startswith("reasoner")

    async def test_node_without_intent_reports_error(self) -> None:
        payload = await ReasonerAgent().__call__(new_qa_state("q"))
        assert payload["errors"] and "缺少 intent" in payload["errors"][0]


class TestFactory:
    """工厂开关（不发起网络请求）。"""

    @pytest.mark.parametrize(
        ("overrides", "expected_tag"),
        [
            ({"degraded_mode": True}, "no-llm"),
            ({"llm_api_key": ""}, "no-llm"),
            ({"llm_api_key": "sk-x"}, "deepseek-reasoner"),
        ],
    )
    def test_build_reasoner_switches(self, overrides: dict[str, Any], expected_tag: str) -> None:
        from aisec_intel.config import Settings
        from aisec_intel.qa.agents.reasoner import build_reasoner

        settings = Settings(**overrides)
        assert build_reasoner(settings).model_tag == expected_tag