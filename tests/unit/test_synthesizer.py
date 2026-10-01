"""Day11 任务 3：Synthesizer Agent 单元测试（``aisec_intel.qa.agents.synthesizer``）。

只断言公开行为：每条论断必须带可回溯引用、编造引用被丢弃、失败降级为模板化答案。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.models.agent_io import AnswerClaimDraft, AnswerDraft, QAResponse
from aisec_intel.qa.agents.synthesizer import (
    NOT_FOUND_ANSWER,
    SynthesizerAgent,
    degraded_answer,
    synthesize,
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


def _result(route: str, doc_id: str, *, content: str = "证据正文") -> RetrievalResult:
    """构造检索结果（测试夹具）。"""
    return RetrievalResult(
        source=route,
        doc_id=doc_id,
        content=content,
        score=0.5,
        rank=1,
        metadata={"cve_id": "CVE-2024-3400", "url": f"https://example.test/{doc_id}"},
    )


def _draft(*claims: tuple[str, list[str]], summary: str = "总体结论", confidence: float = 0.8) -> AnswerDraft:
    """由 ``(论断, 证据 id)`` 序列构造 LLM 草稿。"""
    return AnswerDraft(
        summary=summary,
        claims=[AnswerClaimDraft(claim=text, evidence_doc_ids=ids) for text, ids in claims],
        confidence=confidence,
    )


class TestSynthesize:
    """纯函数：论断筛选 + 引用拼装。"""

    def test_keeps_claims_with_known_evidence(self) -> None:
        """有效论断保留，答案含 summary 与行内依据标注。"""
        results = [_result("graph", "graph:A"), _result("fulltext", "pg:B")]
        answer, citations, dropped = synthesize(_draft(("A 影响 B", ["graph:A"])), results)
        assert answer.startswith("总体结论") and "A 影响 B" in answer and "依据：graph:A" in answer
        assert [item.locator for item in citations] == ["graph:A"]
        assert dropped == 0

    def test_drops_hallucinated_claims(self) -> None:
        """编造 doc_id 的论断被整条丢弃并计数（禁止编造引用）。"""
        results = [_result("graph", "graph:A")]
        answer, citations, dropped = synthesize(_draft(("真", ["graph:A"]), ("假", ["ghost-doc"])), results)
        assert dropped == 1
        assert "假" not in answer
        assert [item.locator for item in citations] == ["graph:A"]

    def test_dedupes_citations(self) -> None:
        """同一 doc_id 在多条论断中复用时不重复生成引用。"""
        results = [_result("graph", "graph:A")]
        _, citations, _ = synthesize(_draft(("一", ["graph:A"]), ("二", ["graph:A"])), results)
        assert len(citations) == 1

    def test_all_claims_dropped_keeps_summary_and_note(self) -> None:
        """全部论断无证据时保留 summary 并给出提示（引用为空）。"""
        answer, citations, dropped = synthesize(_draft(("假", ["ghost"])), [_result("graph", "graph:A")])
        assert citations == [] and dropped == 1
        assert "以引用列表为准" in answer

    @pytest.mark.parametrize(("max_claims", "expected"), [(1, 1), (2, 2)])
    def test_max_claims_limit(self, max_claims: int, expected: int) -> None:
        results = [_result("graph", f"graph:{index}") for index in range(4)]
        draft = _draft(*[(f"论断 {index}", [f"graph:{index}"]) for index in range(4)])
        _, citations, _ = synthesize(draft, results, max_claims=max_claims)
        assert len(citations) == expected


class TestDegradedAnswer:
    """模板化兜底（仍带真实引用）。"""

    def test_no_results_returns_not_found(self) -> None:
        answer, citations = degraded_answer([])
        assert answer == NOT_FOUND_ANSWER and citations == []

    def test_uses_real_results(self) -> None:
        answer, citations = degraded_answer([_result("graph", "graph:A"), _result("vector", "vector:B")])
        assert "最相关的检索结果" in answer and "graph:A" in answer
        assert {item.locator for item in citations} == {"graph:A", "vector:B"}


class TestSynthesizerAgent:
    """Agent 公开行为：LLM 成功 / 编造证据降级 / 空结果 / 节点增量。"""

    async def test_llm_success_produces_cited_answer(self, stub_structured_model: type) -> None:
        """LLM 成功：答案含引用，``degraded=False``，推理链透传。"""
        results = [_result("graph", "graph:A"), _result("fulltext", "pg:B")]
        model = stub_structured_model([_draft(("A 影响 pan-os", ["graph:A"]))])
        agent = SynthesizerAgent(structured_llm=model, model_tag="deepseek-chat")
        outcome = await agent.synthesize(_intent(), results)
        response = outcome.response
        assert response.degraded is False
        assert response.citations and response.citations[0].locator == "graph:A"
        assert response.confidence == 0.8
        assert outcome.model_used == "deepseek-chat"

    async def test_hallucinated_claims_fall_back_to_template(self, stub_structured_model: type) -> None:
        """LLM 全部论断编造证据：答案改为模板化且标记降级（引用仍可回溯）。"""
        model = stub_structured_model([_draft(("编造", ["ghost-doc"]))])
        outcome = await SynthesizerAgent(structured_llm=model).synthesize(_intent(), [_result("graph", "graph:A")])
        assert outcome.response.degraded is True
        assert outcome.response.citations[0].locator == "graph:A"
        assert outcome.dropped_claims == 1

    async def test_structured_failure_degrades(self, stub_structured_model: type) -> None:
        """结构化失败：模板化答案 + 可观测错误。"""
        model = stub_structured_model([ValueError("坏 JSON")])
        outcome = await SynthesizerAgent(structured_llm=model, max_retries=0).synthesize(
            _intent(), [_result("graph", "graph:A")]
        )
        assert outcome.response.degraded is True and outcome.error

    async def test_empty_results_returns_not_found(self) -> None:
        """无检索结果：返回标准「未找到相关信息」且不调用 LLM。"""
        outcome = await SynthesizerAgent(structured_llm=object()).synthesize(_intent(), [])
        assert outcome.response.answer == NOT_FOUND_ANSWER
        assert outcome.response.degraded is True and outcome.response.citations == []

    async def test_node_payload_shape(self, stub_structured_model: type) -> None:
        """LangGraph 节点：返回 answer / citations / degraded 增量。"""
        model = stub_structured_model([_draft(("结论", ["graph:A"]))])
        state = new_qa_state("CVE-2024-3400 影响哪些资产")
        state["intent"] = _intent()
        state["fused"] = [_result("graph", "graph:A")]
        payload = await SynthesizerAgent(structured_llm=model).__call__(state)
        assert payload["answer"] and payload["citations"]
        assert payload["degraded"] is False

    async def test_response_passes_contract_validation(self, stub_structured_model: type) -> None:
        """产出的 ``QAResponse`` 满足契约（非降级必须有引用）。"""
        model = stub_structured_model([_draft(("结论", ["graph:A"]))])
        outcome = await SynthesizerAgent(structured_llm=model).synthesize(_intent(), [_result("graph", "graph:A")])
        assert isinstance(outcome.response, QAResponse)
        assert QAResponse.model_validate(outcome.response.model_dump()).answer


class TestFactory:
    """工厂开关。"""

    @pytest.mark.parametrize(
        ("overrides", "expected_tag"),
        [
            ({"degraded_mode": True}, "no-llm"),
            ({"llm_api_key": ""}, "no-llm"),
            ({"llm_api_key": "sk-x"}, "deepseek-chat"),
        ],
    )
    def test_build_synthesizer_switches(self, overrides: dict[str, Any], expected_tag: str) -> None:
        from aisec_intel.config import Settings
        from aisec_intel.qa.agents.synthesizer import build_synthesizer

        assert build_synthesizer(Settings(**overrides)).model_tag == expected_tag
