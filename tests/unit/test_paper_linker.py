"""Day7 PaperLinker Agent 测试（PROJECT_PLAN.md §5.6 ``enrich/agents/paper_linker.py``）。

**全部离线**：论文检索用桩函数、LLM 用 ``conftest.StubStructuredModel``（响应队列可注入异常）。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.enrich.agents.paper_linker import (
    AGENT_NAME,
    DEGRADED_CONFIDENCE_CAP,
    MODEL_TAG_DEGRADED,
    PaperLinkerAgent,
    build_link,
    degraded_confidence,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.enrich.tools.search_tools import paper_search_keywords
from aisec_intel.models.agent_io import PaperRelevance, PaperRelevanceBatch
from aisec_intel.models.base import utc_now
from aisec_intel.models.paper import Paper
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.repositories.paper_repo import PaperHit


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体（PAN-OS 命令注入）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "title": "PAN-OS Command Injection",
        "description": "PAN-OS GlobalProtect command injection allows remote code execution via crafted requests.",
        "cwe_ids": ["CWE-77"],
        "trace_ids": ["trace-nvd"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_hit(paper_id: str, *, matched: list[str] | None = None, abstract: str = "abstract text") -> PaperHit:
    """构造一条检索命中。"""
    paper = Paper(
        paper_id=paper_id,
        source="arxiv",
        title=f"Paper {paper_id}",
        abstract=abstract,
        url=f"https://arxiv.org/abs/{paper_id}",
        published_at=datetime(2024, 5, 1, tzinfo=UTC),
    )
    hits = matched or ["x"]
    return PaperHit(paper=paper, score=len(hits), matched=hits)


class TestKeywords:
    """关键词生成（纯函数）。"""

    def test_cwe_and_title_tokens_first(self) -> None:
        """CWE 编号优先，其后是标题与描述实词。"""
        keywords = paper_search_keywords(
            cwe_ids=["CWE-77"], title="PAN-OS Command Injection", description="remote code execution"
        )
        assert keywords[0] == "cwe-77"
        assert "pan-os" in keywords and "command" in keywords
        assert len(keywords) <= 6

    def test_caps_and_ignores_empty(self) -> None:
        """关键词数量受上限约束；空输入返回空列表（过短词元被过滤）。"""
        assert paper_search_keywords(cwe_ids=[], title=None, description="") == []
        keywords = paper_search_keywords(
            cwe_ids=["CWE-1"], title="alpha beta gamma", description="delta epsilon", max_keywords=3
        )
        assert keywords == ["cwe-1", "alpha", "beta"]


class TestDegradedConfidence:
    """降级置信度折算（纯函数）。"""

    def test_ratio_scales_but_capped(self) -> None:
        """命中越多置信度越高，但不超过上限。"""
        low = degraded_confidence(make_hit("1", matched=["a"]), max_keywords=6)
        high = degraded_confidence(make_hit("2", matched=["a", "b", "c", "d", "e", "f"]), max_keywords=6)
        assert low == pytest.approx(0.35)
        assert high == pytest.approx(DEGRADED_CONFIDENCE_CAP)


class TestDegradedPath:
    """无 LLM 时的降级路径（保证离线链路可用）。"""

    async def test_links_from_retrieval_scores(self) -> None:
        """检索命中即产出 ``mentions`` 关联，证据含 trace_id 与论文链接。"""

        async def search(keywords: Any, limit: int) -> list[PaperHit]:
            assert "cwe-77" in keywords
            return [make_hit("2404.1", matched=["cwe-77", "pan-os"])]

        result = await PaperLinkerAgent(search=search)(new_state(make_vuln()))

        assert len(result["related_papers"]) == 1
        link = result["related_papers"][0]
        assert link.paper_id == "2404.1"
        assert link.vuln_id == "CVE-2024-3400"
        assert link.relation == "mentions"
        assert link.confidence <= DEGRADED_CONFIDENCE_CAP
        assert link.evidence_refs[0] == "trace-nvd"
        assert result["agent_steps"][0].agent == AGENT_NAME
        assert result["agent_steps"][0].model_used == MODEL_TAG_DEGRADED
        assert result["errors"] == []

    async def test_search_failure_is_isolated(self) -> None:
        """检索异常 → 空关联 + 错误留痕（不抛出）。"""

        async def search(keywords: Any, limit: int) -> list[PaperHit]:
            raise RuntimeError("db down")

        result = await PaperLinkerAgent(search=search)(new_state(make_vuln()))
        assert result["related_papers"] == []
        assert "论文检索失败" in result["errors"][0]
        assert result["agent_steps"][0].error is not None

    async def test_empty_keywords_skips_search(self) -> None:
        """关键词为空时不检索，并记一条说明。"""
        calls = 0

        async def search(keywords: Any, limit: int) -> list[PaperHit]:
            nonlocal calls
            calls += 1
            return []

        result = await PaperLinkerAgent(search=search)(new_state(make_vuln(title="", description="", cwe_ids=[])))
        assert calls == 0
        assert "关键词为空" in result["errors"][0]


class TestLlmPath:
    """LLM 相关性判定路径（桩模型）。"""

    async def test_filters_irrelevant_and_low_confidence(self, stub_structured_model: Any) -> None:
        """仅保留 ``relevant=True`` 且置信度达阈值的候选。"""

        async def search(keywords: Any, limit: int) -> list[PaperHit]:
            return [make_hit("p1"), make_hit("p2"), make_hit("p3")]

        stub = stub_structured_model(
            [
                PaperRelevanceBatch(
                    items=[
                        PaperRelevance(
                            paper_id="p1",
                            relevant=True,
                            relation="proposes-attack",
                            confidence=0.85,
                            evidence="quote-1",
                        ),
                        PaperRelevance(paper_id="p2", relevant=False, confidence=0.9),
                        PaperRelevance(paper_id="p3", relevant=True, confidence=0.2),
                        PaperRelevance(paper_id="p9", relevant=True, confidence=0.9),  # 不在候选内 → 丢弃
                    ]
                )
            ]
        )
        agent = PaperLinkerAgent(search=search, structured_llm=stub, model_tag="deepseek-chat")
        result = await agent(new_state(make_vuln()))

        assert [link.paper_id for link in result["related_papers"]] == ["p1"]
        link = result["related_papers"][0]
        assert link.relation == "proposes-attack"
        assert link.confidence == 0.85
        assert link.evidence == "quote-1"
        assert result["agent_steps"][0].model_used == "deepseek-chat"
        assert stub.call_count == 1

    async def test_prompt_contains_vulnerability_and_candidates(self, stub_structured_model: Any) -> None:
        """提示中包含漏洞事实与候选论文（便于人工复核 Prompt 质量）。"""

        async def search(keywords: Any, limit: int) -> list[PaperHit]:
            return [make_hit("p1")]

        stub = stub_structured_model([PaperRelevanceBatch(items=[])])
        await PaperLinkerAgent(search=search, structured_llm=stub)(new_state(make_vuln()))
        prompt_text = " ".join(str(message.content) for message in stub.calls[0])
        assert "CVE-2024-3400" in prompt_text
        assert "p1" in prompt_text
        assert "cwe-77" in prompt_text.lower()

    async def test_validation_failure_degrades(self, stub_structured_model: Any) -> None:
        """结构化输出失败 → 重试后降级为检索折算，并记录错误。"""

        async def search(keywords: Any, limit: int) -> list[PaperHit]:
            return [make_hit("p1", matched=["a", "b"])]

        stub = stub_structured_model([ValueError("bad json"), ValueError("bad json"), ValueError("bad json")])
        result = await PaperLinkerAgent(search=search, structured_llm=stub)(new_state(make_vuln()))

        assert len(result["related_papers"]) == 1  # 降级仍产出关联
        assert any("降级为检索折算" in error for error in result["errors"])
        assert stub.call_count == 3  # 首次 + 2 次重试


class TestBuildLink:
    """关联边构造。"""

    def test_relation_and_refs(self) -> None:
        """字段映射正确（``evidence_refs`` 统一转字符串）。"""
        link = build_link(
            paper_id="p1",
            vuln_id="CVE-2024-3400",
            confidence=0.7,
            relation="evaluates",
            evidence=None,
            evidence_refs=["trace-1", "https://example.test"],
        )
        assert (link.paper_id, link.vuln_id, link.relation, link.confidence) == (
            "p1",
            "CVE-2024-3400",
            "evaluates",
            0.7,
        )
        assert link.evidence_refs == ["trace-1", "https://example.test"]
