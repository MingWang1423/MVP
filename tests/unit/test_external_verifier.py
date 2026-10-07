"""Day25 阶段 2 任务 2.4：外部证据复核单元测试（``aisec_intel.qa.agents.verifier``）。

覆盖：可信度评分（源权重 / 多源佐证 / 权威链接 / 扣分项）、多源冲突裁决、
``verified`` 门槛与「只有 verified 才能提升为答案事实」的唯一通道、节点并入 ``fused``。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.models.base import utc_now
from aisec_intel.models.external_evidence import ExternalEvidence, ExternalVerification
from aisec_intel.qa.agents import verifier as vf
from aisec_intel.qa.state import QAState, QueryEntities, QueryIntent, RetrievalResult, new_qa_state

CVE = "CVE-2024-34359"


def _evidence(
    source_type: str = "ghsa",
    *,
    cve: str | None = CVE,
    url: str = "https://github.com/advisories/GHSA-56xg-wfcc-g829",
    facts: tuple[str, ...] = ("fixed_version",),
    snippet: str = "修复版本: 0.2.72",
    trust: float = 0.9,
) -> ExternalEvidence:
    """构造一条外部证据（测试夹具）。"""
    return ExternalEvidence(
        query=f"{CVE} 应升级到哪个版本",
        cve_id=cve,
        source_type=source_type,  # type: ignore[arg-type]
        source_name="GHSA-56xg-wfcc-g829" if source_type == "ghsa" else source_type.upper(),
        url=url,
        title="llama-cpp-python RCE",
        snippet=snippet,
        retrieved_at=utc_now(),
        trust_score=trust,
        facts=list(facts),  # type: ignore[arg-type]
    )


def _intent(cve: str = CVE) -> QueryIntent:
    """构造查询意图（带 CVE 实体）。"""
    return QueryIntent(
        query=f"{cve} 应升级到哪个版本",
        intent="remediation",
        entities=QueryEntities(cve_ids=[cve]),
        rewritten_query=cve,
        confidence=0.9,
    )


class TestScoring:
    """纯函数：可信度评分与权威链接判定。"""

    @pytest.mark.parametrize(
        ("source_type", "corroborated", "cve", "expected"),
        [
            ("ghsa", True, CVE, 0.93),
            ("ghsa", False, CVE, 0.73),
            ("nvd", False, CVE, 0.8),
            ("ghsa", False, "CVE-2024-3400", 0.48),
        ],
    )
    def test_score_matrix(self, source_type: str, corroborated: bool, cve: str, expected: float) -> None:
        """源权重 / 佐证加权 / 权威链接 / 不一致罚分（确定性可复算）。"""
        item = _evidence(source_type, cve=cve)
        assert vf.score_evidence(item, corroborated=corroborated, cve_ids=[CVE]) == pytest.approx(expected, abs=1e-3)

    def test_penalties_and_authority(self) -> None:
        """无事实扣分；非 ``https`` 链接拿不到权威加权。"""
        no_fact = _evidence(facts=(), url="http://example.test/x", snippet="普通描述")
        assert vf.score_evidence(no_fact, cve_ids=[CVE]) == pytest.approx(0.53, abs=1e-3)
        assert vf.is_authoritative_url("https://nvd.nist.gov/vuln/detail/CVE-2024-34359") is True
        assert vf.is_authoritative_url("http://nvd.nist.gov/x") is False
        assert vf.is_authoritative_url("https://blog.example.test/x") is False


class TestVerify:
    """纯函数：门槛判定、多源冲突裁决与提升通道。"""

    def test_accept_and_reject(self) -> None:
        """达标证据 ``verified=True``；低分证据被丢弃并给出原因。"""
        good = _evidence()
        weak = _evidence("osv", facts=(), url="http://example.test/x", snippet="无关描述")
        accepted, report = vf.verify_evidence([good, weak], cve_ids=[CVE], threshold=0.6)
        assert [item.locator for item in accepted] == [good.locator]
        assert report.accepted == 1 and report.rejected == 1
        assert report.verified_facts == ["fixed_version"] and report.reasons

    def test_mismatch_never_promoted(self) -> None:
        """CVE 与问题不一致时一律不提升（即使分数够）。"""
        foreign = _evidence(cve="CVE-2026-71379", url="https://nvd.nist.gov/vuln/detail/x")
        accepted, report = vf.verify_evidence([foreign], cve_ids=[CVE], threshold=0.3)
        assert accepted == [] and report.accepted == 0
        assert any("CVE 与问题不一致" in item for item in report.reasons)

    def test_multi_source_conflict_resolution(self) -> None:
        """同一事实多源冲突 → 取复核后 ``trust_score`` 最高者为权威，并记录冲突说明。"""
        osv = _evidence(
            "osv",
            trust=0.99,
            url="https://osv.dev/vulnerability/CVE-2024-34359",
            snippet="修复版本: 0.2.72（OSV 记载）",
        )
        ghsa = _evidence("ghsa", trust=0.5, snippet="修复版本: 0.2.72")
        accepted, report = vf.verify_evidence([osv, ghsa], cve_ids=[CVE])
        assert report.authoritative["fixed_version"] == ghsa.locator
        assert report.conflicts and "修复版本" in report.conflicts[0]
        assert {item.source_type for item in accepted} == {"osv", "ghsa"}

    def test_promote_only_verified(self) -> None:
        """``to_retrieval_results`` 只提升 ``verified=True`` 的条目（唯一通道）。"""
        good = _evidence().model_copy(update={"trust_score": 0.73, "verified": True})
        rejected = _evidence("osv").model_copy(update={"verified": False})
        results = vf.to_retrieval_results([good, rejected])
        assert len(results) == 1
        promoted = results[0]
        assert promoted.source == "external" and promoted.metadata["cve_id"] == CVE
        assert promoted.metadata[vf.UNTRUSTED_FLAG] is True
        assert "外部证据｜不可信内容" in promoted.content and "修复版本" in promoted.content

    def test_empty_input(self) -> None:
        """空输入返回空结果与空汇总。"""
        accepted, report = vf.verify_evidence([])
        assert accepted == [] and report == ExternalVerification()


class TestVerifierNode:
    """节点行为：并入 ``fused``（供引用）与复核汇总写入状态。"""

    async def test_node_merges_fused_and_writes_summary(self) -> None:
        """通过复核的证据被并入 ``fused``，并写入 ``external_verification``。"""
        local = RetrievalResult(source="graph", doc_id="graph:CVE-2024-34359", metadata={"cve_id": CVE})
        state: QAState = new_qa_state("CVE-2024-34359 应升级到哪个版本")
        state["intent"] = _intent()
        state["fused"] = [local]
        state["external_evidence"] = [_evidence()]
        payload = await vf.ExternalEvidenceVerifier(threshold=0.6)(state)

        assert payload["external_verification"].accepted == 1
        assert len(payload["fused"]) == 2 and payload["fused"][0] is local
        assert payload["fused"][1].source == "external"

    async def test_node_empty_evidence(self) -> None:
        """无外部证据时不改 ``fused``（只写空汇总）。"""
        payload = await vf.ExternalEvidenceVerifier()(new_qa_state("q"))
        assert payload["external_verification"] == ExternalVerification()
        assert "fused" not in payload

    def test_threshold_from_settings(self) -> None:
        """阈值可由配置注入。"""
        from aisec_intel.config import Settings

        agent = vf.build_external_verifier(Settings(llm_api_key="", qa_external_trust_threshold=0.8))
        assert agent.threshold == 0.8

    def test_apply_verification_marks_rejected(self) -> None:
        """``apply_verification`` 把未通过条目置 ``verified=False`` 并带上复核评分。"""
        item = _evidence()
        accepted, report = vf.verify_evidence([item], cve_ids=[CVE], threshold=0.9)
        restored = vf.apply_verification([item], accepted, report)
        assert accepted == [] and restored[0].verified is False
        assert restored[0].trust_score == pytest.approx(0.73, abs=1e-3)

    async def test_node_persists_verification(self, memory_engine: Any) -> None:
        """注入会话工厂时复核结论回写 ``external_evidence``（``verified`` / ``trust_score``）。"""
        from aisec_intel.storage.database import session_scope
        from aisec_intel.storage.repositories.external_evidence_repo import ExternalEvidenceRepository

        item = _evidence().model_copy(update={"content_hash": "hash-1"})
        async with session_scope(memory_engine) as session:
            await ExternalEvidenceRepository(session).upsert_many([item])

        state: QAState = new_qa_state("CVE-2024-34359 应升级到哪个版本")
        state["intent"] = _intent()
        state["fused"] = []
        state["external_evidence"] = [item]
        agent = vf.ExternalEvidenceVerifier(threshold=0.6, session_factory=lambda: session_scope(memory_engine))
        await agent(state)

        async with session_scope(memory_engine) as session:
            rows = await ExternalEvidenceRepository(session).list_by_cve(CVE)
        assert rows and rows[0].verified is True
        assert rows[0].trust_score == pytest.approx(0.73, abs=1e-3)

