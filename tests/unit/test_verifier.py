"""Day7 Verifier Agent 测试（PROJECT_PLAN.md §5.6 ``enrich/agents/verifier.py``）。

覆盖四项交叉验证：URL 可达性（含降权）、CVSS 复算、来源可信度、Pydantic 二次校验，
以及置信度公式与复核状态流转（**全部离线**，URL 用 ``httpx.MockTransport``）。
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.agents.verifier import (
    AGENT_NAME,
    DEFAULT_TRUST,
    SOURCE_TRUST,
    VerifierAgent,
    compute_confidence,
    poc_strength_of,
    trust_score,
    verify_cvss,
    verify_severity,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import CVSSVector, Reference, UnifiedVuln

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体（默认 NVD+KEV 双源、CVSS 10.0）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS GlobalProtect command injection vulnerability.",
        "title": "PAN-OS Command Injection",
        "cwe_ids": ["CWE-77"],
        "severity": "CRITICAL",
        "cvss": [CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")],
        "sources": ["nvd", "kev"],
        "kev": True,
        "trace_ids": ["trace-nvd"],
        "references": [Reference(url="https://example.test/advisory", source="nvd")],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_state(**overrides: Any) -> Any:
    """构造富化状态（可覆盖漏洞事实）。"""
    state = new_state(overrides.pop("vuln", make_vuln()))
    state.update(overrides)  # type: ignore[typeddict-item]
    return state


class TestCvssRecompute:
    """交叉验证第 2 项：CVSS 复算。"""

    def test_matching_score_has_no_conflict(self) -> None:
        """源侧分数与公式复算一致 → 无冲突。"""
        conflicts, notes = verify_cvss(make_vuln())
        assert conflicts == [] and notes == []

    def test_mismatched_score_is_reported(self) -> None:
        """源侧分数被篡改 / 口径不同 → 记冲突（含两个数值）。"""
        vuln = make_vuln(cvss=[CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=5.0, severity="MEDIUM")])
        conflicts, _ = verify_cvss(vuln)
        assert len(conflicts) == 1
        assert "复算不一致" in conflicts[0] and "5.0" in conflicts[0]

    def test_invalid_vector_is_conflict(self) -> None:
        """向量串非法 → 记冲突（无法复算）。"""
        vuln = make_vuln(cvss=[CVSSVector(version="3.1", vector="not-a-vector", base_score=9.0, severity="CRITICAL")])
        conflicts, _ = verify_cvss(vuln)
        assert "无法解析" in conflicts[0]

    def test_v4_is_skipped_with_note(self) -> None:
        """v4.0 不自行评分 → 跳过并留 note（不算冲突）。"""
        vuln = make_vuln(cvss=[CVSSVector(version="4.0", vector="CVSS:4.0/AV:N", base_score=9.3, severity="CRITICAL")])
        conflicts, notes = verify_cvss(vuln)
        assert conflicts == [] and "v4.0" in notes[0]

    def test_severity_consistency(self) -> None:
        """``severity`` 与向量推导不一致 → 记冲突。"""
        assert verify_severity(make_vuln()) == []
        assert verify_severity(make_vuln(severity="LOW")) != []


class TestTrustAndStrength:
    """交叉验证第 3 项：来源可信度；以及 PoC 强度。"""

    def test_trust_score_weights_sources(self) -> None:
        """白名单来源取加权平均，未登记来源用默认值。"""
        assert trust_score(["nvd"]) == SOURCE_TRUST["nvd"]
        assert trust_score(["nvd", "ghsa"]) == pytest.approx((1.0 + 0.9) / 2)
        assert trust_score(["unknown"]) == DEFAULT_TRUST
        assert trust_score([]) == 0.0

    def test_poc_strength_ignores_search_entries(self) -> None:
        """检索入口候选（``maturity=none``）不计入 PoC 强度。"""
        search_entry = ExploitRecord(source="exploitdb-search", url="https://x.test/s", maturity="none")
        poc = ExploitRecord(source="github", url="https://x.test/a", maturity="poc")
        assert poc_strength_of([search_entry]) == 0.0
        assert poc_strength_of([poc]) == 0.5
        assert poc_strength_of([poc, search_entry, poc.model_copy(update={"url": "https://x.test/b"})]) == 1.0


class TestConfidenceFormula:
    """置信度公式（纯函数）。"""

    def test_all_components_present(self) -> None:
        """四分量齐全时按权重加权。"""
        value = compute_confidence(
            source_trust=1.0, poc_strength=1.0, paper_strength=1.0, reachability=1.0, conflicts=[]
        )
        assert value == 1.0

    def test_missing_reachability_renormalizes(self) -> None:
        """未做可达性检查时按剩余权重归一化（不得当作满分）。"""
        with_check = compute_confidence(
            source_trust=0.5, poc_strength=0.0, paper_strength=0.0, reachability=0.0, conflicts=[]
        )
        without = compute_confidence(
            source_trust=0.5, poc_strength=0.0, paper_strength=0.0, reachability=None, conflicts=[]
        )
        assert without > with_check  # 未知优于「已确认失败」
        # 仅剩 source_trust 分量时按剩余权重归一化：0.5 * (0.40 / 0.80) = 0.25
        assert without == pytest.approx(0.25)

    def test_conflicts_penalize(self) -> None:
        """每条冲突扣 0.1，上限 0.4。"""
        base = compute_confidence(
            source_trust=1.0, poc_strength=1.0, paper_strength=1.0, reachability=1.0, conflicts=[]
        )
        one = compute_confidence(
            source_trust=1.0, poc_strength=1.0, paper_strength=1.0, reachability=1.0, conflicts=["c"]
        )
        many = compute_confidence(
            source_trust=1.0,
            poc_strength=1.0,
            paper_strength=1.0,
            reachability=1.0,
            conflicts=["a", "b", "c", "d", "e"],
        )
        assert base - one == pytest.approx(0.1)
        assert base - many == pytest.approx(0.4)


class TestVerifierAgent:
    """节点行为：URL 降权、复核状态、二次校验。"""

    async def test_auto_pass_when_confident(self) -> None:
        """来源可信 + 有已验证 PoC + 无可达性检查（离线）→ 自动通过并产出实体。"""
        state = make_state(
            vuln=make_vuln(epss_score=0.97),
            exploits=[
                ExploitRecord(
                    source="nuclei", url="https://example.test/n", maturity="poc", verified=True, reliability=0.8
                ),
                ExploitRecord(source="github", url="https://example.test/g", maturity="poc", reliability=0.6),
            ],
            related_papers=[PaperVulnLink(paper_id="2404.1", vuln_id="CVE-2024-3400", confidence=0.8)],
        )
        result = await VerifierAgent(check_urls=False)(state)

        assert result["confidence"] > 0.7
        enriched = result["enriched_vuln"]
        assert enriched is not None
        assert enriched.review_status == "auto_pass"
        assert enriched.confidence == result["confidence"]
        assert enriched.risk_level == "critical"
        assert enriched.risk_score >= 85  # CVSS 10 + KEV + 2 条 PoC + EPSS 0.97
        assert enriched.risk_breakdown["cvss"] == 45.0
        assert [step.agent for step in enriched.agent_trace] == [AGENT_NAME]
        assert result["verification"].conflicts == []
        assert result["verification"].notes  # 记录「未执行可达性检查」

    async def test_unreachable_poc_is_downgraded(self, mock_router: Any, mock_http: HttpClient) -> None:
        """URL 不可达的 PoC 记录被降权（reliability × 0.5）并计入可达性比例。"""
        mock_router.always("https://example.test/bad", status_code=404, text="gone")
        mock_router.always("https://example.test/good", status_code=200, text="ok")
        state = make_state(
            exploits=[
                ExploitRecord(source="github", url="https://example.test/good", maturity="poc", reliability=0.6),
                ExploitRecord(source="github", url="https://example.test/bad", maturity="poc", reliability=0.6),
            ]
        )
        result = await VerifierAgent(http=mock_http)(state)

        downgraded = [record for record in result["exploits"] if record.url.endswith("/bad")][0]
        assert downgraded.reliability == pytest.approx(0.3)
        assert downgraded.verified is False
        assert result["verification"].checked_urls >= 2
        assert "可达性" in result["verification"].notes[0]

    async def test_low_confidence_marks_needs_human(self) -> None:
        """置信度不足 → ``needs_human``（供图的回流条件边判断）。"""
        state = make_state(vuln=make_vuln(sources=["unknown-source"], cvss=[], severity=None), exploits=[])
        result = await VerifierAgent(check_urls=False)(state)

        assert result["confidence"] < 0.7
        assert result["enriched_vuln"] is not None
        assert result["enriched_vuln"].review_status == "needs_human"

    async def test_conflicts_mark_revised(self) -> None:
        """有冲突但置信度达标 → ``revised``，冲突写入 ``review_notes``。"""
        state = make_state(
            vuln=make_vuln(
                cvss=[CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=5.0, severity="CRITICAL")]
            ),
            exploits=[
                ExploitRecord(
                    source="nuclei",
                    url="https://example.test/n",
                    maturity="functional",
                    verified=True,
                    reliability=0.9,
                ),
                ExploitRecord(
                    source="nuclei",
                    url="https://example.test/n2",
                    maturity="poc",
                    verified=True,
                    reliability=0.8,
                ),
            ],
            related_papers=[PaperVulnLink(paper_id="2404.1", vuln_id="CVE-2024-3400", confidence=0.8)],
        )
        result = await VerifierAgent(check_urls=False)(state)

        assert result["verification"].conflicts  # CVSS 复算不一致
        enriched = result["enriched_vuln"]
        assert enriched is not None and enriched.review_status == "revised"
        assert any("复算不一致" in note for note in enriched.review_notes)

    async def test_second_validation_failure_yields_no_output(self, monkeypatch: Any) -> None:
        """Pydantic 二次校验失败 → **不产出** EnrichedVuln（不写脏数据）并记错误。"""
        monkeypatch.setattr(
            "aisec_intel.enrich.agents.verifier.score_risk",
            lambda *args, **kwargs: SimpleNamespace(score=150.0, level="critical", breakdown={}),
        )
        result = await VerifierAgent(check_urls=False)(make_state())

        assert result["enriched_vuln"] is None
        assert any("二次校验失败" in error for error in result["errors"])

    async def test_urls_capped_by_max_checks(self, mock_router: Any, mock_http: HttpClient) -> None:
        """可达性检查数量受 ``max_url_checks`` 限制。"""
        for index in range(5):
            mock_router.always(f"https://example.test/{index}", status_code=200, text="ok")
        state = make_state(
            exploits=[
                ExploitRecord(source="github", url=f"https://example.test/{index}", maturity="poc")
                for index in range(5)
            ]
        )
        result = await VerifierAgent(http=mock_http, max_url_checks=2)(state)
        assert result["verification"].checked_urls == 2
