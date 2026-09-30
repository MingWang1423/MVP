"""Day7 风险评分测试（PROJECT_PLAN.md §5.6 ``enrich/agents/risk_scorer.py``）。

§6.2 P5 验收 ④ 要求：``risk_scorer`` 公式**边界全覆盖**（CVSS=0 / EPSS=0 / KEV=true）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.enrich.agents.risk_scorer import (
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    WEIGHT_CVSS,
    WEIGHT_EPSS,
    WEIGHT_KEV,
    WEIGHT_POC,
    risk_level,
    score_risk,
)
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.unified_vuln import CVSSVector, UnifiedVuln

CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体（默认无 CVSS / 无 EPSS / 非 KEV）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "description": "PAN-OS command injection.",
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def cvss(score: float, severity: str = "CRITICAL") -> CVSSVector:
    """构造一个 CVSS 向量。"""
    return CVSSVector(version="3.1", vector=CVSS_VECTOR, base_score=score, severity=severity)  # type: ignore[arg-type]


def poc(maturity: str = "poc", url: str = "https://x.test/a") -> ExploitRecord:
    """构造一条 PoC 记录。"""
    return ExploitRecord(source="github", url=url, maturity=maturity, reliability=0.6)  # type: ignore[arg-type]


class TestBoundaries:
    """公式边界（P5 验收 ④）。"""

    def test_all_factors_zero(self) -> None:
        """CVSS=0 / EPSS=0 / 非 KEV / 无 PoC → 0 分、``low``。"""
        result = score_risk(make_vuln(cvss=[cvss(0.0, "NONE")], epss_score=0.0, kev=False), [])
        assert result.score == 0.0
        assert result.level == "low"
        assert result.breakdown == {"cvss": 0.0, "epss": 0.0, "kev": 0.0, "poc": 0.0}

    def test_cvss_only(self) -> None:
        """仅 CVSS 10.0 → 45 分（权重 0.45）→ ``medium``。"""
        result = score_risk(make_vuln(cvss=[cvss(10.0)]), [])
        assert result.score == pytest.approx(WEIGHT_CVSS * 100)
        assert result.level == "medium"  # 45 ≥ 40 但 < 70

    def test_kev_flag_contributes(self) -> None:
        """KEV=true 且其它为 0 → 15 分（走「KEV 为真」边界）。"""
        result = score_risk(make_vuln(kev=True), [])
        assert result.score == pytest.approx(WEIGHT_KEV * 100)
        assert result.breakdown["kev"] == 15.0

    def test_epss_zero_boundary(self) -> None:
        """EPSS=0.0 与 ``None`` 等价（均不加分）。"""
        zero = score_risk(make_vuln(epss_score=0.0), [])
        missing = score_risk(make_vuln(epss_score=None), [])
        assert zero.score == missing.score == 0.0

    def test_epss_full(self) -> None:
        """EPSS=1.0 → 满分 EPSS 权重。"""
        result = score_risk(make_vuln(epss_score=1.0), [])
        assert result.breakdown["epss"] == pytest.approx(WEIGHT_EPSS * 100)

    def test_max_score_capped_at_100(self) -> None:
        """所有因子拉满 → 上限 100（权重之和为 1）。"""
        result = score_risk(
            make_vuln(cvss=[cvss(10.0)], epss_score=1.0, kev=True),
            [poc(), poc(url="https://x.test/b"), poc(url="https://x.test/c")],
        )
        assert result.score == 100.0
        assert result.breakdown["poc"] == pytest.approx(WEIGHT_POC * 100)


class TestPocFactor:
    """PoC 因子：只认「可执行证据」，检索入口候选不计分。"""

    def test_search_entry_candidates_do_not_count(self) -> None:
        """``maturity=none``（检索入口）不加分。"""
        result = score_risk(make_vuln(cvss=[cvss(10.0)]), [poc(maturity="none")])
        assert result.breakdown["poc"] == 0.0

    def test_saturates_at_two_records(self) -> None:
        """2 条可执行 PoC 即饱和（再多不涨分）。"""
        one = score_risk(make_vuln(cvss=[cvss(10.0)]), [poc()])
        two = score_risk(make_vuln(cvss=[cvss(10.0)]), [poc(), poc(url="https://x.test/b")])
        three = score_risk(
            make_vuln(cvss=[cvss(10.0)]),
            [poc(), poc(url="https://x.test/b"), poc(url="https://x.test/c")],
        )
        assert one.breakdown["poc"] == pytest.approx(WEIGHT_POC * 50)
        assert two.breakdown["poc"] == three.breakdown["poc"] == pytest.approx(WEIGHT_POC * 100)

    def test_functional_and_high_count(self) -> None:
        """``functional`` / ``high`` 同样计入。"""
        result = score_risk(make_vuln(), [poc(maturity="functional"), poc(maturity="high", url="https://x.test/b")])
        assert result.breakdown["poc"] == pytest.approx(WEIGHT_POC * 100)


class TestRiskLevelMapping:
    """级别阈值（含边界值）。"""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, "low"),
            (39.99, "low"),
            (MEDIUM_THRESHOLD, "medium"),
            (69.99, "medium"),
            (HIGH_THRESHOLD, "high"),
            (84.99, "high"),
            (CRITICAL_THRESHOLD, "critical"),
            (100.0, "critical"),
        ],
    )
    def test_thresholds(self, score: float, expected: str) -> None:
        """按阈值映射（边界含等号）。"""
        assert risk_level(score) == expected

    def test_breakdown_is_deterministic(self) -> None:
        """相同输入必得相同输出（确定性公式，可复现）。"""
        vuln = make_vuln(cvss=[cvss(9.8, "CRITICAL")], epss_score=0.42, kev=True)
        first = score_risk(vuln, [poc()])
        second = score_risk(vuln, [poc()])
        assert first == second
