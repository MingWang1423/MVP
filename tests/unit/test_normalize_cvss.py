"""Day4 归一化层：CVSS 解析与评分测试（PROJECT_PLAN.md §2 / §5.3）。

验证 FIRST 官方公式：v3.1 的 Log4Shell（10.0）与 9.8 样例、v2 的 Shellshock（10.0），
以及严重度阈值、v4 需源侧给分与容错抽取。
"""

from __future__ import annotations

import pytest

from aisec_intel.models.unified_vuln import CVSSVector
from aisec_intel.normalize.cvss import (
    detect_version,
    extract_cvss_vectors,
    parse_cvss_vector,
    parse_vector_metrics,
    score_v2,
    score_v3,
    severity_from_score,
)

V31_LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
V31_NINE_EIGHT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_LOW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2_SHELLSHOCK = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class TestVersionDetection:
    """版本识别与向量解析。"""

    @pytest.mark.parametrize(
        ("vector", "expected"),
        [(V31_LOG4SHELL, "3.1"), (V30, "3.0"), (V2_SHELLSHOCK, "2.0"), (V4, "4.0")],
    )
    def test_detect_version(self, vector: str, expected: str) -> None:
        """按前缀 / 指标识别版本。"""
        assert detect_version(vector) == expected

    def test_parse_metrics(self) -> None:
        """指标解析出 ``PREFIX`` 与各指标键。"""
        metrics = parse_vector_metrics(V31_LOG4SHELL)
        assert metrics["PREFIX"] == "CVSS:3.1"
        assert metrics["AV"] == "N"
        assert metrics["S"] == "C"

    def test_unknown_vector(self) -> None:
        """无法识别的向量返回 ``None``。"""
        assert detect_version("not-a-vector") is None


class TestSeverity:
    """严重度阈值映射。"""

    @pytest.mark.parametrize(
        ("version", "score", "expected"),
        [
            ("3.1", 0.0, "NONE"),
            ("3.1", 3.9, "LOW"),
            ("3.1", 4.0, "MEDIUM"),
            ("3.1", 6.9, "MEDIUM"),
            ("3.1", 7.0, "HIGH"),
            ("3.1", 8.9, "HIGH"),
            ("3.1", 9.0, "CRITICAL"),
            ("3.1", 10.0, "CRITICAL"),
            ("2.0", 0.0, "LOW"),
            ("2.0", 6.9, "MEDIUM"),
            ("2.0", 7.0, "HIGH"),
        ],
    )
    def test_thresholds(self, version: str, score: float, expected: str) -> None:
        """按版本阈值映射（v2 无 NONE / CRITICAL）。"""
        assert severity_from_score(version, score) == expected

    def test_invalid_inputs(self) -> None:
        """版本不支持或分数越界时报错。"""
        with pytest.raises(ValueError, match="不支持"):
            severity_from_score("9.9", 5.0)
        with pytest.raises(ValueError, match="越界"):
            severity_from_score("3.1", 11.0)


class TestV3Scoring:
    """CVSS v3.x 官方公式回归。"""

    def test_log4shell_is_ten(self) -> None:
        """Log4Shell（S:C，全高影响）= 10.0。"""
        assert score_v3(V31_LOG4SHELL) == pytest.approx(10.0)

    def test_scope_unchanged_high_is_nine_eight(self) -> None:
        """S:U 全高影响 = 9.8。"""
        assert score_v3(V31_NINE_EIGHT) == pytest.approx(9.8)

    def test_scope_unchanged_low_confidentiality(self) -> None:
        """仅 C:L = 5.3。"""
        assert score_v3(V31_LOW) == pytest.approx(5.3)

    def test_v30_vector_supported(self) -> None:
        """v3.0 向量同样可算（与 v3.1 同分）。"""
        assert score_v3(V30) == pytest.approx(9.8)

    def test_missing_metric_raises(self) -> None:
        """缺少必需指标时报错。"""
        with pytest.raises(ValueError, match="缺少指标"):
            score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_invalid_metric_value_raises(self) -> None:
        """指标取值非法时报错。"""
        with pytest.raises(ValueError, match="取值非法"):
            score_v3("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestV2Scoring:
    """CVSS v2 官方公式回归。"""

    def test_shellshock_is_ten(self) -> None:
        """Shellshock（全高影响）= 10.0。"""
        assert score_v2(V2_SHELLSHOCK) == pytest.approx(10.0)

    def test_missing_authentication_metric_raises(self) -> None:
        """v2 缺少 ``Au`` 时报错。"""
        with pytest.raises(ValueError, match="缺少指标"):
            score_v2("AV:N/AC:L/C:C/I:C/A:C")


class TestParseCvssVector:
    """向量 → 契约模型。"""

    def test_computes_score_when_absent(self) -> None:
        """未提供 ``base_score`` 时自行计算（v3.1）。"""
        parsed = parse_cvss_vector(V31_LOG4SHELL)
        assert isinstance(parsed, CVSSVector)
        assert parsed.version == "3.1"
        assert parsed.base_score == 10.0
        assert parsed.severity == "CRITICAL"

    def test_prefers_provided_score(self) -> None:
        """源侧提供的分数优先（避免口径差异）。"""
        parsed = parse_cvss_vector(V31_NINE_EIGHT, base_score=8.8)
        assert parsed.base_score == 8.8
        assert parsed.severity == "HIGH"

    def test_v4_requires_provided_score(self) -> None:
        """v4.0 需源侧给分（本层不实现 MacroVector 查表）。"""
        with pytest.raises(ValueError, match="base_score"):
            parse_cvss_vector(V4)
        assert parse_cvss_vector(V4, base_score=9.3).severity == "CRITICAL"


class TestExtractCvssVectors:
    """从源侧载荷抽取向量。"""

    def test_nvd_metrics(self) -> None:
        """NVD ``metrics`` 中同时抽 v2 与 v3.1（按版本升序）。"""
        payload = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"vectorString": V31_LOG4SHELL, "baseScore": 10.0}}],
                "cvssMetricV2": [{"cvssData": {"vectorString": V2_SHELLSHOCK, "baseScore": 10.0}}],
            }
        }
        assert [item.version for item in extract_cvss_vectors(payload)] == ["2.0", "3.1"]

    def test_nvd_wrapped_entry(self) -> None:
        """NVD ``{"cve": {...}}`` 包装形态：从 ``cve.metrics`` 抽取（回归用例）。"""
        payload = {
            "cve": {
                "id": "CVE-2024-3400",
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"vectorString": V31_LOG4SHELL, "baseScore": 10.0}}]
                },
            }
        }
        vectors = extract_cvss_vectors(payload)
        assert len(vectors) == 1
        assert vectors[0].base_score == 10.0
        assert vectors[0].severity == "CRITICAL"

    def test_ghsa_cvss(self) -> None:
        """GHSA ``cvss`` 对象抽取。"""
        vectors = extract_cvss_vectors({"cvss": {"vectorString": V31_NINE_EIGHT, "score": 9.8}})
        assert len(vectors) == 1
        assert vectors[0].base_score == 9.8

    def test_osv_severity(self) -> None:
        """OSV ``severity[].score`` 抽取（无分数时自行计算）。"""
        assert extract_cvss_vectors({"severity": [{"type": "CVSS_V3", "score": V31_NINE_EIGHT}]})[0].base_score == 9.8

    def test_bad_vector_is_ignored(self) -> None:
        """脏数据被忽略（采集不得因脏数据中断）。"""
        assert extract_cvss_vectors({"cvss": {"vectorString": "garbage"}}) == []
        assert extract_cvss_vectors({}) == []
