"""Day4 归一化层：CVSS 解析与评分测试（PROJECT_PLAN.md §2 / §5.3）。

验证 FIRST 官方公式：v3.1 的 Log4Shell（10.0）与 9.8 样例、v2 的 Shellshock（10.0），
以及严重度阈值、v4 需源侧给分与容错抽取。

Note:
    Day12 任务 2 合并：原 37 个用例（含 15 个 parametrize 展开）压到 8 个，
    改用「同函数多组输入循环」，公式口径与边界断言不变。
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
    severity_rank_max,
)

V31_LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
V31_NINE_EIGHT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_LOW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V2_SHELLSHOCK = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class TestVersionAndSeverity:
    """版本识别、指标解析、严重度阈值与「取最高」合并。"""

    def test_version_and_metrics(self) -> None:
        """按前缀 / 指标识别版本；指标解析出 ``PREFIX`` 与各键；无法识别返回 ``None``。"""
        for vector, expected in (
            (V31_LOG4SHELL, "3.1"),
            (V30, "3.0"),
            (V2_SHELLSHOCK, "2.0"),
            (V4, "4.0"),
        ):
            assert detect_version(vector) == expected, vector
        metrics = parse_vector_metrics(V31_LOG4SHELL)
        assert metrics["PREFIX"] == "CVSS:3.1" and metrics["AV"] == "N" and metrics["S"] == "C"
        assert detect_version("not-a-vector") is None

    def test_severity_thresholds(self) -> None:
        """按版本阈值映射（v2 无 NONE / CRITICAL）；非法版本与越界分数报错。"""
        cases: list[tuple[str, float, str]] = [
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
        ]
        for version, score, expected in cases:
            assert severity_from_score(version, score) == expected, (version, score)
        with pytest.raises(ValueError, match="不支持"):
            severity_from_score("9.9", 5.0)
        with pytest.raises(ValueError, match="越界"):
            severity_from_score("3.1", 11.0)

    def test_severity_rank_max(self) -> None:
        """「取最高」合并：全空返回 ``None``、忽略空值、与输入顺序无关。"""
        assert severity_rank_max([]) is None
        assert severity_rank_max([None, None]) is None
        assert severity_rank_max([None, "LOW", "CRITICAL", "MEDIUM"]) == "CRITICAL"
        assert severity_rank_max(["NONE", "LOW"]) == "LOW"
        values = ["MEDIUM", None, "HIGH", "LOW"]
        assert severity_rank_max(values) == severity_rank_max(list(reversed(values))) == "HIGH"


class TestScoring:
    """CVSS v3.x / v2 官方公式回归与非法输入。"""

    def test_v3_scoring(self) -> None:
        """v3.1 Log4Shell=10.0、9.8 样例、低危样例、v3.0 样例；缺指标 / 非法取值报错。"""
        assert score_v3(V31_LOG4SHELL) == pytest.approx(10.0)
        assert score_v3(V31_NINE_EIGHT) == pytest.approx(9.8)
        assert score_v3(V30) == pytest.approx(9.8)
        low = score_v3(V31_LOW)
        assert low == pytest.approx(5.3) and severity_from_score("3.1", low) == "MEDIUM"
        with pytest.raises(ValueError, match="缺少指标"):
            score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
        with pytest.raises(ValueError, match="取值非法"):
            score_v3("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_v2_scoring(self) -> None:
        """Shellshock（全高影响）= 10.0；缺少 ``Au`` 报错。"""
        assert score_v2(V2_SHELLSHOCK) == pytest.approx(10.0)
        with pytest.raises(ValueError, match="缺少指标"):
            score_v2("AV:N/AC:L/C:C/I:C/A:C")


class TestParseCvssVector:
    """向量 → 契约模型。"""

    def test_parse_cvss_vector(self) -> None:
        """无分数时自行计算；源侧分数优先；v4 必须由源侧给分。"""
        computed = parse_cvss_vector(V31_LOG4SHELL)
        assert isinstance(computed, CVSSVector)
        assert computed.version == "3.1" and computed.base_score == 10.0
        assert computed.severity == "CRITICAL"
        provided = parse_cvss_vector(V31_NINE_EIGHT, base_score=8.8)
        assert provided.base_score == 8.8 and provided.severity == "HIGH"
        with pytest.raises(ValueError, match="base_score"):
            parse_cvss_vector(V4)
        assert parse_cvss_vector(V4, base_score=9.3).severity == "CRITICAL"


class TestExtractCvssVectors:
    """从源侧载荷抽取向量（NVD / GHSA / OSV / 脏数据）。"""

    def test_extract_from_sources(self) -> None:
        """NVD ``metrics``（含 ``{"cve": ...}`` 包装）、GHSA ``cvss``、OSV ``severity`` 均可抽取。"""
        nvd = extract_cvss_vectors(
            {
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"vectorString": V31_LOG4SHELL, "baseScore": 10.0}}],
                    "cvssMetricV2": [{"cvssData": {"vectorString": V2_SHELLSHOCK, "baseScore": 10.0}}],
                }
            }
        )
        assert [item.version for item in nvd] == ["2.0", "3.1"]

        wrapped = extract_cvss_vectors(
            {
                "cve": {
                    "id": "CVE-2024-3400",
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"vectorString": V31_LOG4SHELL, "baseScore": 10.0}}
                        ]
                    },
                }
            }
        )
        assert len(wrapped) == 1 and wrapped[0].base_score == 10.0
        assert wrapped[0].severity == "CRITICAL"

        ghsa = extract_cvss_vectors({"cvss": {"vectorString": V31_NINE_EIGHT, "score": 9.8}})
        assert len(ghsa) == 1 and ghsa[0].base_score == 9.8
        osv = extract_cvss_vectors({"severity": [{"type": "CVSS_V3", "score": V31_NINE_EIGHT}]})
        assert osv[0].base_score == 9.8

    def test_bad_vector_is_ignored(self) -> None:
        """脏数据被忽略（采集不得因脏数据中断）。"""
        assert extract_cvss_vectors({"cvss": {"vectorString": "garbage"}}) == []
        assert extract_cvss_vectors({}) == []
