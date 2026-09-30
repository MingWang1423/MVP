"""Day4 归一化层：CVE 字段抽取测试（PROJECT_PLAN.md §2 / §5.3）。

覆盖：编号规范化、正文抽取、跨源字段映射（NVD / OSV / GHSA / KEV / EPSS）、文本清洗。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.normalize.cve import (
    clean_text,
    extract_cve_fields,
    extract_cve_ids,
    find_aliases,
    is_cve_id,
    normalize_cve_id,
    parse_payload,
)


class TestNormalizeCveId:
    """CVE 编号规范化。"""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("CVE-2024-3400", "CVE-2024-3400"),
            (" cve-2024-3400 ", "CVE-2024-3400"),
            ("cve-1999-0001", "CVE-1999-0001"),
        ],
    )
    def test_valid_ids(self, raw: str, expected: str) -> None:
        """合法编号被规范化为大写。"""
        assert normalize_cve_id(raw) == expected

    @pytest.mark.parametrize("raw", ["", None, "CVE-24-3400", "GHSA-xxxx-yyyy-zzzz", "CVE-2024-", "not-a-cve"])
    def test_invalid_ids(self, raw: str | None) -> None:
        """非法编号返回 ``None``。"""
        assert normalize_cve_id(raw) is None
        assert is_cve_id(raw) is False

    def test_extract_from_text(self) -> None:
        """从正文抽取编号（去重、保持出现顺序、大写）。"""
        text = "Fixed cve-2024-3400 and CVE-2021-44228; CVE-2024-3400 again."
        assert extract_cve_ids(text) == ["CVE-2024-3400", "CVE-2021-44228"]

    def test_find_aliases(self) -> None:
        """抽取 GHSA / PYSEC 别名（不含 CVE）。"""
        aliases = find_aliases("See GHSA-2qrp-3j2c-6v3x and PYSEC-2024-115 and CVE-2024-28088.")
        assert "GHSA-2QRP-3J2C-6V3X" in aliases
        assert "PYSEC-2024-115" in aliases
        assert all(not alias.startswith("CVE-") for alias in aliases)


class TestCleanTextAndPayload:
    """文本清洗与 JSON 载荷解析。"""

    def test_strips_html_and_collapses_whitespace(self) -> None:
        """去标签 + 压缩空白。"""
        assert clean_text("<p>Hello   <b>world</b></p>\n\n  again") == "Hello world again"
        assert clean_text(None) == ""

    def test_parse_payload(self) -> None:
        """对象可解析，非对象 / 非法 JSON 返回 ``None``。"""
        assert parse_payload('{"a": 1}') == {"a": 1}
        assert parse_payload("[1, 2]") is None
        assert parse_payload("not json") is None


class TestExtractFields:
    """跨源字段抽取。"""

    def test_kev_entry(self, load_fixture: Callable[[str], Any]) -> None:
        """KEV 条目：主键为 cveID，``kev=True``，CWE 列表与参考链接可抽取。"""
        entry = load_fixture("kev_sample.json")["vulnerabilities"][0]
        fields = extract_cve_fields(json.dumps(entry), source="kev", fallback_id=entry["cveID"])
        assert fields.vuln_id == "CVE-2024-3400"
        assert fields.kev is True
        assert fields.published_at == datetime(2024, 4, 12, tzinfo=UTC)
        assert "CWE-77" in fields.cwe_ids
        assert fields.reference_urls

    def test_osv_entry(self, load_fixture: Callable[[str], Any]) -> None:
        """OSV 条目：主键为 OSV id，CVE 落入别名。"""
        entry = load_fixture("osv_sample.json")["vulns"][0]
        fields = extract_cve_fields(json.dumps(entry), source="osv")
        assert fields.vuln_id == "GHSA-3hjh-jh2g-v3gj"
        assert "CVE-2024-28088" in fields.aliases
        assert fields.modified_at == datetime(2024, 5, 1, 12, 0, tzinfo=UTC)

    def test_ghsa_entry(self, load_fixture: Callable[[str], Any]) -> None:
        """GHSA 节点：主键为 ghsaId，CVE 与 CWE 均可抽取。"""
        node = load_fixture("ghsa_graphql_sample.json")["data"]["securityAdvisories"]["nodes"][0]
        fields = extract_cve_fields(json.dumps(node), source="ghsa")
        assert fields.vuln_id == "GHSA-2qrp-3j2c-6v3x"
        assert "CVE-2024-28088" in fields.aliases
        assert "CWE-94" in fields.cwe_ids

    def test_epss_row(self, load_fixture: Callable[[str], Any]) -> None:
        """EPSS 行：主键为 cve，EPSS 分数 / 百分位被抽取。"""
        row = load_fixture("epss_sample.json")["data"][0]
        fields = extract_cve_fields(json.dumps(row), source="epss")
        assert fields.vuln_id == "CVE-2024-3400"
        assert fields.epss_score == pytest.approx(0.97432)
        assert fields.epss_percentile == pytest.approx(0.99912)

    def test_nvd_entry(self) -> None:
        """NVD 记录：从 ``cve.descriptions`` 取英文描述并清洗 HTML。"""
        payload = {
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "A <b>test</b> vuln."}],
                "published": "2024-01-02T00:00:00.000Z",
                "lastModified": "2024-01-03T00:00:00.000Z",
                "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                "references": [{"url": "https://example.test/a"}],
            }
        }
        fields = extract_cve_fields(json.dumps(payload), source="nvd")
        assert fields.vuln_id == "CVE-2024-0001"
        assert fields.description == "A test vuln."
        assert fields.cwe_ids == ("CWE-79",)
        assert fields.published_at == datetime(2024, 1, 2, tzinfo=UTC)

    def test_source_autodetection(self) -> None:
        """未显式给出 ``source`` 时按字段特征推断。"""
        assert extract_cve_fields('{"cveID": "CVE-2024-0002", "shortDescription": "x"}').vuln_id == "CVE-2024-0002"
        assert extract_cve_fields('{"id": "PYSEC-2024-1", "details": "y"}').vuln_id == "PYSEC-2024-1"

    def test_fallback_id_for_plain_text(self) -> None:
        """非 JSON 原文退化为纯文本描述，主键取 ``fallback_id``。"""
        fields = extract_cve_fields("plain text payload", fallback_id="CVE-2024-0003")
        assert fields.vuln_id == "CVE-2024-0003"
        assert fields.description == "plain text payload"

    def test_missing_id_raises(self) -> None:
        """既无主键也无兜底时报错。"""
        with pytest.raises(ValueError, match="vuln_id"):
            extract_cve_fields("plain text", source="kev")
