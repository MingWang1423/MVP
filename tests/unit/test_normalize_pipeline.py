"""Day4 归一化流水线测试（PROJECT_PLAN.md §2 / §5.3）。

用 **KEV / OSV / GHSA / EPSS fixture** 走完整 ``RawItem → UnifiedVuln`` 流水线，
断言字段完整性与「事实层不做推断」的边界（§10.2 不变式 4）。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.cve import CveFields
from aisec_intel.normalize.pipeline import (
    build_many,
    build_references,
    build_unified_vuln,
    canonical_ecosystem,
    extract_cpe_matches,
    extract_ecosystem_packages,
    parse_cpe23,
)

NORMALIZED_AT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def make_raw(source: str, source_id: str, payload: dict[str, Any], *, url: str = "https://example.test/x") -> RawItem:
    """由源侧条目构造 ``RawItem``（等价于采集器输出）。"""
    return RawItem(
        trace_id="trace-fixture-0001",
        source=source,
        source_id=source_id,
        url=url,
        title=None,
        raw_text=json.dumps(payload, ensure_ascii=False, sort_keys=True),
        fetched_at=NORMALIZED_AT,
        sha256="a" * 64,
    )


class TestKevPipeline:
    """KEV → UnifiedVuln。"""

    def test_full_pipeline(self, load_fixture: Callable[[str], Any]) -> None:
        """KEV 条目产出完整 ``UnifiedVuln``（kev 标记、CWE、参考链接、trace_id 透传）。"""
        entry = load_fixture("kev_sample.json")["vulnerabilities"][0]
        vuln = build_unified_vuln(make_raw("kev", "CVE-2024-3400", entry), normalized_at=NORMALIZED_AT)
        assert vuln.vuln_id == "CVE-2024-3400"
        assert vuln.kev is True
        assert vuln.cwe_ids == ["CWE-77"]
        assert vuln.published_at == datetime(2024, 4, 12, tzinfo=UTC)
        assert vuln.sources == ["kev"]
        assert vuln.trace_ids == ["trace-fixture-0001"]
        assert vuln.normalized_at == NORMALIZED_AT
        assert vuln.description
        assert vuln.references

    def test_no_cvss_is_not_invented(self, load_fixture: Callable[[str], Any]) -> None:
        """KEV 不含 CVSS 时保持空列表（不臆造分数）。"""
        entry = load_fixture("kev_sample.json")["vulnerabilities"][1]
        vuln = build_unified_vuln(make_raw("kev", entry["cveID"], entry), normalized_at=NORMALIZED_AT)
        assert vuln.cvss == []


class TestOsvPipeline:
    """OSV → UnifiedVuln。"""

    def test_full_pipeline(self, load_fixture: Callable[[str], Any]) -> None:
        """OSV 条目产出 ``UnifiedVuln``（CVSS 自算、生态包、CVE 别名）。"""
        entry = load_fixture("osv_sample.json")["vulns"][0]
        vuln = build_unified_vuln(make_raw("osv", "GHSA-3hjh-jh2g-v3gj", entry), normalized_at=NORMALIZED_AT)
        assert vuln.vuln_id == "GHSA-3hjh-jh2g-v3gj"
        assert "CVE-2024-28088" in vuln.aliases
        assert "PyPI:langchain" in vuln.ecosystem_packages
        assert vuln.cvss[0].base_score == 9.8
        assert vuln.cvss[0].severity == "CRITICAL"
        assert vuln.kev is False
        assert vuln.description.startswith("LangChain before")

    def test_html_is_cleaned(self, load_fixture: Callable[[str], Any]) -> None:
        """描述中的 HTML 标签被清洗。"""
        entry = load_fixture("osv_sample.json")["vulns"][0]
        vuln = build_unified_vuln(make_raw("osv", entry["id"], entry), normalized_at=NORMALIZED_AT)
        assert "<code>" not in vuln.description


class TestGhsaPipeline:
    """GHSA → UnifiedVuln。"""

    def test_full_pipeline(self, load_fixture: Callable[[str], Any]) -> None:
        """GHSA 节点产出 ``UnifiedVuln``（CVSS 用源侧分数、CWE、生态包）。"""
        node = load_fixture("ghsa_graphql_sample.json")["data"]["securityAdvisories"]["nodes"][0]
        vuln = build_unified_vuln(make_raw("ghsa", "GHSA-2qrp-3j2c-6v3x", node), normalized_at=NORMALIZED_AT)
        assert vuln.vuln_id == "GHSA-2qrp-3j2c-6v3x"
        assert vuln.cvss[0].base_score == 9.8
        assert vuln.cwe_ids == ["CWE-94", "CWE-502"]
        assert "PyPI:langchain" in vuln.ecosystem_packages
        assert "CVE-2024-28088" in vuln.aliases


class TestPipelineHelpers:
    """辅助纯函数测试（CPE / 生态包 / 参考链接 / 批处理）。"""

    def test_parse_cpe23_with_version(self) -> None:
        """精确版本 CPE → 区间 ``[version, version]``。"""
        parsed = parse_cpe23("cpe:2.3:a:paloaltonetworks:pan-os:10.2.9:*:*:*:*:*:*:*")
        assert parsed is not None
        assert parsed.vendor == "paloaltonetworks"
        assert parsed.version_start_incl == "10.2.9"

    def test_parse_cpe23_wildcard_version(self) -> None:
        """``*`` 版本 → 仅 vendor/product + 修复版本。"""
        parsed = parse_cpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", version_end_excl="2.15.0")
        assert parsed is not None
        assert parsed.version_end_excl == "2.15.0"
        assert parsed.version_start_incl is None

    def test_parse_cpe23_invalid(self) -> None:
        """非法 / 通配厂商的 CPE 返回 ``None``。"""
        assert parse_cpe23("not-a-cpe") is None
        assert parse_cpe23("cpe:2.3:a:*:log4j:1.0:*:*:*:*:*:*:*") is None

    def test_extract_cpe_matches_from_nvd_configurations(self) -> None:
        """从 NVD ``configurations`` 递归抽取 CPE。"""
        payload = {
            "cve": {
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
                                        "versionEndExcluding": "11.1.3",
                                        "vulnerable": True,
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        }
        matches = extract_cpe_matches(payload)
        assert len(matches) == 1
        assert matches[0].product == "pan-os"
        assert matches[0].version_end_excl == "11.1.3"

    def test_extract_ecosystem_packages(self) -> None:
        """OSV 与 GHSA 两种载荷形态都能抽出 ``生态:包名``，且生态名被对齐为统一写法。"""
        assert extract_ecosystem_packages({"affected": [{"package": {"ecosystem": "PyPI", "name": "vllm"}}]}) == [
            "PyPI:vllm"
        ]
        ghsa_payload = {"vulnerabilities": {"nodes": [{"package": {"ecosystem": "PIP", "name": "torch"}}]}}
        assert extract_ecosystem_packages(ghsa_payload) == ["PyPI:torch"]  # PIP → PyPI 跨源对齐

    def test_canonical_ecosystem(self) -> None:
        """生态别名映射：GHSA 写法 → OSV 写法；未知值原样保留。"""
        assert canonical_ecosystem("PIP") == "PyPI"
        assert canonical_ecosystem("npm") == "npm"
        assert canonical_ecosystem("RUBYGEMS") == "RubyGems"
        assert canonical_ecosystem("WeirdEco") == "WeirdEco"

    def test_build_references_tags(self) -> None:
        """参考链接按 URL 关键词打标签（patch / exploit）。"""
        fields = CveFields(
            vuln_id="CVE-2024-0001",
            reference_urls=(
                "https://example.test/patch/1",
                "https://example.test/exploit/poc",
                "https://example.test/generic",
            ),
        )
        tags = [ref.tags for ref in build_references(fields, source="nvd")]
        assert ["patch"] in tags
        assert ["exploit"] in tags
        assert [] in tags

    def test_build_many_uses_fallback_id(self) -> None:
        """未知源但带 ``source_id`` 时仍可归一化（主键回退为 ``source_id``）。"""
        good = make_raw("kev", "CVE-2024-0009", {"cveID": "CVE-2024-0009", "shortDescription": "x"})
        fallback = RawItem(
            trace_id="t",
            source="unknown-source",
            source_id="CVE-2024-0010",
            url="https://example.test/x",
            raw_text="plain text without ids",
            fetched_at=NORMALIZED_AT,
            sha256="b" * 64,
        )
        results = build_many([good, fallback], normalized_at=NORMALIZED_AT)
        assert [item.vuln_id for item in results] == ["CVE-2024-0009", "CVE-2024-0010"]
        assert results[1].description == "plain text without ids"


class TestEpssPipeline:
    """EPSS → UnifiedVuln。"""

    def test_full_pipeline(self, load_fixture: Callable[[str], Any]) -> None:
        """EPSS 行产出 ``UnifiedVuln``（EPSS 分数 / 百分位、模型日期）。"""
        row = load_fixture("epss_sample.json")["data"][0]
        vuln = build_unified_vuln(make_raw("epss", "CVE-2024-3400", row), normalized_at=NORMALIZED_AT)
        assert vuln.vuln_id == "CVE-2024-3400"
        assert vuln.epss_score == pytest.approx(0.97432)
        assert vuln.epss_percentile == pytest.approx(0.99912)
        assert vuln.published_at == datetime(2024, 4, 15, tzinfo=UTC)
