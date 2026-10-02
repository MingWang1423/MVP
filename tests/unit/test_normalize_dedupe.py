"""Day5 跨源去重与合并测试（PROJECT_PLAN.md §5.4 `normalize/dedupe.py`）。

覆盖：URL 规范化 / 去重、SimHash 稳定性与汉明距离、CVE 精确合并（NVD+OSV+GHSA+KEV+EPSS 五源）、
无 CVE 主键的近似聚类、多源字段并集与「取最早/最晚」等合并规则。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aisec_intel.models.base import utc_now
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.normalize.dedupe import (
    dedupe_urls,
    hamming_distance,
    merge_for_update,
    merge_group,
    merge_unified_vulns,
    normalize_url,
    primary_key,
    simhash,
    similarity_fingerprint,
    tokenize,
)
from aisec_intel.normalize.pipeline import build_unified_vuln

BASE = datetime(2024, 1, 1, tzinfo=UTC)


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造用于合并测试的 ``UnifiedVuln``。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "description": f"description for {vuln_id}",
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def raw_from(source: str, payload: dict[str, Any], source_id: str) -> Any:
    """由源侧载荷构造 ``RawItem``。"""
    from aisec_intel.models.raw_item import RawItem

    return RawItem(
        trace_id=f"trace-{source}-{source_id}",
        source=source,
        source_id=source_id,
        url=f"https://example.test/{source}/{source_id}",
        raw_text=json.dumps(payload, ensure_ascii=False, sort_keys=True),
        fetched_at=BASE,
        sha256="a" * 64,
    )


class TestUrlNormalization:
    """URL 规范化与去重。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_normalize_url()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_normalize_url: {type(exc).__name__}: {exc}")
        try:
            self._case_test_dedupe_urls()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_dedupe_urls: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_normalize_url(self) -> None:
        """去查询串 / 片段 / 末尾斜杠，host 小写。"""
        assert normalize_url("https://Example.COM/path/?utm_source=x#frag") == "https://example.com/path"
        assert normalize_url("  ") is None
        assert normalize_url(None) is None

    def _case_test_dedupe_urls(self) -> None:
        """同地址不同查询串视为同一 URL。"""
        urls = [
            "https://example.test/a?utm_source=tw",
            "https://example.test/a",
            "https://example.test/b",
        ]
        assert dedupe_urls(urls) == ["https://example.test/a?utm_source=tw", "https://example.test/b"]


class TestSimHash:
    """SimHash 指纹与距离。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_tokenize()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_tokenize: {type(exc).__name__}: {exc}")
        try:
            self._case_test_simhash_is_deterministic()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_simhash_is_deterministic: {type(exc).__name__}: {exc}")
        try:
            self._case_test_similar_texts_have_small_distance()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_similar_texts_have_small_distance: {type(exc).__name__}: {exc}")
        try:
            self._case_test_exact_and_symmetric_distance()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_exact_and_symmetric_distance: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_tokenize(self) -> None:
        """仅保留小写字母与数字。"""
        assert tokenize("CVE-2024-3400 Command Injection!") == ["cve", "2024", "3400", "command", "injection"]

    def _case_test_simhash_is_deterministic(self) -> None:
        """同一文本指纹稳定；空文本为 0。"""
        assert simhash("hello world") == simhash("hello world")
        assert simhash("") == 0

    def _case_test_similar_texts_have_small_distance(self) -> None:
        """近似文本汉明距离小，差异文本距离大（阈值 15 的定标依据）。"""
        base = "PAN-OS GlobalProtect command injection allows remote code execution"
        near = "PAN-OS GlobalProtect command injection allows remote code execution with root"
        far = "Open redirect in actionpack allows phishing"
        assert hamming_distance(simhash(base), simhash(near)) <= 16
        assert hamming_distance(simhash(base), simhash(far)) >= 20

    def _case_test_exact_and_symmetric_distance(self) -> None:
        """相同指纹距离 0；距离对称。"""
        value = simhash("some text")
        assert hamming_distance(value, value) == 0
        assert hamming_distance(value, simhash("other")) == hamming_distance(simhash("other"), value)


class TestPrimaryKey:
    """主键归一。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_prefers_cve_alias()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_prefers_cve_alias: {type(exc).__name__}: {exc}")
        try:
            self._case_test_falls_back_to_vuln_id()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_falls_back_to_vuln_id: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_prefers_cve_alias(self) -> None:
        """``vuln_id`` 非 CVE 时用别名中的 CVE 作为主键。"""
        vuln = make_vuln("GHSA-3hjh-jh2g-v3gj", aliases=["CVE-2024-28088"])
        assert primary_key(vuln) == "CVE-2024-28088"

    def _case_test_falls_back_to_vuln_id(self) -> None:
        """无 CVE 时使用 ``vuln_id``（大写）。"""
        assert primary_key(make_vuln("pypi-2024-1")) == "PYPI-2024-1"


class TestMergeGroup:
    """同主键合并规则。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_unions_and_picks_extremes()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_unions_and_picks_extremes: {type(exc).__name__}: {exc}")
        try:
            self._case_test_merges_references_without_duplicates()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_merges_references_without_duplicates: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_group_raises()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_group_raises: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_unions_and_picks_extremes(self) -> None:
        """字段取并集；发布取最早、修改取最晚、描述取最长、KEV/EPSS 取「任一」。"""
        early = BASE
        late = BASE + timedelta(days=30)
        merged = merge_group(
            [
                make_vuln(
                    "CVE-2024-3400",
                    description="short",
                    sources=["nvd"],
                    trace_ids=["t-nvd"],
                    cwe_ids=["CWE-77"],
                    kev=False,
                    published_at=late,
                    modified_at=late,
                ),
                make_vuln(
                    "CVE-2024-3400",
                    description="a much longer description coming from KEV",
                    sources=["kev"],
                    trace_ids=["t-kev"],
                    cwe_ids=["CWE-77", "CWE-20"],
                    kev=True,
                    epss_score=0.97,
                    published_at=early,
                    modified_at=early,
                ),
            ]
        )
        assert merged.vuln_id == "CVE-2024-3400"
        assert merged.sources == ["kev", "nvd"]
        # trace_ids 顺序跟随「最早发布在前」的排序（KEV 记录发布更早）
        assert merged.trace_ids == ["t-kev", "t-nvd"]
        assert merged.cwe_ids == ["CWE-77", "CWE-20"]
        assert merged.kev is True
        assert merged.epss_score == pytest.approx(0.97)
        assert merged.description.startswith("a much longer")
        assert merged.published_at == early
        assert merged.modified_at == late

    def _case_test_merges_references_without_duplicates(self) -> None:
        """参考链接按规范化 URL 去重（带查询串的重复被合并，标签取并集）。"""
        from aisec_intel.models.unified_vuln import Reference

        merged = merge_group(
            [
                make_vuln("CVE-2024-0001", references=[Reference(url="https://a.test/x?utm=1", source="nvd")]),
                make_vuln(
                    "CVE-2024-0001",
                    references=[Reference(url="https://a.test/x", source="ghsa", tags=["patch"])],
                ),
            ]
        )
        assert len(merged.references) == 1
        assert merged.references[0].tags == ["patch"]

    def _case_test_empty_group_raises(self) -> None:
        """空序列报错。"""
        with pytest.raises(ValueError, match="至少一条"):
            merge_group([])


class TestMergeForUpdate:
    """``upsert`` 落库合并规则（v1.1 行为变更：非空优先 / 取极值 / 取并集）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 6 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_empty_incoming_does_not_wipe_existing()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_incoming_does_not_wipe_existing: {type(exc).__name__}: {exc}")
        try:
            self._case_test_unions_and_extremes_on_both_sides()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_unions_and_extremes_on_both_sides: {type(exc).__name__}: {exc}")
        try:
            self._case_test_primary_key_follows_existing_row()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_primary_key_follows_existing_row: {type(exc).__name__}: {exc}")
        try:
            self._case_test_same_key_does_not_add_self_alias()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_same_key_does_not_add_self_alias: {type(exc).__name__}: {exc}")
        try:
            self._case_test_merge_is_idempotent()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_merge_is_idempotent: {type(exc).__name__}: {exc}")
        try:
            self._case_test_schema_version_takes_highest()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_schema_version_takes_highest: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_empty_incoming_does_not_wipe_existing(self) -> None:
        """**核心回归**：本次写入为空值时，不得清空库中已有值（原「后写覆盖」缺陷）。"""
        from aisec_intel.models.unified_vuln import CpeMatch, CVSSVector, Reference

        existing = make_vuln(
            "CVE-2024-3400",
            description="NVD 的长描述",
            cvss=[CVSSVector(version="3.1", vector="CVSS:3.1/AV:N", base_score=10.0, severity="CRITICAL")],
            severity="CRITICAL",
            cwe_ids=["CWE-77"],
            cpe_matches=[CpeMatch(vendor="paloaltonetworks", product="pan-os", version_end_excl="10.2.9-h1")],
            affected_versions=["paloaltonetworks:pan-os <10.2.9-h1"],
            references=[Reference(url="https://example.test/nvd", source="nvd")],
            kev=True,
            epss_score=0.97,
            published_at=BASE,
            modified_at=BASE + timedelta(days=5),
            sources=["nvd"],
            trace_ids=["t-nvd"],
        )
        # 模拟 KEV 视图：只有描述与 CWE，无 CVSS / CPE / EPSS
        incoming = make_vuln(
            "CVE-2024-3400",
            description="KEV 短描述",
            cwe_ids=["CWE-20"],
            sources=["kev"],
            trace_ids=["t-kev"],
        )

        merged = merge_for_update(existing, incoming)

        assert merged.vuln_id == "CVE-2024-3400"
        assert merged.cvss and merged.cvss[0].base_score == 10.0  # 未被 KEV 的「无 CVSS」覆盖
        assert merged.severity == "CRITICAL"  # 严重度只升不降
        assert merged.description == "NVD 的长描述"  # 取最长
        assert merged.cpe_matches and merged.cpe_matches[0].product == "pan-os"
        assert merged.affected_versions == ["paloaltonetworks:pan-os <10.2.9-h1"]
        assert merged.references and merged.references[0].source == "nvd"
        assert merged.kev is True  # 任一为真
        assert merged.epss_score == pytest.approx(0.97)  # 非空值保留
        assert merged.published_at == BASE  # 取最早
        assert merged.sources == ["kev", "nvd"]  # 并集
        assert sorted(merged.trace_ids) == ["t-kev", "t-nvd"]

    def _case_test_unions_and_extremes_on_both_sides(self) -> None:
        """两侧各有值时：集合并集、时间取极值、epss 取最大、kev 取 OR。"""
        from aisec_intel.models.unified_vuln import CpeMatch

        early = BASE
        late = BASE + timedelta(days=30)
        left = make_vuln(
            "CVE-2024-3400",
            description="left",
            cwe_ids=["CWE-77"],
            cpe_matches=[CpeMatch(vendor="a", product="p1")],
            kev=False,
            epss_score=0.10,
            published_at=late,
            modified_at=late,
            sources=["nvd"],
        )
        right = make_vuln(
            "CVE-2024-3400",
            description="right-description-is-longer",
            cwe_ids=["CWE-20"],
            cpe_matches=[CpeMatch(vendor="b", product="p2")],
            kev=True,
            epss_score=0.55,
            published_at=early,
            modified_at=early,
            sources=["kev"],
        )

        merged = merge_for_update(left, right)

        assert merged.description == "right-description-is-longer"
        # 并集顺序跟随「发布时间升序」的贡献顺序（right 更早 → 其 CWE 在前），与入参顺序无关
        assert merged.cwe_ids == ["CWE-20", "CWE-77"]
        assert {match.vendor for match in merged.cpe_matches} == {"a", "b"}
        assert merged.kev is True
        assert merged.epss_score == pytest.approx(0.55)
        assert merged.published_at == early
        assert merged.modified_at == late
        assert merged.sources == ["kev", "nvd"]
        # 字段合并结果与「谁先入库」无关（交换入参得到同一实体）
        assert merge_for_update(right, left) == merged

    def _case_test_primary_key_follows_existing_row(self) -> None:
        """主键以库中既有行为准；本次写入的异主键降级为别名（不静默换主键）。"""
        existing = make_vuln("GHSA-jfh8-c2jp-5v3q", aliases=[], sources=["ghsa"])
        incoming = make_vuln("CVE-2024-3400", sources=["nvd"])

        merged = merge_for_update(existing, incoming)

        assert merged.vuln_id == "GHSA-jfh8-c2jp-5v3q"
        assert "CVE-2024-3400" in merged.aliases
        assert "GHSA-JFH8-C2JP-5V3Q" not in merged.aliases  # 自身主键不作为别名

    def _case_test_same_key_does_not_add_self_alias(self) -> None:
        """同主键合并不会产生自别名。"""
        existing = make_vuln("CVE-2024-3400", sources=["nvd"])
        incoming = make_vuln("CVE-2024-3400", sources=["kev"])
        assert merge_for_update(existing, incoming).aliases == []

    def _case_test_merge_is_idempotent(self) -> None:
        """重复合并同一实体不再变化（可安全重复重跑）。"""
        existing = make_vuln(
            "CVE-2024-3400",
            description="desc",
            kev=True,
            epss_score=0.9,
            sources=["nvd"],
            cwe_ids=["CWE-77"],
        )
        once = merge_for_update(existing, make_vuln("CVE-2024-3400", sources=["kev"]))
        twice = merge_for_update(once, make_vuln("CVE-2024-3400", sources=["kev"]))
        assert once == twice

    def _case_test_schema_version_takes_highest(self) -> None:
        """``schema_version`` 取较高者（旧行被新契约刷新）。"""
        existing = make_vuln("CVE-2024-3400", schema_version="1.0")
        incoming = make_vuln("CVE-2024-3400", schema_version="1.1")
        assert merge_for_update(existing, incoming).schema_version == "1.1"


class TestMergeUnifiedVulns:
    """跨源合并主入口（真实 fixture 五源）。"""

    def test_five_sources_merge_into_one(self, load_fixture: Callable[[str], Any]) -> None:
        """同一 CVE 的多源记录合并为一条，``sources`` / ``trace_ids`` 记录全部来源。"""
        kev_entry = load_fixture("kev_sample.json")["vulnerabilities"][0]
        nvd_entry = load_fixture("nvd_sample.json")["vulnerabilities"][0]
        ghsa_node = load_fixture("ghsa_graphql_sample.json")["data"]["securityAdvisories"]["nodes"][0]
        osv_entry = load_fixture("osv_sample.json")["vulns"][0]
        epss_row = load_fixture("epss_sample.json")["data"][0]

        vulns = [
            build_unified_vuln(raw_from("kev", kev_entry, "CVE-2024-3400")),
            build_unified_vuln(raw_from("nvd", nvd_entry, "CVE-2024-3400")),
            build_unified_vuln(raw_from("epss", epss_row, "CVE-2024-3400")),
            build_unified_vuln(raw_from("ghsa", ghsa_node, "GHSA-2qrp-3j2c-6v3x")),
            build_unified_vuln(raw_from("osv", osv_entry, "GHSA-3hjh-jh2g-v3gj")),
        ]
        merged = merge_unified_vulns(vulns)
        by_id = {item.vuln_id: item for item in merged}
        assert set(by_id) == {"CVE-2024-3400", "CVE-2024-28088"}  # 5 条 → 2 条

        target = by_id["CVE-2024-3400"]
        assert target.sources == ["epss", "kev", "nvd"]
        assert sorted(target.trace_ids) == [
            "trace-epss-CVE-2024-3400",
            "trace-kev-CVE-2024-3400",
            "trace-nvd-CVE-2024-3400",
        ]
        assert target.kev is True
        assert target.epss_score == pytest.approx(0.97432)
        assert target.cvss and target.cvss[0].base_score == 10.0

        cve_28088 = by_id["CVE-2024-28088"]
        assert cve_28088.sources == ["ghsa", "osv"]
        ids = {cve_28088.vuln_id.upper(), *[alias.upper() for alias in cve_28088.aliases]}
        assert {"GHSA-2QRP-3J2C-6V3X", "GHSA-3HJH-JH2G-V3GJ"} <= ids

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_similarity_clustering_without_cve()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_similarity_clustering_without_cve: {type(exc).__name__}: {exc}")
        try:
            self._case_test_fast_mode_only_exact_match()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_fast_mode_only_exact_match: {type(exc).__name__}: {exc}")
        try:
            self._case_test_dissimilar_records_stay_separate()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_dissimilar_records_stay_separate: {type(exc).__name__}: {exc}")
        try:
            self._case_test_similarity_fingerprint_matches_simhash()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_similarity_fingerprint_matches_simhash: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_similarity_clustering_without_cve(self) -> None:
        """无 CVE 主键的近似条目按 SimHash 聚类合并。"""
        text = "vLLM denial of service through malformed sampling parameter in server"
        first = make_vuln("GHSA-aaaa-bbbb-cccc", title=text, description=text, sources=["ghsa"])
        second = make_vuln("GHSA-dddd-eeee-ffff", title=text, description=text + " remote", sources=["osv"])
        merged = merge_unified_vulns([first, second])
        assert len(merged) == 1
        assert merged[0].sources == ["ghsa", "osv"]

    def _case_test_fast_mode_only_exact_match(self) -> None:
        """``use_similarity=False`` 时只做精确匹配。"""
        text = "same text for both records"
        first = make_vuln("GHSA-aaaa-bbbb-cccc", title=text, description=text)
        second = make_vuln("GHSA-dddd-eeee-ffff", title=text, description=text)
        assert len(merge_unified_vulns([first, second], use_similarity=False)) == 2

    def _case_test_dissimilar_records_stay_separate(self) -> None:
        """差异大的无 CVE 记录不会被误合并。"""
        first = make_vuln("GHSA-1111-2222-3333", title="Open redirect", description="phishing via redirect")
        second = make_vuln("GHSA-4444-5555-6666", title="SQL injection", description="database dump")
        assert len(merge_unified_vulns([first, second])) == 2

    def test_output_is_deterministic(self, load_fixture: Callable[[str], Any]) -> None:
        """输入顺序不影响输出（按 ``vuln_id`` 升序、字段取并集）。"""
        kev_entry = load_fixture("kev_sample.json")["vulnerabilities"][0]
        nvd_entry = load_fixture("nvd_sample.json")["vulnerabilities"][0]
        first = build_unified_vuln(raw_from("kev", kev_entry, "CVE-2024-3400"))
        second = build_unified_vuln(raw_from("nvd", nvd_entry, "CVE-2024-3400"))
        assert merge_unified_vulns([first, second]) == merge_unified_vulns([second, first])

    def _case_test_similarity_fingerprint_matches_simhash(self) -> None:
        """``similarity_fingerprint`` 等价于「标题 + 描述」的 SimHash。"""
        vuln = make_vuln("GHSA-x", title="T", description="D")
        assert similarity_fingerprint(vuln) == simhash("T D")