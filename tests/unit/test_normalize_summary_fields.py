"""Day7 前置：``UnifiedVuln`` v1.1 新增字段（``severity`` / ``affected_versions``）测试。

覆盖三个层次（全部离线、无 LLM）：

1. **纯函数**：``render_version_range`` / ``affected_versions_from_cpes`` / ``severity_from_vectors``；
2. **归一化填充**：``build_unified_vuln`` 确定性派生两字段；
3. **合并重算**：``merge_unified_vulns`` 后两字段与 cvss / cpe_matches 自洽。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.models.base import new_trace_id
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import CpeMatch, CVSSVector, Reference, UnifiedVuln
from aisec_intel.normalize.cvss import severity_from_vectors
from aisec_intel.normalize.dedupe import merge_unified_vulns
from aisec_intel.normalize.pipeline import (
    UNBOUNDED_RANGE,
    affected_versions_from_cpes,
    build_unified_vuln,
    render_version_range,
)
from aisec_intel.utils.hashing import sha256_text

NORMALIZED_AT = datetime(2026, 9, 30, 6, 0, tzinfo=UTC)


def make_cpe(**overrides: Any) -> CpeMatch:
    """构造一条 CPE 匹配（默认区间为 ``>=10.2.0, <10.2.9-h1``）。"""
    payload: dict[str, Any] = {
        "vendor": "paloaltonetworks",
        "product": "pan-os",
        "version_start_incl": "10.2.0",
        "version_end_excl": "10.2.9-h1",
        "vulnerable": True,
    }
    payload.update(overrides)
    return CpeMatch(**payload)


def make_vector(version: str, score: float, severity: str, *, vector: str | None = None) -> CVSSVector:
    """构造一个 CVSS 向量（``vector`` 缺省为 ``CVSS:{version}/AV:N/AC:L``）。"""
    return CVSSVector(
        version=version,  # type: ignore[arg-type]
        vector=vector or f"CVSS:{version}/AV:N/AC:L",
        base_score=score,
        severity=severity,  # type: ignore[arg-type]
    )


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造一个合法的 ``UnifiedVuln``。"""
    payload: dict[str, Any] = {"vuln_id": vuln_id, "description": "d", "normalized_at": NORMALIZED_AT}
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_raw(source: str, source_id: str, payload: dict[str, Any]) -> RawItem:
    """构造一条 ``RawItem``。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=None,
        raw_text=text,
        lang="en",
        published_at=NORMALIZED_AT,
        fetched_at=NORMALIZED_AT,
        sha256=sha256_text(text),
        meta={},
    )


class TestRenderVersionRange:
    """版本区间渲染（与 CpeMatch 语义一一对应）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 5 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_range_with_exclusive_end()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_range_with_exclusive_end: {type(exc).__name__}: {exc}")
        try:
            self._case_test_range_with_inclusive_end()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_range_with_inclusive_end: {type(exc).__name__}: {exc}")
        try:
            self._case_test_exact_version()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_exact_version: {type(exc).__name__}: {exc}")
        try:
            self._case_test_exclusive_start_only()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_exclusive_start_only: {type(exc).__name__}: {exc}")
        try:
            self._case_test_unbounded()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_unbounded: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_range_with_exclusive_end(self) -> None:
        """``>=start, <end`` 常规区间。"""
        assert render_version_range(make_cpe()) == ">=10.2.0, <10.2.9-h1"

    def _case_test_range_with_inclusive_end(self) -> None:
        """终点含（``<=``）由 ``version_end_incl`` 决定。"""
        match = make_cpe(version_end_excl=None, version_end_incl="10.2.9")
        assert render_version_range(match) == ">=10.2.0, <=10.2.9"

    def _case_test_exact_version(self) -> None:
        """``start_incl == end_incl`` 渲染为精确版本 ``==``。"""
        match = make_cpe(version_start_incl="11.0.1", version_end_excl=None, version_end_incl="11.0.1")
        assert render_version_range(match) == "==11.0.1"

    def _case_test_exclusive_start_only(self) -> None:
        """仅有排他起点时输出 ``>``。"""
        match = make_cpe(version_start_incl=None, version_start_excl="9.1", version_end_excl=None)
        assert render_version_range(match) == ">9.1"

    def _case_test_unbounded(self) -> None:
        """两端皆无界时输出通配占位。"""
        match = make_cpe(version_start_incl=None, version_end_excl=None)
        assert render_version_range(match) == UNBOUNDED_RANGE
        assert UNBOUNDED_RANGE == "*"


class TestAffectedVersions:
    """受影响版本清单渲染。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_dedupes_and_keeps_order()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_dedupes_and_keeps_order: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_matches_return_empty_list()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_matches_return_empty_list: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_dedupes_and_keeps_order(self) -> None:
        """相同标签去重，顺序保持首次出现。"""
        matches = [
            CpeMatch(vendor="apache", product="log4j", version_start_incl="2.0", version_end_excl="2.15.0"),
            CpeMatch(vendor="apache", product="log4j", version_start_incl="2.0", version_end_excl="2.15.0"),
            CpeMatch(vendor="apache", product="log4j-core", version_start_incl="2.0"),
        ]
        assert affected_versions_from_cpes(matches) == [
            "apache:log4j >=2.0, <2.15.0",
            "apache:log4j-core >=2.0",
        ]

    def _case_test_empty_matches_return_empty_list(self) -> None:
        """无 CPE 时返回空列表（不得编造）。"""
        assert affected_versions_from_cpes([]) == []


class TestSeverityFromVectors:
    """最高严重度推导。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_empty_returns_none()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_returns_none: {type(exc).__name__}: {exc}")
        try:
            self._case_test_picks_highest_score()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_picks_highest_score: {type(exc).__name__}: {exc}")
        try:
            self._case_test_ties_are_deterministic()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_ties_are_deterministic: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_empty_returns_none(self) -> None:
        """无 CVSS 时返回 ``None``（不猜测）。"""
        assert severity_from_vectors([]) is None

    def _case_test_picks_highest_score(self) -> None:
        """取 ``base_score`` 最高的向量。"""
        vectors = [make_vector("2.0", 6.5, "MEDIUM"), make_vector("3.1", 10.0, "CRITICAL")]
        assert severity_from_vectors(vectors) == "CRITICAL"

    def _case_test_ties_are_deterministic(self) -> None:
        """同分时按版本字符串序取最新（输出确定）。"""
        vectors = [make_vector("3.0", 9.8, "CRITICAL"), make_vector("3.1", 9.8, "CRITICAL")]
        assert severity_from_vectors(vectors) == "CRITICAL"
        assert severity_from_vectors(list(reversed(vectors))) == "CRITICAL"


NVD_PAYLOAD: dict[str, Any] = {
    "cve": {
        "id": "CVE-2024-3400",
        "published": "2024-04-12T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "PAN-OS command injection."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-77"}]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionEndExcluding": "10.2.9-h1",
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.org/advisory"}],
    }
}

KEV_ENTRY: dict[str, Any] = {
    "cveID": "CVE-2024-3400",
    "vulnerabilityName": "PAN-OS Command Injection",
    "shortDescription": "Command injection in PAN-OS GlobalProtect.",
    "dateAdded": "2024-04-12",
    "cwes": ["CWE-77"],
}


class TestPipelineFillsNewFields:
    """``build_unified_vuln`` 填充 v1.1 新字段。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_nvd_payload_yields_severity_and_versions()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_nvd_payload_yields_severity_and_versions: {type(exc).__name__}: {exc}")
        try:
            self._case_test_kev_payload_without_cvss_has_no_severity()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_kev_payload_without_cvss_has_no_severity: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_nvd_payload_yields_severity_and_versions(self) -> None:
        """NVD 载荷（含 CVSS + CPE）→ severity=CRITICAL、affected_versions 非空。"""
        vuln = build_unified_vuln(make_raw("nvd", "CVE-2024-3400", NVD_PAYLOAD), normalized_at=NORMALIZED_AT)
        assert vuln.schema_version == "1.1"
        assert vuln.severity == "CRITICAL"
        assert vuln.affected_versions == ["paloaltonetworks:pan-os ==10.2.0"]
        assert vuln.cvss[0].base_score == 10.0

    def _case_test_kev_payload_without_cvss_has_no_severity(self) -> None:
        """无 CVSS 的源（KEV）→ ``severity is None``（不猜测），affected_versions 为空。"""
        vuln = build_unified_vuln(make_raw("kev", "CVE-2024-3400", KEV_ENTRY), normalized_at=NORMALIZED_AT)
        assert vuln.severity is None
        assert vuln.affected_versions == []
        assert vuln.cwe_ids == ["CWE-77"]


class TestMergeRecomputesNewFields:
    """合并后新字段与 cvss / cpe_matches 自洽。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_union_of_versions_and_highest_severity()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_union_of_versions_and_highest_severity: {type(exc).__name__}: {exc}")
        try:
            self._case_test_severity_none_when_no_cvss_anywhere()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_severity_none_when_no_cvss_anywhere: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_union_of_versions_and_highest_severity(self) -> None:
        """两源合并：版本清单取并集、严重度取最高、schema_version 取最高版本。"""
        low = make_vuln(
            "CVE-2024-3400",
            schema_version="1.0",
            cvss=[make_vector("3.1", 6.5, "MEDIUM")],
            severity="MEDIUM",
            cpe_matches=[CpeMatch(vendor="apache", product="log4j", version_start_incl="2.0")],
            affected_versions=["apache:log4j >=2.0"],
            sources=["osv"],
            references=[Reference(url="https://example.org/osv", source="osv")],
        )
        high = make_vuln(
            "CVE-2024-3400",
            cvss=[make_vector("3.1", 10.0, "CRITICAL", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")],
            severity="CRITICAL",
            cpe_matches=[make_cpe()],
            affected_versions=["paloaltonetworks:pan-os >=10.2.0, <10.2.9-h1"],
            sources=["nvd"],
            references=[Reference(url="https://example.org/nvd", source="nvd")],
        )

        merged = merge_unified_vulns([low, high])

        assert len(merged) == 1
        entity = merged[0]
        assert entity.schema_version == "1.1"  # 取组内最高契约版本
        assert entity.severity == "CRITICAL"
        assert set(entity.affected_versions) == {
            "apache:log4j >=2.0",
            "paloaltonetworks:pan-os >=10.2.0, <10.2.9-h1",
        }
        assert len(entity.cvss) == 2  # 两个向量均保留（(version, vector) 不同）
        assert {match.product for match in entity.cpe_matches} == {"log4j", "pan-os"}
        assert entity.sources == ["nvd", "osv"]

    def _case_test_severity_none_when_no_cvss_anywhere(self) -> None:
        """组内无 CVSS 时合并结果 severity 仍为 ``None``。"""
        first = make_vuln("CVE-2024-9999", sources=["kev"])
        second = make_vuln("CVE-2024-9999", sources=["epss"], severity=None)
        assert merge_unified_vulns([first, second])[0].severity is None


class TestRepositoryRoundTrip:
    """ORM 往返：新字段必须落库并读回（表列由迁移 0004 追加）。"""

    async def test_columns_round_trip(self, memory_engine: Any) -> None:
        """``upsert`` → ``get_by_cve`` 后 severity / affected_versions 保持一致。"""
        from aisec_intel.storage.database import session_scope
        from aisec_intel.storage.repositories.vuln_repo import VulnRepository

        vuln = make_vuln(
            "CVE-2024-3400",
            severity="CRITICAL",
            affected_versions=["paloaltonetworks:pan-os >=10.2.0, <10.2.9-h1"],
            cvss=[make_vector("3.1", 10.0, "CRITICAL")],
        )
        async with session_scope(memory_engine) as session:
            await VulnRepository(session).upsert(vuln)

        async with session_scope(memory_engine) as session:
            stored = await VulnRepository(session).get_by_cve("cve-2024-3400")
        assert stored is not None
        assert stored.severity == "CRITICAL"
        assert stored.affected_versions == ["paloaltonetworks:pan-os >=10.2.0, <10.2.9-h1"]
        assert stored.schema_version == "1.1"


@pytest.mark.parametrize("value", ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_severity_literals_are_accepted(value: str) -> None:
    """五档严重度均可写入契约。"""
    assert make_vuln("CVE-2024-3400", severity=value).severity == value
