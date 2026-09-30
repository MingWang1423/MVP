"""Day6 采集服务单元测试（PROJECT_PLAN.md §5.5 P4 任务 1）。

覆盖：``--since`` 解析、源解析、论文源跳过归一化、合并统计（折叠计数）、
``print_stats`` 输出门控与结果对象语义（不访问网络 / 数据库）。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from aisec_intel.connectors.registry import UnknownSourceError
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.services.collect_service import (
    CollectStats,
    MergeOutcome,
    NormalizeOutcome,
    normalize_batch,
    parse_since,
    print_stats,
    resolve_sources,
)
from aisec_intel.utils.hashing import sha256_text

CVE_ID = "CVE-2024-3400"


def make_item(source: str, source_id: str, payload: dict[str, Any]) -> RawItem:
    """构造一条内容与指纹自洽的 ``RawItem``。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=None,
        raw_text=text,
        lang="en",
        published_at=utc_now(),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


def kev_payload(description: str = "PAN-OS command injection vulnerability.") -> dict[str, Any]:
    """构造一条 KEV 风格载荷。"""
    return {
        "cveID": CVE_ID,
        "vulnerabilityName": "PAN-OS Command Injection",
        "shortDescription": description,
        "dateAdded": "2024-04-12",
        "cwes": ["CWE-77"],
    }


class TestParseSince:
    """``--since`` 解析。"""

    def test_accepts_date_and_iso(self) -> None:
        """``YYYY-MM-DD`` 与 ISO8601 均可解析为 UTC。"""
        assert parse_since("2024-01-01") == datetime(2024, 1, 1, tzinfo=UTC)
        assert parse_since("2024-01-01T08:30:00Z") == datetime(2024, 1, 1, 8, 30, tzinfo=UTC)

    def test_blank_and_invalid(self) -> None:
        """空串返回 ``None``；无法解析的文本返回 ``None``（调用方报错退出）。"""
        assert parse_since(None) is None
        assert parse_since("   ") is None
        assert parse_since("not-a-date") is None


class TestResolveSources:
    """``--source`` 解析。"""

    def test_all_expands_to_registry(self) -> None:
        """``all`` 展开为全部已注册源（含 P4 新增论文源）。"""
        sources = resolve_sources("all")
        assert {"arxiv", "kev", "nvd", "openalex"} <= set(sources)
        assert sources == sorted(sources)

    def test_comma_separated_is_normalized(self) -> None:
        """逗号分隔、大小写与空白均被规范化。"""
        assert resolve_sources(" KEV , nvd ") == ["kev", "nvd"]

    def test_unknown_source_raises(self) -> None:
        """未注册源显式报错。"""
        with pytest.raises(UnknownSourceError, match="未注册"):
            resolve_sources("not-exist")

    def test_missing_source_raises_system_exit(self) -> None:
        """未提供 ``--source`` 时提示可用 ``--list-sources``。"""
        with pytest.raises(SystemExit, match="list-sources"):
            resolve_sources(None)


class TestNormalizeBatch:
    """归一化 + 合并（纯函数）。"""

    def test_two_records_same_cve_are_folded(self) -> None:
        """同源两条同 CVE 记录合并为 1 条，折叠计数正确。"""
        items = [
            make_item("kev", CVE_ID, kev_payload("short")),
            make_item("kev", CVE_ID, kev_payload("a much longer description for the same CVE")),
        ]
        outcome = normalize_batch(items, source="kev", normalized_at=datetime(2024, 5, 1, tzinfo=UTC))
        assert outcome.ok_count == 2
        assert outcome.failed_count == 0
        assert outcome.merged_count == 1
        assert outcome.folded_count == 1
        assert outcome.merged[0].vuln_id == CVE_ID

    def test_paper_sources_are_skipped(self) -> None:
        """论文源不参与漏洞归一化（返回空结果，避免污染 ``unified_vuln``）。"""
        items = [make_item("arxiv", "2404.12345", {"arxiv_id": "2404.12345", "title": "t"})]
        outcome = normalize_batch(items, source="arxiv")
        assert (outcome.merged, outcome.ok_count, outcome.failed_count) == ([], 0, 0)

    def test_invalid_record_counts_as_failure(self) -> None:
        """归一化抛异常的条目计入失败但不中断整批（防御性：正常 ``RawItem`` 不会出现）。"""
        broken = SimpleNamespace(
            trace_id="t-broken",
            source="nvd",
            source_id="",
            url="",
            title=None,
            raw_text='{"cve": {"id": ""}}',
            lang=None,
            published_at=None,
        )
        good = make_item("nvd", CVE_ID, {"cve": {"id": CVE_ID, "descriptions": [{"lang": "en", "value": "d"}]}})
        outcome = normalize_batch([broken, good], source="nvd")  # type: ignore[list-item]
        assert (outcome.ok_count, outcome.failed_count, outcome.merged_count) == (1, 1, 1)


class TestOutcomeSemantics:
    """结果对象语义。"""

    def test_merge_outcome_folded_count(self) -> None:
        """``folded_count`` = 输入 - 合并后（非负）。"""
        assert MergeOutcome(input_count=3, merged_count=1, created=1, updated=0).folded_count == 2
        assert MergeOutcome(input_count=1, merged_count=1, created=0, updated=1).folded_count == 0

    def test_normalize_outcome_properties(self) -> None:
        """``NormalizeOutcome`` 的合并 / 折叠计数。"""
        vuln = UnifiedVuln(vuln_id=CVE_ID, description="d", normalized_at=utc_now())
        outcome = NormalizeOutcome(merged=[vuln], ok_count=3, failed_count=1)
        assert outcome.merged_count == 1
        assert outcome.folded_count == 2


class TestPrintStats:
    """输出门控（``--normalize`` 才打印归一化行）。"""

    def test_normalization_line_is_gated(self, capsys: pytest.CaptureFixture[str]) -> None:
        """未请求归一化时不打印归一化行。"""
        print_stats(CollectStats(source="kev", since=utc_now(), fetched=3, processed=3, created=3))
        out = capsys.readouterr().out
        assert "归一化" not in out
        assert "拉取=3" in out

    def test_paper_source_prints_skip_note(self, capsys: pytest.CaptureFixture[str]) -> None:
        """论文源在 ``--normalize`` 下打印跳过说明。"""
        print_stats(CollectStats(source="arxiv", since=utc_now(), normalize_requested=True))
        assert "跳过（论文源只落 raw_item" in capsys.readouterr().out

    def test_failure_line_prints_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        """失败时打印状态与错误原因。"""
        stats = CollectStats(source="kev", since=utc_now(), status="failed", error="HttpStatusError: 503")
        print_stats(stats)
        out = capsys.readouterr().out
        assert "[FAIL kev]" in out
        assert "HttpStatusError: 503" in out

