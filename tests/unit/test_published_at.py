"""发布时间口径测试（Day26；PROJECT_PLAN.md §12.22 / §10.1 时间口径）。

回归目标：``UnifiedVuln.published_at`` 只能来自**源侧**字段，**不允许**用入库时间
（``normalized_at``）或采集时间（``fetched_at``）冒充；EPSS 的模型评分日期归 ``modified_at``；
API 列表条目（``VulnSummary``）不再做 ``published_at or normalized_at`` 兜底。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.api.schemas.vuln import VulnSummary
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.pipeline import (
    NO_PUBLISHED_AT_SOURCES,
    build_unified_vuln,
    extract_published_at,
    lookup_field,
)

FETCHED_AT = datetime(2026, 10, 7, 8, 0, tzinfo=UTC)
"""采集时间（入库前）：若它出现在 ``published_at`` 上即为回归失败。"""
NORMALIZED_AT = datetime(2026, 10, 7, 9, 0, tzinfo=UTC)
"""归一化 / 入库时间：与 ``published_at`` 语义独立。"""


def make_raw(
    source: str,
    payload: dict[str, Any] | str,
    *,
    source_id: str = "CVE-2024-3400",
    published_at: datetime | None = None,
) -> RawItem:
    """由源侧条目构造 ``RawItem``（等价于采集器输出）。

    Args:
        source: 源标识。
        payload: 条目级载荷（``dict`` 会被序列化为 JSON 文本）。
        source_id: 源内唯一 ID。
        published_at: 采集器自身映射出的源侧发布时间（可为 ``None``）。

    Returns:
        ``RawItem``（``fetched_at`` 固定为 ``FETCHED_AT``）。
    """
    raw_text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return RawItem(
        trace_id="trace-published-at-0001",
        source=source,
        source_id=source_id,
        url="https://example.test/advisory",
        title=None,
        raw_text=raw_text,
        fetched_at=FETCHED_AT,
        published_at=published_at,
        sha256="c" * 64,
    )


class TestExtractPublishedAt:
    """源侧发布时间抽取（纯函数）。"""

    def test_nvd_nested_cve_published(self) -> None:
        """NVD：取嵌套的 ``cve.published``。"""
        raw = make_raw("nvd", {"cve": {"id": "CVE-2024-3400", "published": "2024-04-12T20:15:00.000Z"}})
        assert extract_published_at(raw) == datetime(2024, 4, 12, 20, 15, tzinfo=UTC)

    def test_kev_date_added(self) -> None:
        """KEV：``dateAdded`` 即「加入已知被利用目录」日期。"""
        raw = make_raw("kev", {"cveID": "CVE-2024-3400", "dateAdded": "2024-04-12"})
        assert extract_published_at(raw) == datetime(2024, 4, 12, tzinfo=UTC)

    def test_ghsa_published_at(self) -> None:
        """GHSA：``publishedAt``。"""
        raw = make_raw("ghsa", {"ghsaId": "GHSA-2qrp-3j2c-6v3x", "publishedAt": "2024-05-02T10:30:00Z"})
        assert extract_published_at(raw) == datetime(2024, 5, 2, 10, 30, tzinfo=UTC)

    def test_osv_published(self) -> None:
        """OSV：``published``。"""
        raw = make_raw("osv", {"id": "GHSA-3hjh-jh2g-v3gj", "published": "2024-04-01T00:00:00Z"})
        assert extract_published_at(raw) == datetime(2024, 4, 1, tzinfo=UTC)

    def test_vendor_github_nested_advisory(self) -> None:
        """厂商 GitHub 公告：优先嵌套的 ``advisory.publishedAt``。"""
        payload = {"advisory": {"publishedAt": "2024-06-11T09:00:00Z"}, "publishedAt": "2024-06-20T00:00:00Z"}
        assert extract_published_at(make_raw("vendor_github", payload)) == datetime(2024, 6, 11, 9, 0, tzinfo=UTC)

    def test_rss_blog_pub_date(self) -> None:
        """RSS 博客：``published`` / ``pubDate`` 均可命中。"""
        payload = {"title": "post", "pubDate": "Tue, 02 Apr 2024 00:00:00 GMT", "published": "2024-04-02T00:00:00Z"}
        assert extract_published_at(make_raw("rss_blog", payload)) == datetime(2024, 4, 2, tzinfo=UTC)

    def test_unknown_source_uses_generic_keys(self) -> None:
        """未知源：走通用键（``publication_date``），不依赖源特有路径。"""
        assert extract_published_at(make_raw("arxiv", {"publication_date": "2024-03-05"})) == datetime(
            2024, 3, 5, tzinfo=UTC
        )

    def test_source_argument_overrides_raw_source(self) -> None:
        """``source`` 入参优先于 ``raw.source``（供调用方显式指定口径）。"""
        raw = make_raw("unknown", {"dateAdded": "2024-04-12"})
        assert extract_published_at(raw, source="kev") == datetime(2024, 4, 12, tzinfo=UTC)

    def test_epss_model_date_is_not_published_at(self) -> None:
        """EPSS：``date`` 是模型评分日期 → 恒返回 ``None``。"""
        raw = make_raw("epss", {"cve": "CVE-2024-3400", "date": "2024-04-15", "epss": "0.97432"})
        assert extract_published_at(raw) is None
        assert "epss" in NO_PUBLISHED_AT_SOURCES

    def test_falls_back_to_raw_published_at(self) -> None:
        """载荷里没有时间字段时，使用采集件上的 ``published_at``（仍是源侧时间）。"""
        raw = make_raw("nvd", {"cve": {"id": "CVE-2024-3400"}}, published_at=datetime(2024, 4, 12, tzinfo=UTC))
        assert extract_published_at(raw) == datetime(2024, 4, 12, tzinfo=UTC)

    def test_missing_is_none_never_ingestion_time(self) -> None:
        """**核心回归**：源未提供发布时间时返回 ``None``，绝不用 ``fetched_at`` 顶替。"""
        raw = make_raw("osv", {"id": "OSV-2024-1", "summary": "no timestamps here"})
        assert extract_published_at(raw) is None

    @pytest.mark.parametrize("value", [{"nested": 1}, True, False, "not-a-date", "", []])
    def test_invalid_values_are_ignored(self, value: Any) -> None:
        """非法 / 非时间类型的字段值被忽略（随后继续尝试下一优先级，最终 ``None``）。"""
        raw = make_raw("nvd", {"cve": {"id": "CVE-2024-3400", "published": value}})
        assert extract_published_at(raw) is None


class TestLookupField:
    """通用点分路径取值助手。"""

    def test_nested_hit(self) -> None:
        """命中嵌套路径。"""
        assert lookup_field({"cve": {"published": "2024-04-12"}}, "cve.published") == "2024-04-12"

    def test_top_level_hit(self) -> None:
        """命中顶层路径。"""
        assert lookup_field({"published": "x"}, "published") == "x"

    def test_miss_returns_none(self) -> None:
        """任一层缺失 / 中间层不是字典 → 返回 ``None``。"""
        assert lookup_field({"cve": {}}, "cve.published") is None
        assert lookup_field({"cve": "not-a-dict"}, "cve.published") is None
        assert lookup_field({}, "published") is None


class TestUnifiedVulnTimestamps:
    """``build_unified_vuln`` 的时间字段口径。"""

    def test_published_at_kept_and_independent(self) -> None:
        """有源侧发布时间：``published_at`` 与 ``normalized_at`` 各司其职。"""
        raw = make_raw("nvd", {"cve": {"id": "CVE-2024-3400", "published": "2024-04-12T20:15:00.000Z"}})
        vuln = build_unified_vuln(raw, normalized_at=NORMALIZED_AT)
        assert vuln.published_at == datetime(2024, 4, 12, 20, 15, tzinfo=UTC)
        assert vuln.normalized_at == NORMALIZED_AT

    def test_missing_published_at_is_none(self) -> None:
        """无源侧发布时间：``published_at`` 为 ``None``，``normalized_at`` 不被借用。"""
        vuln = build_unified_vuln(make_raw("osv", {"id": "OSV-2024-2", "details": "x"}), normalized_at=NORMALIZED_AT)
        assert vuln.published_at is None
        assert vuln.normalized_at == NORMALIZED_AT
        assert vuln.modified_at is None

    def test_epss_model_date_lands_in_modified_at(self) -> None:
        """EPSS：模型日期落到 ``modified_at``，``published_at`` 保持 ``None``。"""
        row = {"cve": "CVE-2024-3400", "date": "2024-04-15", "epss": "0.97432", "percentile": "0.99912"}
        vuln = build_unified_vuln(make_raw("epss", row), normalized_at=NORMALIZED_AT)
        assert vuln.published_at is None
        assert vuln.modified_at == datetime(2024, 4, 15, tzinfo=UTC)


class TestVulnSummaryTimestamp:
    """API 列表条目不再用入库时间兜底（Day26 根因回归）。"""

    def test_missing_published_at_stays_none(self) -> None:
        """``VulnSummary.from_unified`` 原样透传 ``None``（此前会回退 ``normalized_at``）。"""
        vuln = build_unified_vuln(make_raw("osv", {"id": "OSV-2024-3", "details": "x"}), normalized_at=NORMALIZED_AT)
        summary = VulnSummary.from_unified(vuln)
        assert summary.published_at is None

    def test_present_published_at_is_forwarded(self) -> None:
        """有源侧发布时间时原样透传。"""
        raw = make_raw("nvd", {"cve": {"id": "CVE-2024-3400", "published": "2024-04-12T00:00:00Z"}})
        vuln = build_unified_vuln(raw, normalized_at=NORMALIZED_AT)
        summary = VulnSummary.from_unified(vuln)
        assert summary.published_at == datetime(2024, 4, 12, tzinfo=UTC)