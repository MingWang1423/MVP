"""Day16 任务 2：数据质量聚合的**纯函数**单测（``services/quality_service.py``）。

覆盖（全部不依赖数据库 / 网络 / LLM）：

1. :func:`~aisec_intel.services.quality_service.summarize` 的汇总口径
   （总量 / 成功率 / 全局完整率 / 源覆盖率 / 缺失源）；
2. :class:`~aisec_intel.services.quality_service.SnapshotCache` 的 TTL 行为（注入时钟）；
3. :meth:`~aisec_intel.services.quality_service.DataQualityService.cache_key` 的稳定性；
4. :func:`~aisec_intel.services.quality_service.render_markdown` 的抬头与合计口径。

这些数字直接决定质量页 KPI 与 P4 报告，改动即影响交付物，故必须锁定行为。
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from aisec_intel.services.quality_service import (
    FIELD_NAMES,
    DataQualityService,
    DataQualitySnapshot,
    QualitySummary,
    SnapshotCache,
    SourceQuality,
    render_markdown,
    summarize,
)

NOW = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)


def make_quality(
    source: str,
    *,
    kind: str = "vuln",
    raw_count: int = 100,
    ok: int = 100,
    failed: int = 0,
    hits: dict[str, int] | None = None,
) -> SourceQuality:
    """构造单源指标（纯数据，供汇总测试使用）。

    Args:
        source: 源标识。
        kind: ``vuln`` / ``paper``。
        raw_count: 采集条数。
        ok: 归一化成功条数。
        failed: 归一化失败条数。
        hits: 字段命中数；``None`` 时四字段全命中 ``ok``。

    Returns:
        :class:`SourceQuality`。
    """
    return SourceQuality(
        source=source,
        kind=kind,
        raw_count=raw_count,
        normalized_ok=ok,
        normalized_failed=failed,
        field_complete=hits if hits is not None else dict.fromkeys(FIELD_NAMES, ok),
    )


def make_snapshot(summary: QualitySummary) -> DataQualitySnapshot:
    """构造最小可用快照（仅用于缓存测试，字段值无关紧要）。

    Args:
        summary: 全局汇总指标。

    Returns:
        :class:`DataQualitySnapshot`。
    """
    return DataQualitySnapshot(
        summary=summary,
        sources=(),
        declared_sources=(),
        enabled_source_count=0,
        trend={date(2026, 10, 2): 1},
        trend_normalized={},
        sample_limit=1000,
        trend_days=30,
        truncated=False,
        markdown="# 采集数据质量报告（P4）\n",
        graph_stats_markdown=None,
        generated_at=NOW,
    )


class TestSummarize:
    """``summarize``：全局 KPI 与覆盖率。"""

    def test_totals_rates_and_coverage(self) -> None:
        """总量求和、成功率按成功 / 尝试计算、覆盖率按声明源计算。"""
        qualities = [
            make_quality("nvd", raw_count=200, ok=90, failed=10),
            make_quality("kev", raw_count=50, ok=50),
        ]
        summary = summarize(qualities, declared=["nvd", "kev", "arxiv"])
        assert isinstance(summary, QualitySummary)
        assert summary.total_raw == 250
        assert summary.normalized_ok == 140
        assert summary.normalized_failed == 10
        assert summary.success_rate == 140 / 150
        assert summary.coverage_rate == 2 / 3
        assert summary.with_data_sources == ("nvd", "kev")
        assert summary.missing_sources == ("arxiv",)

    def test_field_completeness_uses_global_denominator(self) -> None:
        """全局完整率的分母是「成功条数合计」，不是「采集条数合计」。"""
        qualities = [
            make_quality("nvd", raw_count=100, ok=50, hits={"description": 50, "cvss": 25}),
            make_quality("osv", raw_count=100, ok=50, hits={"description": 50, "cvss": 50}),
        ]
        summary = summarize(qualities, declared=["nvd", "osv"])
        assert summary.field_completeness["description"] == 1.0
        assert summary.field_completeness["cvss"] == 75 / 100
        assert summary.field_completeness["cwe"] == 0.0

    def test_empty_input_is_safe(self) -> None:
        """无任何源时不抛异常，全部指标为 0。"""
        summary = summarize([], declared=["nvd"])
        assert summary.total_raw == 0
        assert summary.success_rate == 0.0
        assert summary.coverage_rate == 0.0
        assert summary.missing_sources == ("nvd",)
        assert set(summary.field_completeness) == set(FIELD_NAMES)

    def test_zero_data_source_counts_as_missing(self) -> None:
        """采集条数为 0 的源算「缺数据」（前端据此提示采集缺口）。"""
        summary = summarize([make_quality("nvd", raw_count=0, ok=0)], declared=["nvd"])
        assert summary.with_data_sources == ()
        assert summary.missing_sources == ("nvd",)


class FakeClock:
    """可手工推进的单调时钟（替代 ``time.monotonic``）。"""

    def __init__(self) -> None:
        """从 0 开始计时。"""
        self.now = 0.0

    def __call__(self) -> float:
        """返回当前值。

        Returns:
            单调递增的秒数。
        """
        return self.now


class TestSnapshotCache:
    """``SnapshotCache``：TTL 命中 / 过期 / 清空。"""

    def test_hits_before_ttl_and_expires_after(self) -> None:
        """TTL 内命中缓存，超时后返回 ``None`` 并清理条目。"""
        clock = FakeClock()
        cache = SnapshotCache(ttl_s=60.0, clock=clock)
        snapshot = make_snapshot(summarize([], declared=[]))
        cache.put(("k",), snapshot)
        assert cache.get(("k",)) is snapshot
        clock.now = 59.9
        assert cache.get(("k",)) is snapshot
        clock.now = 60.0
        assert cache.get(("k",)) is None
        assert cache.get(("k",)) is None

    def test_clear_removes_all_entries(self) -> None:
        """``clear()`` 后所有键失效（运维强制刷新路径）。"""
        cache = SnapshotCache(ttl_s=600.0, clock=FakeClock())
        cache.put(("a",), make_snapshot(summarize([], declared=[])))
        cache.clear()
        assert cache.get(("a",)) is None


class TestCacheKey:
    """``DataQualityService.cache_key``：参数变化必须产生不同键。"""

    def test_stable_and_parameter_sensitive(self) -> None:
        """同参同键；``sample_limit`` / ``trend_days`` / ``include_reports`` 任一变化换键。"""
        key = DataQualityService.cache_key(1000, 30, True)
        assert key == DataQualityService.cache_key(1000, 30, True)
        assert key != DataQualityService.cache_key(500, 30, True)
        assert key != DataQualityService.cache_key(1000, 7, True)
        assert key != DataQualityService.cache_key(1000, 30, False)


class TestRenderMarkdownSampleLimit:
    """``render_markdown``：采样上限与合计写入报告（可复现性要求）。"""

    def test_limit_window_and_totals_are_rendered(self) -> None:
        """抬头写明窗口与上限，合计行给出总量与失败数，并提示缺失源。"""
        qualities = [make_quality("nvd", raw_count=10, ok=8, failed=2)]
        text = render_markdown(
            qualities,
            declared=["nvd", "kev"],
            since=None,
            generated_at=NOW,
            limit=500,
        )
        assert "每源读取上限=500" in text
        assert "since=全量（不限时间）" in text
        assert "| **合计** | — | 10 | 8 | 2 | — |" in text
        assert "以下启用源当前无数据" in text
        assert text.endswith("\n")

    def test_all_sources_have_data(self) -> None:
        """全部声明源都有数据时给出 ✅ 结论（与 P4 报告一致）。"""
        text = render_markdown(
            [make_quality("nvd")],
            declared=["nvd"],
            since=NOW,
            generated_at=NOW,
        )
        assert "所有声明的启用源均已有数据" in text
        assert "源覆盖率：100.0%" in text
