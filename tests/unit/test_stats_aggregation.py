"""Day14 任务 6：仪表盘统计的**纯函数**单测（``storage/repositories/stats_repo.py``）。

覆盖三个确定性算法：

1. :func:`~aisec_intel.storage.repositories.stats_repo.bucket_by_day`（日期分桶补 0）；
2. :func:`~aisec_intel.storage.repositories.stats_repo.count_by_source_values`（来源展开统计）；
3. :func:`~aisec_intel.storage.repositories.stats_repo.normalize_severity_counts`（严重度规整）。

这些函数是前端饼图 / 柱图 / 折线图的口径来源，改动即影响页面数字，故必须锁定行为。
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from aisec_intel.storage.repositories.stats_repo import (
    bucket_by_day,
    count_by_source_values,
    normalize_severity_counts,
)

UTC_DAY_START = datetime(2024, 1, 1, tzinfo=UTC)


class TestBucketByDay:
    """``bucket_by_day``：UTC 日期分桶 + 缺失日补 0。"""

    def test_fills_missing_days_and_keeps_order(self) -> None:
        """区间内每个日期都出现（``until`` 为闭区间），缺失日补 0，顺序为日期升序。"""
        buckets = bucket_by_day(
            [datetime(2024, 1, 2, 23, 59, tzinfo=UTC), datetime(2024, 1, 2, 0, 1, tzinfo=UTC)],
            since=UTC_DAY_START,
            until=datetime(2024, 1, 3, tzinfo=UTC),
        )
        assert list(buckets) == [date(2024, 1, 1), date(2024, 1, 2), date(2024, 1, 3)]
        assert buckets[date(2024, 1, 1)] == 0
        assert buckets[date(2024, 1, 2)] == 2
        assert buckets[date(2024, 1, 3)] == 0

    def test_ignores_none_and_out_of_range(self) -> None:
        """``None`` 与区间外的时间点被忽略，不进入任何桶。"""
        buckets = bucket_by_day(
            [None, datetime(2023, 12, 31, 23, 59, tzinfo=UTC), datetime(2024, 1, 5, tzinfo=UTC)],
            since=UTC_DAY_START,
            until=datetime(2024, 1, 2, tzinfo=UTC),
        )
        assert sum(buckets.values()) == 0
        assert len(buckets) == 2

    def test_naive_datetime_treated_as_utc(self) -> None:
        """naive 时间按 UTC 解释（与 ``models.base.to_utc`` 口径一致）。"""
        buckets = bucket_by_day(
            [datetime(2024, 1, 2, 8, 0)],
            since=UTC_DAY_START,
            until=datetime(2024, 1, 2, tzinfo=UTC),
        )
        assert buckets[date(2024, 1, 2)] == 1

    def test_non_utc_timezone_converted(self) -> None:
        """带时区的时间先换算到 UTC 再落桶（东八区 08:00 属于 UTC 前一日）。"""
        from datetime import timedelta, timezone

        buckets = bucket_by_day(
            [datetime(2024, 1, 2, 7, 0, tzinfo=timezone(timedelta(hours=8)))],
            since=UTC_DAY_START,
            until=datetime(2024, 1, 2, tzinfo=UTC),
        )
        assert buckets[date(2024, 1, 1)] == 1
        assert buckets[date(2024, 1, 2)] == 0

    def test_reversed_range_returns_empty(self) -> None:
        """``until < since`` 时返回空字典（不抛异常，避免页面 500）。"""
        assert bucket_by_day([], since=datetime(2024, 1, 3, tzinfo=UTC), until=UTC_DAY_START) == {}


class TestCountBySourceValues:
    """``count_by_source_values``：来源展开统计。"""

    def test_counts_lowercased_and_sorted_by_count(self) -> None:
        """大小写归一化后计数，按「条数倒序 → 名称升序」排序。"""
        counts = count_by_source_values([["nvd", "kev"], ["NVD"], ["osv"], ["kev"]])
        assert counts == {"nvd": 2, "kev": 2, "osv": 1}

    def test_handles_none_and_blank_items(self) -> None:
        """``None`` 行、空字符串与空白项都不计入。"""
        assert count_by_source_values([None, [], ["  ", "OSV "]]) == {"osv": 1}

    def test_empty_input(self) -> None:
        """无数据时返回空字典（前端柱图渲染空态）。"""
        assert count_by_source_values([]) == {}


class TestNormalizeSeverityCounts:
    """``normalize_severity_counts``：严重度分布规整。"""

    def test_fixed_keys_always_present(self) -> None:
        """四个固定键恒存在（即使计数为 0），保证前端配色映射稳定。"""
        counts = normalize_severity_counts({"CRITICAL": 3})
        assert counts == {"critical": 3, "high": 0, "medium": 0, "low": 0}

    def test_none_severity_bucketed_as_unknown(self) -> None:
        """未定级条数归入 ``unknown`` 并追加在末尾。"""
        counts = normalize_severity_counts({None: 7, "high": 2})
        assert list(counts) == ["critical", "high", "medium", "low", "unknown"]
        assert counts["unknown"] == 7 and counts["high"] == 2

    def test_zero_unknown_omitted(self) -> None:
        """未定级为 0 时不出现 ``unknown`` 键（前端图例不显示空项）。"""
        assert "unknown" not in normalize_severity_counts({})
