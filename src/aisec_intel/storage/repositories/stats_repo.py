"""首页仪表盘的统计聚合仓储（Day14 任务 6；PROJECT_PLAN.md §5.9 前端数据源）。

本模块只做**只读聚合**，不写入任何数据；聚合口径全部为确定性 SQL / 纯函数，
便于单测（SQLite 内存库）与 PG 上语义一致。

口径定义（前端 KPI 卡片与图表直接消费）：

===========================  ====================================================
``total``                     ``unified_vuln`` 总行数（漏洞事实总数）
``count_by_severity``         事实层 ``severity`` 分组（**小写**键；未定级归 ``unknown``）
``count_by_source``           ``sources`` JSON 数组展开后的来源条数（小写键，按条数倒序）
``count_since``               入库时间不早于给定时刻的条数（``published_at`` 优先，
                              缺省回退 ``normalized_at``）
``daily_counts``              按 UTC 日期分桶的披露 / 入库趋势（区间内缺失日期补 0）
``list_recent_high_risk``     最近的高危条目（``severity ∈ {CRITICAL, HIGH}``），供仪表盘表格
===========================  ====================================================

Note:
    与 :class:`~aisec_intel.storage.repositories.vuln_repo.VulnRepository` 分离，是为了让
    「写路径仓储」与「只读聚合」各自可独立演进（聚合 SQL 变更不影响采集 / 富化写入）。
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from aisec_intel.models.base import to_utc, utc_now
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.models.enriched import EnrichedVulnRow
from aisec_intel.storage.models.vuln import UnifiedVulnRow

SEVERITY_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low")
"""风险分布的固定键顺序（前端饼图配色与图例顺序依赖该顺序）。"""

UNKNOWN_SEVERITY: str = "unknown"
"""事实层 ``severity`` 为空时的归类键（NVD 之外的源常缺该字段，不应丢弃）。"""

HIGH_RISK_LEVELS: tuple[str, ...] = ("CRITICAL", "HIGH")
"""仪表盘「高危」口径（事实层严重度，与 ``Severity`` 枚举取值一致）。"""


@dataclass(frozen=True, slots=True)
class HighRiskRow:
    """高危清单的一行：事实层实体 + 可选富化风险分（左连接结果）。

    Attributes:
        vuln: 事实层实体。
        risk_score: 富化风险分；未富化时为 ``None``。
        risk_level: 富化风险级别；未富化时为 ``None``。
    """

    vuln: UnifiedVuln
    risk_score: float | None = None
    risk_level: str | None = None



def count_by_source_values(rows: Iterable[Sequence[str] | None]) -> dict[str, int]:
    """统计各数据源的贡献条数（纯函数）。

    Args:
        rows: 每行的 ``sources`` 数组（``None`` / 空数组按「无来源」处理，不计入任何键）。

    Returns:
        ``{source: count}``，按「条数倒序 → 源名升序」稳定排序（前端图例顺序确定性）。

    Examples:
        >>> count_by_source_values([["nvd", "kev"], ["NVD"], ["osv"]])
        {'nvd': 2, 'kev': 1, 'osv': 1}
    """
    counter: Counter[str] = Counter()
    for sources in rows:
        for item in sources or []:
            name = str(item).strip().lower()
            if name:
                counter[name] += 1
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))


def bucket_by_day(
    values: Iterable[datetime | None],
    *,
    since: datetime,
    until: datetime,
) -> dict[date, int]:
    """把时间点按 **UTC 日期** 分桶（纯函数），区间内缺失日期补 0。

    Args:
        values: 待分桶的时间点（``None`` 跳过；naive 时间按 UTC 解释，见
            :func:`aisec_intel.models.base.to_utc`）。
        since: 区间起点（含）。
        until: 区间终点（含）。

    Returns:
        ``{date: count}``，按日期升序且**连续**（前端折线图无需自行补点）。

    Examples:
        >>> from datetime import UTC
        >>> bucket_by_day(
        ...     [datetime(2024, 1, 2, 3, tzinfo=UTC), datetime(2024, 1, 2, 5, tzinfo=UTC)],
        ...     since=datetime(2024, 1, 1, tzinfo=UTC),
        ...     until=datetime(2024, 1, 3, tzinfo=UTC),
        ... )
        {datetime.date(2024, 1, 1): 0, datetime.date(2024, 1, 2): 2, datetime.date(2024, 1, 3): 0}
    """
    start = to_utc(since).date()
    end = to_utc(until).date()
    if end < start:
        return {}
    buckets: dict[date, int] = {
        start + timedelta(days=offset): 0 for offset in range((end - start).days + 1)
    }
    for value in values:
        if value is None:
            continue
        day = to_utc(value).date()
        if day in buckets:
            buckets[day] += 1
    return buckets


def normalize_severity_counts(counts: dict[str | None, int]) -> dict[str, int]:
    """把「原始 severity 分组」规整为前端可用的小写分布（纯函数）。

    Args:
        counts: ``{severity: count}``，``severity`` 可为 ``None``（未定级）或任意大小写。

    Returns:
        ``{level: count}``：四个固定键（``critical`` / ``high`` / ``medium`` / ``low``）恒存在，
        未定级条数在非零时以 ``unknown`` 追加在末尾。
    """
    merged: dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
    unknown = 0
    for key, value in counts.items():
        name = (key or "").strip().lower()
        if name in merged:
            merged[name] += int(value)
        elif name:
            merged[name] = merged.get(name, 0) + int(value)
        else:
            unknown += int(value)
    if unknown:
        merged[UNKNOWN_SEVERITY] = unknown
    return merged


class StatsRepository:
    """只读聚合仓储：``unified_vuln`` 的规模 / 分布 / 趋势 + 高危清单。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    @staticmethod
    def _timeline_column() -> ColumnElement[datetime | None]:
        """返回「时间轴」表达式：``published_at`` 优先，为空回退 ``normalized_at``。

        Returns:
            供 ``where`` / ``order_by`` 复用的 SQLAlchemy 表达式。
        """
        return func.coalesce(UnifiedVulnRow.published_at, UnifiedVulnRow.normalized_at)

    async def total(self) -> int:
        """返回漏洞事实总条数。

        Returns:
            ``unified_vuln`` 行数。
        """
        await self._session.flush()
        stmt = select(func.count()).select_from(UnifiedVulnRow)
        return int((await self._session.execute(stmt)).scalar() or 0)

    async def count_since(self, since: datetime) -> int:
        """返回「时间轴不早于 ``since``」的条数（近 N 小时 / 近 N 天增量、今日新增）。

        Args:
            since: 起始时刻（UTC）。

        Returns:
            命中条数。
        """
        await self._session.flush()
        stmt = (
            select(func.count()).select_from(UnifiedVulnRow).where(self._timeline_column() >= since)
        )
        return int((await self._session.execute(stmt)).scalar() or 0)

    async def count_by_severity(self) -> dict[str, int]:
        """按事实层 ``severity`` 分组统计（键为小写，未定级归 ``unknown``）。

        Returns:
            ``{level: count}``，见 :func:`normalize_severity_counts`。
        """
        await self._session.flush()
        stmt = select(UnifiedVulnRow.severity, func.count()).group_by(UnifiedVulnRow.severity)
        rows = (await self._session.execute(stmt)).all()
        return normalize_severity_counts({row[0]: int(row[1]) for row in rows})

    async def count_by_source(self) -> dict[str, int]:
        """按 ``sources`` JSON 数组展开统计各源贡献条数。

        Note:
            在 Python 侧做展开（纯函数），而不用 PG 的 ``json_array_elements_text``，
            以保证与 SQLite（单测）语义一致。

        Returns:
            ``{source: count}``，按条数倒序。
        """
        await self._session.flush()
        stmt = select(UnifiedVulnRow.sources)
        rows = (await self._session.execute(stmt)).scalars().all()
        return count_by_source_values(rows)

    async def daily_counts(self, *, days: int = 30, now: datetime | None = None) -> dict[date, int]:
        """返回最近 ``days`` 天（含当天）按 UTC 日期分桶的趋势。

        Args:
            days: 天数窗口（含当天），``>= 1``。
            now: 基准时刻；缺省取 :func:`aisec_intel.models.base.utc_now`（测试可注入）。

        Returns:
            ``{date: count}``：日期连续升序（缺失日补 0），末尾为当天。
        """
        await self._session.flush()
        anchor = to_utc(now or utc_now())
        end = datetime.combine(anchor.date(), time.min, tzinfo=anchor.tzinfo)
        start = end - timedelta(days=max(1, days) - 1)
        stmt = select(self._timeline_column()).where(self._timeline_column() >= start)
        values = [row[0] for row in (await self._session.execute(stmt)).all()]
        return bucket_by_day(values, since=start, until=end)

    async def list_recent_high_risk(
        self,
        *,
        levels: Sequence[str] = HIGH_RISK_LEVELS,
        limit: int = 10,
    ) -> list[HighRiskRow]:
        """返回最近的高危漏洞（仪表盘底部表格数据源）。

        左连接 ``enriched_vuln`` 一并取出富化风险分，避免前端表格出现 N+1 请求。

        Args:
            levels: 严重度白名单（默认 ``CRITICAL`` / ``HIGH``，大小写不敏感）。
            limit: 返回条数上限（``<= 0`` 时返回空列表）。

        Returns:
            :class:`HighRiskRow` 列表，按时间轴倒序。
        """
        await self._session.flush()
        keys = [item.strip().upper() for item in levels if item.strip()]
        if not keys or limit <= 0:
            return []
        stmt = (
            select(UnifiedVulnRow, EnrichedVulnRow.risk_score, EnrichedVulnRow.risk_level)
            .outerjoin(EnrichedVulnRow, EnrichedVulnRow.vuln_id == UnifiedVulnRow.vuln_id)
            .where(UnifiedVulnRow.severity.in_(keys))
            .order_by(self._timeline_column().desc())
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).all()
        return [
            HighRiskRow(vuln=row[0].to_domain(), risk_score=row[1], risk_level=row[2])
            for row in rows
        ]


__all__ = [
    "HIGH_RISK_LEVELS",
    "SEVERITY_LEVELS",
    "UNKNOWN_SEVERITY",
    "HighRiskRow",
    "StatsRepository",
    "bucket_by_day",
    "count_by_source_values",
    "normalize_severity_counts",
]
