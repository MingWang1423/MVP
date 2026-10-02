"""数据质量路由（Day16 任务 2；PROJECT_PLAN.md §5.9 质量页数据源）。

端点：

=============================  =================================================
``GET /data-quality``          一次返回 KPI + 4 张图 + 2 份 Markdown 报告
=============================  =================================================

设计要点：

- **一次请求**：页面所有卡片 / 图表 / 报告共用一次 HTTP 往返，避免首屏瀑布；
- **口径与 P4 报告同源**：复用 :mod:`aisec_intel.services.quality_service` 的纯函数，
  ``reports.data_quality`` 与该脚本产物逐字一致（仅生成时间不同）；
- **可调采样**：``sample_limit`` 控制每源重放条数（越小越快，``truncated=true`` 表示数值为下界）；
- **进程内缓存 5 分钟**：``refresh=true`` 强制重算；
- **无副作用 / 无 LLM**：纯只读聚合（L5 服务层，见 §2.1）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from aisec_intel.api.deps import get_quality_service
from aisec_intel.api.schemas.quality import (
    DataQualityReportsDto,
    DataQualityResponse,
    SourceQualityDto,
)
from aisec_intel.api.schemas.stats import TimelinePoint
from aisec_intel.logging_config import get_logger
from aisec_intel.services.quality_service import (
    DEFAULT_SAMPLE_LIMIT,
    DEFAULT_TREND_DAYS,
    MAX_ROWS_PER_SOURCE,
    DataQualityService,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/data-quality", tags=["quality"])
"""数据质量路由（挂载后路径为 ``/api/v1/data-quality``）。"""

MAX_SAMPLE_LIMIT: int = MAX_ROWS_PER_SOURCE
"""每源重放上限（与 ``scripts/data_quality.py --limit`` 的上限一致）。"""

MAX_TREND_DAYS: int = 180
"""趋势窗口上限（保护聚合耗时）。"""


def _timeline(points: dict[object, int]) -> list[TimelinePoint]:
    """把 ``{date: count}`` 映射为按日期升序的 API 时间点列表（纯函数）。

    Args:
        points: ``bucket_by_day`` 风格的分桶结果（日期升序）。

    Returns:
        :class:`~aisec_intel.api.schemas.stats.TimelinePoint` 列表。
    """
    return [TimelinePoint(date=str(day), count=int(count)) for day, count in points.items()]


@router.get(
    "",
    response_model=DataQualityResponse,
    summary="采集数据质量（KPI / 各源明细 / 趋势 / Markdown 报告）",
)
async def get_data_quality(
    sample_limit: int = Query(
        default=DEFAULT_SAMPLE_LIMIT,
        ge=0,
        le=MAX_SAMPLE_LIMIT,
        description="每源重放条数上限（0 = 使用上限 10000）",
    ),
    trend_days: int = Query(default=DEFAULT_TREND_DAYS, ge=1, le=MAX_TREND_DAYS, description="趋势天数"),
    include_reports: bool = Query(default=True, description="是否附带 Markdown 报告原文"),
    refresh: bool = Query(default=False, description="true 时绕过 5 分钟缓存重新聚合"),
    service: DataQualityService = Depends(get_quality_service),
) -> DataQualityResponse:
    """返回数据质量页所需的全部数据。

    Args:
        sample_limit: 每源最多重放的 ``raw_item`` 条数。
        trend_days: 趋势窗口天数（含当天）。
        include_reports: 是否附带 ``reports/graph_stats.md`` 原文。
        refresh: 是否绕过缓存。
        service: 数据质量聚合服务（请求级会话）。

    Returns:
        :class:`~aisec_intel.api.schemas.quality.DataQualityResponse`。
    """
    snapshot = await service.snapshot(
        sample_limit=sample_limit,
        trend_days=trend_days,
        include_reports=include_reports,
        refresh=refresh,
    )
    summary = snapshot.summary
    return DataQualityResponse(
        enabled_source_count=snapshot.enabled_source_count,
        declared_sources=list(snapshot.declared_sources),
        missing_sources=list(summary.missing_sources),
        total_raw=summary.total_raw,
        normalized_ok=summary.normalized_ok,
        normalized_failed=summary.normalized_failed,
        normalization_success_rate=summary.success_rate,
        field_completeness=dict(summary.field_completeness),
        coverage_rate=summary.coverage_rate,
        sources=[
            SourceQualityDto(
                source=item.source,
                kind="paper" if item.kind == "paper" else "vuln",
                raw_count=item.raw_count,
                normalized_ok=item.normalized_ok,
                normalized_failed=item.normalized_failed,
                success_rate=item.success_rate,
                field_completeness={
                    name: item.completeness(name) for name in sorted(item.field_complete)
                },
            )
            for item in snapshot.sources
        ],
        trend=_timeline(snapshot.trend),
        trend_normalized=_timeline(snapshot.trend_normalized),
        trend_days=snapshot.trend_days,
        sample_limit=snapshot.sample_limit,
        truncated=snapshot.truncated,
        reports=(
            DataQualityReportsDto(
                data_quality=snapshot.markdown,
                graph_stats=snapshot.graph_stats_markdown,
            )
            if include_reports
            else None
        ),
        generated_at=snapshot.generated_at,
    )
