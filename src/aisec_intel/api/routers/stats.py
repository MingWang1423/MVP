"""首页仪表盘统计路由（Day14 任务 6；PROJECT_PLAN.md §5.9 前端数据源）。

端点：

=============================  ====================================================
``GET /stats``                 一次返回首页所需的 KPI + 两张分布 + 一张趋势 + 高危清单
=============================  ====================================================

设计说明：

- **单一请求**：仪表盘 4 个 KPI + 3 张图 + 1 张表共用一次 HTTP 往返，避免首屏瀑布；
- **口径集中在仓储层**：本路由只做参数编排与 DTO 装配，不改写任何统计语义；
- **无副作用 / 无 LLM**：纯只读聚合（L5 服务层，禁止 LLM，见 §2.1）。
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Query

from aisec_intel.api.deps import get_source_repo, get_stats_repo
from aisec_intel.api.schemas.stats import StatsResponse, TimelinePoint
from aisec_intel.api.schemas.vuln import VulnSummary
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import utc_now
from aisec_intel.storage.repositories.source_repo import SourceRepository
from aisec_intel.storage.repositories.stats_repo import StatsRepository

logger = get_logger(__name__)

router = APIRouter(prefix="/stats", tags=["stats"])
"""统计路由（挂载后路径为 ``/api/v1/stats``）。"""

TODAY_WINDOW_HOURS: int = 24
"""``today_new`` 的滚动窗口（小时）。

不用「UTC 当日零点」是因为全量重跑会把 ``normalized_at`` 刷成当天，
「今日新增」会退化成 ≈ 总量；滚动 24 小时窗口对运维更有信息量。
"""

MAX_HIGH_RISK_ROWS: int = 50
"""高危清单单次返回上限（默认 10，防止前端意外拉全库）。"""


@router.get(
    "",
    response_model=StatsResponse,
    summary="首页仪表盘统计（KPI / 分布 / 趋势 / 高危清单）",
)
async def get_stats(
    timeline_days: int = Query(default=30, ge=1, le=365, description="趋势窗口天数（含当天）"),
    high_risk_limit: int = Query(default=10, ge=1, le=MAX_HIGH_RISK_ROWS, description="高危清单条数"),
    repo: StatsRepository = Depends(get_stats_repo),
    sources: SourceRepository = Depends(get_source_repo),
) -> StatsResponse:
    """返回仪表盘所需的全部聚合数据。

    Args:
        timeline_days: 趋势窗口天数（含当天，缺失日期补 0）。
        high_risk_limit: 底部「最近高危漏洞」表格条数。
        repo: 统计聚合仓储（请求级会话）。
        sources: 采集源登记仓储（请求级会话，用于「数据源」KPI）。

    Returns:
        :class:`~aisec_intel.api.schemas.stats.StatsResponse`。
    """
    now = utc_now()
    total = await repo.total()
    severity_counts = await repo.count_by_severity()
    source_counts = await repo.count_by_source()
    today_new = await repo.count_since(now - timedelta(hours=TODAY_WINDOW_HOURS))
    daily = await repo.daily_counts(days=timeline_days, now=now)
    high_risk = await repo.list_recent_high_risk(limit=high_risk_limit)
    source_count = await sources.count(enabled_only=True)

    logger.info(
        f"仪表盘统计：总数={total} 高危={severity_counts.get('critical', 0)} "
        f"源={source_count} 近{TODAY_WINDOW_HOURS}h新增={today_new} 趋势={len(daily)}天"
    )
    return StatsResponse(
        total_vulns=total,
        critical_count=severity_counts.get("critical", 0),
        source_count=source_count,
        today_new=today_new,
        risk_distribution=severity_counts,
        source_distribution=source_counts,
        timeline=[TimelinePoint(date=day, count=count) for day, count in daily.items()],
        top_high_risk=[
            VulnSummary.from_unified(
                row.vuln,
                (row.risk_score, row.risk_level)
                if row.risk_score is not None and row.risk_level is not None
                else None,
            )
            for row in high_risk
        ],
        generated_at=now,
    )
