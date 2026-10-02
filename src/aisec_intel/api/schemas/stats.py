"""仪表盘统计 API 的数据传输契约（Day14 任务 6；PROJECT_PLAN.md §5.9 前端数据源）。

``GET /api/v1/stats`` 一次返回首页所需的全部聚合数据，避免前端并发多次请求：

- 4 个 KPI：``total_vulns`` / ``critical_count`` / ``source_count`` / ``today_new``；
- 2 个分布：``risk_distribution``（饼图）、``source_distribution``（柱图）；
- 1 个趋势：``timeline``（近 N 天折线图，日期连续已补 0）；
- 1 个清单：``top_high_risk``（底部高危表格，复用 :class:`VulnSummary`）。

口径说明（与 ``storage/repositories/stats_repo.py`` 严格一致）：

- ``today_new``：**近 24 小时**新增（`published_at` 优先、回退 `normalized_at`）。
  之所以不用「UTC 当日零点」，是因为全量重跑会把 ``normalized_at`` 刷成当天，
  导致「今日新增 ≈ 总量」的失真数字；滚动 24 小时窗口对运维更有意义。
- ``risk_distribution``：事实层 ``severity`` 分布（键恒含 ``critical`` / ``high`` /
  ``medium`` / ``low``；未定级追加 ``unknown``）。富化 ``risk_level`` 当前覆盖率低，
  不用于这张饼图。
- ``source_count``：``source`` 表中**已启用**的采集源数量（登记口径，非贡献口径）；
  ``source_distribution`` 才是各源实际贡献条数。
"""

from __future__ import annotations

import datetime as dt

from pydantic import ConfigDict, Field

from aisec_intel.api.schemas.vuln import VulnSummary
from aisec_intel.models.base import IntelBaseModel, UTCDateTime


class TimelinePoint(IntelBaseModel):
    """披露 / 入库趋势上的一个数据点（折线图 X-Y 对）。

    Attributes:
        date: UTC 日期（JSON 序列化为 ``YYYY-MM-DD``）。
        count: 当日条数。
    """

    model_config = ConfigDict(extra="forbid")

    # 字段名 ``date`` 与 ``datetime.date`` 同名，故类型用模块限定名 ``dt.date`` 书写，
    # 否则 Pydantic 解析注解时会与字段名冲突（PydanticUserError）。
    date: dt.date = Field(description="UTC 日期（YYYY-MM-DD）")
    count: int = Field(default=0, ge=0, description="当日条数")


class StatsResponse(IntelBaseModel):
    """``GET /api/v1/stats`` 的响应体（首页仪表盘单一数据源）。

    Attributes:
        total_vulns: 漏洞事实总条数。
        critical_count: 严重度 ``CRITICAL`` 条数（KPI「高危」）。
        source_count: 已启用采集源数量。
        today_new: 近 24 小时新增条数。
        risk_distribution: 风险分布（严重度口径，小写键）。
        source_distribution: 来源分布（各源贡献条数，按条数倒序）。
        timeline: 近 N 天趋势（日期连续升序，缺失日补 0）。
        top_high_risk: 最近的高危漏洞（``CRITICAL`` / ``HIGH``，最多 ``top_limit`` 条）。
        generated_at: 本次统计的生成时间（UTC，前端展示「数据更新时间」）。
    """

    model_config = ConfigDict(extra="forbid")

    total_vulns: int = Field(default=0, ge=0, description="漏洞总数")
    critical_count: int = Field(default=0, ge=0, description="严重度 CRITICAL 条数")
    source_count: int = Field(default=0, ge=0, description="已启用采集源数量")
    today_new: int = Field(default=0, ge=0, description="近 24 小时新增条数")
    risk_distribution: dict[str, int] = Field(default_factory=dict, description="风险分布")
    source_distribution: dict[str, int] = Field(default_factory=dict, description="来源分布")
    timeline: list[TimelinePoint] = Field(default_factory=list, description="近 N 天趋势")
    top_high_risk: list[VulnSummary] = Field(default_factory=list, description="最近高危漏洞")
    generated_at: UTCDateTime = Field(description="统计生成时间（UTC）")


__all__ = ["StatsResponse", "TimelinePoint"]
