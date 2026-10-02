"""数据质量 API 的数据传输契约（Day16 任务 2）。

``GET /api/v1/data-quality`` 一次返回前端 ``/quality`` 页所需的全部数据：

- **KPI**：数据源数 / 采集总条数 / 归一化成功率 / 字段完整率；
- **图表**：各源采集量（柱图）、归一化成功率（环形图）、四字段完整率（雷达图）、
  近 N 天采集 / 入库趋势（折线图）；
- **报告**：``reports/data_quality.md`` 同生成器的 Markdown 原文 + ``reports/graph_stats.md``
  原文（由 ``scripts/load_graph.py`` 生成，缺失时为 ``null``，前端展示空态）。

口径与 P4 报告（``scripts/data_quality.py``）完全一致：``raw_item`` 逐源取样后重放
L2 纯函数 ``build_unified_vuln``，无 LLM、无副作用。
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from aisec_intel.api.schemas.stats import TimelinePoint
from aisec_intel.models.base import IntelBaseModel


class SourceQualityDto(IntelBaseModel):
    """单个采集源的数据质量指标。

    Attributes:
        source: 源标识（``nvd`` / ``kev`` / ``arxiv`` ...）。
        kind: ``vuln``（漏洞源）或 ``paper``（论文源，只落 ``raw_item``）。
        raw_count: 采集条数。
        normalized_ok: 归一化成功条数。
        normalized_failed: 归一化失败条数。
        success_rate: 归一化成功率（``[0, 1]``）。
        field_completeness: 字段 → 完整率（``description`` / ``cvss`` / ``cwe`` / ``references``）。
    """

    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="源标识")
    kind: Literal["vuln", "paper"] = Field(description="源类型")
    raw_count: int = Field(ge=0, description="采集条数")
    normalized_ok: int = Field(ge=0, description="归一化成功条数")
    normalized_failed: int = Field(ge=0, description="归一化失败条数")
    success_rate: float = Field(ge=0.0, le=1.0, description="归一化成功率")
    field_completeness: dict[str, float] = Field(
        default_factory=dict, description="字段 → 完整率（0-1）"
    )


class DataQualityReportsDto(IntelBaseModel):
    """两份 Markdown 报告原文（前端用 react-markdown 渲染）。

    Attributes:
        data_quality: ``reports/data_quality.md`` 同生成器的 Markdown 全文。
        graph_stats: ``reports/graph_stats.md`` 原文；文件缺失时为 ``None``。
    """

    model_config = ConfigDict(extra="forbid")

    data_quality: str = Field(description="采集数据质量报告（Markdown）")
    graph_stats: str | None = Field(default=None, description="图谱规模报告（Markdown，可缺）")


class DataQualityResponse(IntelBaseModel):
    """``GET /data-quality`` 响应体。

    Attributes:
        enabled_source_count: ``source`` 表中已启用的采集源数量（KPI「数据源数」）。
        declared_sources: ``configs/sources.yaml`` 声明启用的源。
        missing_sources: 声明启用但当前无数据的源（采集缺口）。
        total_raw: 采集总条数（各源之和）。
        normalized_ok: 归一化成功总条数。
        normalized_failed: 归一化失败总条数。
        normalization_success_rate: 归一化成功率（``[0, 1]``）。
        field_completeness: 四字段全局完整率（雷达图数据源）。
        coverage_rate: 源覆盖率（有数据源 / 声明启用源）。
        sources: 各源明细（柱图 + 表格）。
        trend: 近 N 天**采集**趋势（``raw_item.fetched_at``，缺失日补 0）。
        trend_normalized: 近 N 天**入库 / 披露**趋势（``unified_vuln`` 时间轴）。
        trend_days: 趋势窗口天数。
        sample_limit: 每源重放上限（``truncated=true`` 表示数值为下界）。
        truncated: 是否有源触达重放上限。
        reports: 两份 Markdown 报告。
        generated_at: 快照生成时间（UTC）。
    """

    model_config = ConfigDict(extra="forbid")

    enabled_source_count: int = Field(ge=0, description="已启用采集源数量")
    declared_sources: list[str] = Field(default_factory=list, description="sources.yaml 声明源")
    missing_sources: list[str] = Field(default_factory=list, description="声明启用但无数据的源")
    total_raw: int = Field(ge=0, description="采集总条数")
    normalized_ok: int = Field(ge=0, description="归一化成功总条数")
    normalized_failed: int = Field(ge=0, description="归一化失败总条数")
    normalization_success_rate: float = Field(ge=0.0, le=1.0, description="归一化成功率")
    field_completeness: dict[str, float] = Field(default_factory=dict, description="字段完整率")
    coverage_rate: float = Field(ge=0.0, le=1.0, description="源覆盖率")
    sources: list[SourceQualityDto] = Field(default_factory=list, description="各源明细")
    trend: list[TimelinePoint] = Field(default_factory=list, description="采集趋势")
    trend_normalized: list[TimelinePoint] = Field(default_factory=list, description="入库趋势")
    trend_days: int = Field(ge=1, description="趋势窗口天数")
    sample_limit: int = Field(ge=1, description="每源重放上限")
    truncated: bool = Field(default=False, description="是否有源触达重放上限")
    reports: DataQualityReportsDto | None = Field(default=None, description="Markdown 报告")
    generated_at: datetime = Field(description="快照生成时间（UTC）")


__all__ = [
    "DataQualityReportsDto",
    "DataQualityResponse",
    "SourceQualityDto",
]
