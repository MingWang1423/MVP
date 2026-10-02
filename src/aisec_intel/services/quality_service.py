"""数据质量聚合服务（Day16 任务 2；PROJECT_PLAN.md §5.9 / §5.5 P4）。

本模块把 P4 的「数据质量报告」能力从一次性脚本（``scripts/data_quality.py``）**下沉为可复用服务**，
让前端 ``/quality`` 页既能拿到结构化指标（画柱图 / 环形图 / 雷达图 / 折线图），
也能拿到与 ``reports/data_quality.md`` **同口径、同生成器**的 Markdown 报告：

1. **纯函数层**（无 DB、无 LLM、可单测）：:func:`evaluate_source` / :func:`evaluate_all` /
   :func:`summarize` / :func:`render_markdown`；
2. **聚合层**（只读 DB）：:meth:`DataQualityService.snapshot` —— 逐源读取 ``raw_item`` 并重放
   L2 纯函数 :func:`aisec_intel.normalize.pipeline.build_unified_vuln`，另取近 N 天采集趋势；
3. **进程内缓存**：同一参数重复请求直接命中（默认 5 分钟），避免演示时反复重放；
   需要最新数据时传 ``refresh=True``。

约束：L5 服务层只读聚合、**禁止 LLM**（§2.1）；所有对外数值口径与 P4 报告脚本完全一致。
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from datetime import time as dt_time
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.config import Settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import iso_z, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.pipeline import build_unified_vuln
from aisec_intel.services.collect_service import PAPER_SOURCES, enabled_sources_from_config
from aisec_intel.storage.repositories.raw_repo import RawRepository
from aisec_intel.storage.repositories.source_repo import SourceRepository
from aisec_intel.storage.repositories.stats_repo import StatsRepository, bucket_by_day

logger = get_logger(__name__)

FIELD_NAMES: tuple[str, ...] = ("description", "cvss", "cwe", "references")
"""参与字段完整率统计的字段（与 §5.5 P4 要求一致）。"""

MAX_ROWS_PER_SOURCE: int = 10000
"""单源最多重放的 ``raw_item`` 行数（``sample_limit=0`` 时使用）。"""

DEFAULT_SAMPLE_LIMIT: int = 1000
"""API 默认的每源采样上限（前端首屏 3 秒内出图；``0`` 表示不限，取 10000）。"""

DEFAULT_TREND_DAYS: int = 30
"""趋势窗口天数（含当天）。"""

CACHE_TTL_S: float = 300.0
"""快照缓存存活时间（秒）。"""

REPORTS_DIR: Path = Path(__file__).resolve().parents[3] / "reports"
"""报告目录（仓库根 ``reports/``；容器内为 ``/app/reports``）。"""

GRAPH_STATS_FILENAME: str = "graph_stats.md"
"""图谱规模报告文件名（由 ``scripts/load_graph.py`` 生成）。"""


@dataclass(slots=True)
class SourceQuality:
    """单个源的数据质量指标。

    Attributes:
        source: 源标识。
        kind: ``vuln``（漏洞源）或 ``paper``（论文源，只落 ``raw_item``）。
        raw_count: 采集条数（``raw_item`` 行数）。
        normalized_ok: 归一化成功条数。
        normalized_failed: 归一化失败条数。
        field_complete: 字段 → 非空条数（分母为 ``normalized_ok``）。
    """

    source: str
    kind: str
    raw_count: int
    normalized_ok: int
    normalized_failed: int
    field_complete: dict[str, int] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        """归一化成功率（无数据时返回 0.0）。

        Returns:
            成功率，区间 ``[0, 1]``。
        """
        total = self.normalized_ok + self.normalized_failed
        return self.normalized_ok / total if total else 0.0

    def completeness(self, field_name: str) -> float:
        """某字段的完整率（无归一化成功条数时返回 0.0）。

        Args:
            field_name: :data:`FIELD_NAMES` 中的字段名。

        Returns:
            完整率，区间 ``[0, 1]``。
        """
        if not self.normalized_ok:
            return 0.0
        return self.field_complete.get(field_name, 0) / self.normalized_ok


def evaluate_source(source: str, items: list[RawItem]) -> SourceQuality:
    """对单个源的条目做质量评估（纯函数，不访问数据库、不调用 LLM）。

    逐条重放 :func:`aisec_intel.normalize.pipeline.build_unified_vuln`：
    抛异常的条目计入「归一化失败」，其余按四类字段统计完整率。
    论文源（arXiv / OpenAlex）同样评估，但报告中标注其不写入 ``unified_vuln``（P4 设计）。

    Args:
        source: 源标识。
        items: 该源的 ``RawItem`` 列表。

    Returns:
        :class:`SourceQuality` 指标。
    """
    hits: dict[str, int] = dict.fromkeys(FIELD_NAMES, 0)
    normalized_ok = 0
    normalized_failed = 0
    for item in items:
        try:
            vuln = build_unified_vuln(item)
        except Exception:  # noqa: BLE001 - 无法归一化的条目只计数，不中断报告
            normalized_failed += 1
            continue
        normalized_ok += 1
        if vuln.description.strip():
            hits["description"] += 1
        if vuln.cvss:
            hits["cvss"] += 1
        if vuln.cwe_ids:
            hits["cwe"] += 1
        if vuln.references:
            hits["references"] += 1
    return SourceQuality(
        source=source,
        kind="paper" if source in PAPER_SOURCES else "vuln",
        raw_count=len(items),
        normalized_ok=normalized_ok,
        normalized_failed=normalized_failed,
        field_complete=hits,
    )


def evaluate_all(
    grouped: dict[str, list[RawItem]],
    *,
    sources: Iterable[str],
) -> list[SourceQuality]:
    """对全部指定源做评估（含「零数据」源，便于暴露采集缺口）。

    Args:
        grouped: ``{源标识: [RawItem, ...]}``。
        sources: 期望统计的源标识列表（顺序被保留）。

    Returns:
        :class:`SourceQuality` 列表（按「类型 + 源标识」排序）。
    """
    qualities = [evaluate_source(source, grouped.get(source, [])) for source in sources]
    qualities.sort(key=lambda item: (item.kind, item.source))
    return qualities


@dataclass(frozen=True, slots=True)
class QualitySummary:
    """全库汇总指标（前端 KPI 卡与雷达图的数据源）。

    Attributes:
        total_raw: 采集总条数（各源之和）。
        normalized_ok: 归一化成功总条数。
        normalized_failed: 归一化失败总条数。
        success_rate: 归一化成功率（``[0, 1]``）。
        field_completeness: 字段 → 全局完整率（分母为成功条数）。
        coverage_rate: 源覆盖率（有数据的源 / 声明启用的源）。
        with_data_sources: 实际有数据的源。
        missing_sources: 声明启用但当前无数据的源。
    """

    total_raw: int
    normalized_ok: int
    normalized_failed: int
    success_rate: float
    field_completeness: dict[str, float]
    coverage_rate: float
    with_data_sources: tuple[str, ...]
    missing_sources: tuple[str, ...]


def summarize(qualities: Iterable[SourceQuality], *, declared: Iterable[str]) -> QualitySummary:
    """把各源指标汇总为全局指标（纯函数）。

    Args:
        qualities: 各源质量指标。
        declared: ``sources.yaml`` 声明启用的源标识（覆盖率分母）。

    Returns:
        :class:`QualitySummary`。
    """
    items = list(qualities)
    declared_list = [name for name in declared if name]
    total_raw = sum(item.raw_count for item in items)
    total_ok = sum(item.normalized_ok for item in items)
    total_failed = sum(item.normalized_failed for item in items)
    total_attempts = total_ok + total_failed
    with_data = tuple(item.source for item in items if item.raw_count > 0)
    missing = tuple(name for name in declared_list if name not in set(with_data))
    completeness = {
        name: (sum(item.field_complete.get(name, 0) for item in items) / total_ok)
        if total_ok
        else 0.0
        for name in FIELD_NAMES
    }
    return QualitySummary(
        total_raw=total_raw,
        normalized_ok=total_ok,
        normalized_failed=total_failed,
        success_rate=(total_ok / total_attempts) if total_attempts else 0.0,
        field_completeness=completeness,
        coverage_rate=(len(with_data) / len(declared_list)) if declared_list else 0.0,
        with_data_sources=with_data,
        missing_sources=missing,
    )


def format_percent(value: float) -> str:
    """把比率格式化为百分比文本。

    Args:
        value: 区间 ``[0, 1]`` 的比率。

    Returns:
        形如 ``98.3%`` 的文本。
    """
    return f"{value * 100:.1f}%"


def render_markdown(
    qualities: list[SourceQuality],
    *,
    declared: list[str],
    since: datetime | None,
    generated_at: datetime,
    limit: int = 0,
) -> str:
    """把质量指标渲染为 Markdown 报告（纯函数，便于单测）。

    输出内容与 ``reports/data_quality.md``（P4 交付物）**逐字一致**——
    两条路径共用本函数，避免「报告口径」与「页面口径」漂移。

    Args:
        qualities: 各源质量指标。
        declared: ``sources.yaml`` 声明启用的源标识。
        since: 统计窗口起点（UTC）；``None`` 表示全量。
        generated_at: 报告生成时间（UTC）。
        limit: 每源读取上限（写入报告以便复现）。

    Returns:
        Markdown 文本。
    """
    with_data = [item.source for item in qualities if item.raw_count > 0]
    coverage = len(with_data) / len(declared) if declared else 0.0
    total_raw = sum(item.raw_count for item in qualities)
    total_ok = sum(item.normalized_ok for item in qualities)
    total_failed = sum(item.normalized_failed for item in qualities)

    window = iso_z(since) if since is not None else "全量（不限时间）"
    lines: list[str] = [
        "# 采集数据质量报告（P4）",
        "",
        f"- 生成时间：{iso_z(generated_at)}",
        f"- 统计窗口：since={window}；每源读取上限={limit if limit > 0 else MAX_ROWS_PER_SOURCE}",
        "- 统计口径：`raw_item` 表 + L2 纯函数 `build_unified_vuln` 重放（确定性，无 LLM）",
        "- 生成命令：`python -m scripts.data_quality`（详见 §5.5 / §6.2 P4）",
        "",
        "## 1. 采集量与归一化成功率",
        "",
        "| 源 | 类型 | 采集条数 | 归一化成功 | 归一化失败 | 归一化成功率 |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for item in qualities:
        lines.append(
            f"| {item.source} | {'论文' if item.kind == 'paper' else '漏洞'} | {item.raw_count} | "
            f"{item.normalized_ok} | {item.normalized_failed} | {format_percent(item.success_rate)} |"
        )
    lines.append(f"| **合计** | — | {total_raw} | {total_ok} | {total_failed} | — |")

    lines += [
        "",
        "## 2. 字段完整率（分母 = 归一化成功条数）",
        "",
        "| 源 | description | cvss | cwe | references |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in qualities:
        cells = " | ".join(format_percent(item.completeness(name)) for name in FIELD_NAMES)
        lines.append(f"| {item.source} | {cells} |")

    missing = [name for name in declared if name not in with_data]
    lines += [
        "",
        "## 3. 源覆盖率",
        "",
        f"- 声明启用源：{len(declared)} 个 → {'、'.join(declared) if declared else '（无）'}",
        f"- 实际有数据源：{len(with_data)} 个 → {'、'.join(with_data) if with_data else '（无）'}",
        f"- **源覆盖率：{format_percent(coverage)}**",
        "",
        "## 4. 结论与待办",
        "",
        f"- 采集总量：{total_raw} 条；归一化成功 {total_ok} 条、失败 {total_failed} 条。",
    ]
    if missing:
        lines.append(f"- ⚠️ 以下启用源当前无数据（需检查调度 / 凭据 / 源可用性）：{'、'.join(missing)}")
    else:
        lines.append("- ✅ 所有声明的启用源均已有数据。")
    if total_ok:
        averages = {
            name: sum(item.field_complete.get(name, 0) for item in qualities) / total_ok
            for name in FIELD_NAMES
        }
        lines.append(
            "- 四字段平均完整率："
            f"description={format_percent(averages['description'])}、"
            f"cvss={format_percent(averages['cvss'])}、"
            f"cwe={format_percent(averages['cwe'])}、"
            f"references={format_percent(averages['references'])}"
        )
    lines += [
        "- 备注：论文源（arxiv / openalex）在 P4 只落 `raw_item`，不写入 `unified_vuln`，"
        "其 `cvss` / `cwe` 完整率天然为 0%（P6 由论文实体与图谱承载）。",
        "",
    ]
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class DataQualitySnapshot:
    """一次数据质量快照（服务层产物，由路由层映射为 API 契约）。

    Attributes:
        summary: 全局汇总指标。
        sources: 各源指标（按「类型 + 源标识」排序）。
        declared_sources: ``sources.yaml`` 声明启用的源。
        enabled_source_count: ``source`` 表中已启用的采集源数量。
        trend: 近 N 天**采集**趋势（``raw_item.fetched_at``，缺失日补 0）。
        trend_normalized: 近 N 天**入库 / 披露**趋势（``unified_vuln`` 时间轴）。
        sample_limit: 实际生效的每源重放上限。
        trend_days: 趋势窗口天数。
        truncated: 是否有源触达重放上限（意味着数值是下界）。
        markdown: 与 ``reports/data_quality.md`` 同生成器的 Markdown 报告。
        graph_stats_markdown: ``reports/graph_stats.md`` 原文（缺失时为 ``None``）。
        generated_at: 快照生成时间（UTC）。
    """

    summary: QualitySummary
    sources: tuple[SourceQuality, ...]
    declared_sources: tuple[str, ...]
    enabled_source_count: int
    trend: dict[date, int]
    trend_normalized: dict[date, int]
    sample_limit: int
    trend_days: int
    truncated: bool
    markdown: str
    graph_stats_markdown: str | None
    generated_at: datetime


@dataclass(slots=True)
class SnapshotCache:
    """进程内快照缓存（单机部署足够；多副本需换 Redis，与 ``RateLimiter`` 同口径）。

    Attributes:
        ttl_s: 存活时间（秒）。
        clock: 时钟（默认 :func:`time.monotonic`，测试可注入）。
    """

    ttl_s: float = CACHE_TTL_S
    clock: Callable[[], float] = time.monotonic
    _entries: dict[tuple[object, ...], tuple[float, DataQualitySnapshot]] = field(
        default_factory=dict, repr=False
    )

    def get(self, key: tuple[object, ...]) -> DataQualitySnapshot | None:
        """读取未过期的快照。

        Args:
            key: 缓存键（由 :meth:`DataQualityService.cache_key` 生成）。

        Returns:
            命中且未过期时返回快照，否则 ``None``。
        """
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, snapshot = entry
        if self.clock() >= expires_at:
            self._entries.pop(key, None)
            return None
        return snapshot

    def put(self, key: tuple[object, ...], snapshot: DataQualitySnapshot) -> None:
        """写入快照（覆盖同键旧值）。

        Args:
            key: 缓存键。
            snapshot: 快照。
        """
        self._entries[key] = (self.clock() + self.ttl_s, snapshot)

    def clear(self) -> None:
        """清空缓存（测试与运维强制刷新用）。"""
        self._entries.clear()


_CACHE: SnapshotCache = SnapshotCache()
"""进程级快照缓存单例。"""


def clear_cache() -> None:
    """清空进程级快照缓存（下次请求重新聚合）。"""
    _CACHE.clear()


class DataQualityService:
    """数据质量聚合服务（只读、无 LLM、结果带进程内缓存）。"""

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings,
        cache: SnapshotCache | None = None,
        reports_dir: Path | None = None,
    ) -> None:
        """绑定会话与配置。

        Args:
            session: 请求级 PG 会话（只读）。
            settings: 全局配置（定位 ``configs/sources.yaml``）。
            cache: 快照缓存；``None`` 时用进程级单例。
            reports_dir: 报告目录；``None`` 时用仓库根 ``reports/``。
        """
        self._session = session
        self._settings = settings
        self._cache = cache or _CACHE
        self._reports_dir = reports_dir or REPORTS_DIR

    @staticmethod
    def cache_key(sample_limit: int, trend_days: int, include_reports: bool) -> tuple[object, ...]:
        """生成缓存键（纯函数）。

        Args:
            sample_limit: 每源重放上限。
            trend_days: 趋势天数。
            include_reports: 是否附带报告原文。

        Returns:
            缓存键元组。
        """
        return ("data-quality", sample_limit, trend_days, bool(include_reports))

    async def snapshot(
        self,
        *,
        sample_limit: int = DEFAULT_SAMPLE_LIMIT,
        trend_days: int = DEFAULT_TREND_DAYS,
        include_reports: bool = True,
        refresh: bool = False,
    ) -> DataQualitySnapshot:
        """生成（或命中缓存）数据质量快照。

        Args:
            sample_limit: 每源最多重放的 ``raw_item`` 条数（``0`` = 使用上限 10000）。
            trend_days: 趋势窗口天数（含当天）。
            include_reports: 是否附带 ``reports/graph_stats.md`` 原文。
            refresh: 为 ``True`` 时绕过缓存重新聚合。

        Returns:
            :class:`DataQualitySnapshot`。
        """
        row_limit = sample_limit if sample_limit > 0 else MAX_ROWS_PER_SOURCE
        days = max(1, trend_days)
        key = self.cache_key(row_limit, days, include_reports)
        if not refresh:
            cached = self._cache.get(key)
            if cached is not None:
                logger.info(f"数据质量快照命中缓存：limit={row_limit} days={days}")
                return cached

        declared = enabled_sources_from_config(self._settings)
        grouped = await self._grouped_raw(declared, row_limit)
        qualities = evaluate_all(grouped, sources=declared)
        summary = summarize(qualities, declared=declared)
        trend, trend_normalized = await self._trends(days)
        truncated = row_limit < MAX_ROWS_PER_SOURCE and any(
            len(items) >= row_limit for items in grouped.values()
        )
        generated_at = utc_now()
        snapshot = DataQualitySnapshot(
            summary=summary,
            sources=tuple(qualities),
            declared_sources=tuple(declared),
            enabled_source_count=await SourceRepository(self._session).count(enabled_only=True),
            trend=trend,
            trend_normalized=trend_normalized,
            sample_limit=row_limit,
            trend_days=days,
            truncated=truncated,
            markdown=render_markdown(
                qualities,
                declared=declared,
                since=None,
                generated_at=generated_at,
                limit=row_limit,
            ),
            graph_stats_markdown=self._read_report(GRAPH_STATS_FILENAME) if include_reports else None,
            generated_at=generated_at,
        )
        self._cache.put(key, snapshot)
        logger.info(
            f"数据质量快照已生成：源={len(declared)} 采集={summary.total_raw} "
            f"成功率={summary.success_rate:.3f} 覆盖率={summary.coverage_rate:.3f} "
            f"（limit={row_limit} days={days}）"
        )
        return snapshot

    async def _grouped_raw(self, sources: list[str], row_limit: int) -> dict[str, list[RawItem]]:
        """按源读取 ``raw_item``（一次会话内完成，避免频繁建连）。

        Args:
            sources: 源标识列表。
            row_limit: 每源读取上限。

        Returns:
            ``{源标识: [RawItem, ...]}``。
        """
        repo = RawRepository(self._session)
        grouped: dict[str, list[RawItem]] = {}
        for source in sources:
            grouped[source] = await repo.list_by_source(source, limit=row_limit)
        return grouped

    async def _trends(self, days: int) -> tuple[dict[date, int], dict[date, int]]:
        """取「采集趋势」与「入库 / 披露趋势」。

        Args:
            days: 窗口天数（含当天）。

        Returns:
            ``(采集趋势, 入库趋势)``，两份均为日期连续、缺失日补 0 的字典。
        """
        anchor = utc_now()
        end = datetime.combine(anchor.date(), dt_time.min, tzinfo=UTC)
        start = end - timedelta(days=days - 1)
        fetched = await RawRepository(self._session).list_fetched_times(since=start)
        collected = bucket_by_day(fetched, since=start, until=end)
        normalized = await StatsRepository(self._session).daily_counts(days=days, now=anchor)
        return collected, normalized

    def _read_report(self, filename: str) -> str | None:
        """读取 ``reports/`` 下的 Markdown 报告原文（缺失时返回 ``None``）。

        Args:
            filename: 报告文件名。

        Returns:
            文件内容；不存在或不可读时 ``None``（前端据此展示空态）。
        """
        path = self._reports_dir / filename
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning(f"报告不可读（{path}）：{exc}")
            return None
