"""采集编排服务（PROJECT_PLAN.md §5.5 P4：调度、增量、去重与监控）。

本模块是采集链路的**唯一实现**，两类调用方共享同一份逻辑，避免行为漂移：

1. ``scripts/run_collect.py``：命令行一次性采集（人工 / 演示 / CI）；
2. ``src/aisec_intel/services/scheduler.py``：APScheduler 周期调度（常驻进程）。

流程（§1.3 数据流）：``BaseConnector.fetch_incremental`` → ``raw_item``（内容寻址幂等）
→ ``build_unified_vuln``（L2 纯函数）→ ``merge_unified_vulns``（跨源去重）
→ ``unified_vuln``（按 ``vuln_id`` 幂等 upsert）。

分工说明（P4 去重落地点）：
    - **源内合并**：单个源一次采集内的多条记录先归一再合并（同 CVE 多条目只写一条）；
    - **跨源合并**：``--source all`` 时把各源结果合并后再 upsert，
      避免「先写 NVD、后写 KEV」互相覆盖字段（§10.2 不变式 5）。

硬约束：本层属 L5 编排层，**禁止 LLM**（§0 约束 1）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from aisec_intel.config import Settings, SourcesConfig, load_sources_config
from aisec_intel.connectors import UnknownSourceError, available_sources, create_connector
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import to_utc, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.normalize.dedupe import merge_unified_vulns
from aisec_intel.normalize.pipeline import build_unified_vuln
from aisec_intel.storage.database import get_engine, session_scope
from aisec_intel.storage.repositories.raw_repo import RawRepository
from aisec_intel.storage.repositories.task_repo import TaskRepository
from aisec_intel.storage.repositories.vuln_repo import VulnRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

logger = get_logger(__name__)

ALL_SOURCES: str = "all"
"""``--source all`` 的取值。"""

CollectMode = Literal["incremental", "full"]
"""采集模式：``incremental`` 走 ``task_run`` 游标，``full`` 从固定起始日期全量拉。"""

FULL_MODE_START: datetime = datetime(2024, 1, 1, tzinfo=UTC)
"""全量模式（``--mode full``）的固定起始日期（§5.5：从固定起始日期全量拉）。"""

PAPER_SOURCES: frozenset[str] = frozenset({"arxiv", "openalex"})
"""论文类源（arXiv / OpenAlex）。

P4 阶段它们只落 ``raw_item``（保真元数据），**不写入** ``unified_vuln``——
论文实体在 P6 由 ``models/paper.py`` + 图谱节点承载，避免污染漏洞表。
"""

PARAM_ALIASES: dict[str, str] = {"watchlist": "packages"}
"""``sources.yaml`` 参数名 → 采集器构造参数名的兼容别名（见 :func:`supported_connector_kwargs`）。"""


@dataclass(slots=True)
class CollectStats:
    """单个源的采集与归一化统计。

    Attributes:
        source: 源标识。
        since: 增量起点（UTC）。
        mode: 采集模式（``incremental`` / ``full``）。
        fetched: 源侧拉取条数（过滤后、限制前）。
        processed: 本次处理条数（受 ``--limit`` 限制）。
        created: ``raw_item`` 新增条数（指纹此前不存在）。
        skipped: ``raw_item`` 跳过条数（指纹已存在）。
        norm_ok: 成功归一化为 ``UnifiedVuln`` 的条数。
        norm_failed: 归一化失败条数（单条失败不中断整批）。
        merged_count: 合并后实体数（本次写入 ``unified_vuln`` 的条数）。
        skipped_count: 因合并被折叠掉的条数（``norm_ok - merged_count``）。
        norm_created: 合并实体中新增（此前库里没有）的条数。
        norm_skipped: 合并实体中更新（此前库里已有）的条数。
        duration_s: 耗时（秒）。
        status: ``succeeded`` / ``failed``。
        error: 失败原因。
        normalize_requested: 本次是否请求了归一化（仅影响输出展示）。
        normalized: 本批合并后的实体（供跨源二次合并使用，非持久化字段）。
        extra: 附加诊断信息。
    """

    source: str
    since: datetime
    mode: str = "incremental"
    fetched: int = 0
    processed: int = 0
    created: int = 0
    skipped: int = 0
    norm_ok: int = 0
    norm_failed: int = 0
    merged_count: int = 0
    skipped_count: int = 0
    norm_created: int = 0
    norm_skipped: int = 0
    duration_s: float = 0.0
    status: str = "succeeded"
    error: str | None = None
    normalize_requested: bool = False
    normalized: list[UnifiedVuln] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MergeOutcome:
    """跨源合并写库结果。

    Attributes:
        input_count: 参与合并的归一化实体数（含重复）。
        merged_count: 合并后实体数。
        created: 合并实体中新增条数。
        updated: 合并实体中更新条数。
    """

    input_count: int
    merged_count: int
    created: int
    updated: int

    @property
    def folded_count(self) -> int:
        """被合并折叠掉的重复条数。"""
        return max(0, self.input_count - self.merged_count)


@dataclass(frozen=True, slots=True)
class NormalizeOutcome:
    """单批归一化 + 合并的结果（P4 任务 1 的统计载体）。

    Attributes:
        merged: 合并后的实体列表。
        ok_count: 归一化成功条数（合并前）。
        failed_count: 归一化失败条数。
    """

    merged: list[UnifiedVuln]
    ok_count: int
    failed_count: int

    @property
    def merged_count(self) -> int:
        """合并后实体数。"""
        return len(self.merged)

    @property
    def folded_count(self) -> int:
        """被合并折叠掉的重复条数。"""
        return max(0, self.ok_count - self.merged_count)


def parse_since(value: str | None) -> datetime | None:
    """把 ``--since`` 字符串解析为 UTC 时间。

    Args:
        value: ``YYYY-MM-DD`` 或 ISO8601 字符串；``None`` / 空串表示未指定。

    Returns:
        UTC ``datetime``；无法解析时返回 ``None``（调用方据此报错退出）。
    """
    if not value or not value.strip():
        return None
    from aisec_intel.normalize.datetime_utils import parse_datetime

    return parse_datetime(value.strip())


def resolve_sources(source_arg: str | None, *, list_sources: bool = False) -> list[str]:
    """解析 ``--source`` 参数。

    Args:
        source_arg: 用户传入的源标识（``None`` / ``all`` / 逗号分隔列表）。
        list_sources: 是否为 ``--list-sources`` 模式（此时不校验参数）。

    Returns:
        源标识列表（字典序、去重）。

    Raises:
        SystemExit: 未提供 ``--source`` 且非 ``--list-sources``。
        UnknownSourceError: 出现未注册的源。
    """
    if list_sources:
        return []
    if not source_arg:
        raise SystemExit(f"缺少 --source（可用 --list-sources 查看已注册源，或 --source {ALL_SOURCES}）")
    if source_arg.strip().lower() == ALL_SOURCES:
        return available_sources()
    requested = [part.strip().lower() for part in source_arg.split(",") if part.strip()]
    known = set(available_sources())
    unknown = [name for name in requested if name not in known]
    if unknown:
        raise UnknownSourceError(f"未注册的源 {unknown}；可用源：{sorted(known)}")
    return sorted(set(requested))


def enabled_sources_from_config(
    settings: Settings,
    *,
    config: SourcesConfig | None = None,
) -> list[str]:
    """返回「声明启用 且 已注册」的源标识（字典序）。

    ``configs/sources.yaml`` 缺失时退化为全部已注册源，保证离线 / 降级环境可运行。

    Args:
        settings: 全局配置（用于定位 ``sources.yaml``）。
        config: 已加载的源配置；``None`` 时按 ``Settings.sources_config_path`` 读取。

    Returns:
        源标识列表。
    """
    sources_config = config if config is not None else load_sources_config(settings=settings)
    registered = set(available_sources())
    if not sources_config.sources:
        return sorted(registered)
    return sorted(name for name in sources_config.enabled_sources if name in registered)


def source_interval_minutes(
    settings: Settings,
    source: str,
    *,
    config: SourcesConfig | None = None,
) -> int:
    """读取某源的调度间隔（分钟），未声明时取 ``defaults.interval_minutes``。

    Args:
        settings: 全局配置。
        source: 源标识。
        config: 已加载的源配置；``None`` 时按 ``Settings.sources_config_path`` 读取。

    Returns:
        调度间隔（分钟，恒为正数）。
    """
    sources_config = config if config is not None else load_sources_config(settings=settings)
    entry = sources_config.for_source(source)
    if entry is None:
        return sources_config.defaults.interval_minutes
    return entry.interval_minutes


def supported_connector_kwargs(
    settings: Settings,
    source: str,
    *,
    config: SourcesConfig | None = None,
) -> dict[str, object]:
    """把 ``configs/sources.yaml`` 的 ``params`` 映射为采集器构造参数（安全过滤）。

    仅保留目标采集器 ``__init__`` 真正接受的键（避免源与源之间参数差异导致 ``TypeError``），
    并支持少量别名（``watchlist`` → ``packages``）。这样「改配置不改代码」在调度与 CLI 两侧一致。

    Args:
        settings: 全局配置。
        source: 源标识。
        config: 已加载的源配置；``None`` 时按 ``Settings.sources_config_path`` 读取。

    Returns:
        可直接 ``**`` 展开给 ``create_connector`` 的参数字典（可能为空）。
    """
    from inspect import signature

    from aisec_intel.connectors import get_connector_class

    sources_config = config if config is not None else load_sources_config(settings=settings)
    entry = sources_config.for_source(source)
    if entry is None or not entry.params:
        return {}
    accepted = set(signature(get_connector_class(source).__init__).parameters) - {"self", "kwargs"}
    resolved: dict[str, object] = {}
    for key, value in entry.params.items():
        target = PARAM_ALIASES.get(key, key)
        if target in accepted:
            resolved[target] = value
    return resolved


async def resolve_since(
    source: str,
    *,
    settings: Settings,
    explicit: datetime | None = None,
    days: int | None = None,
    mode: str = "incremental",
) -> datetime:
    """决定某个源的采集起点（P4 增量游标落地）。

    优先级：显式 ``--since`` > ``--days`` > ``--mode full`` 固定起点
    > ``task_run`` 上次成功时间 > ``now - COLLECT_DEFAULT_DAYS``。

    Args:
        source: 源标识。
        settings: 全局配置。
        explicit: 用户显式指定的起点。
        days: 显式回看天数（``--days``）。
        mode: ``incremental`` / ``full``。

    Returns:
        UTC ``datetime``。
    """
    if explicit is not None:
        return to_utc(explicit)
    if mode == "full":
        return FULL_MODE_START
    if days is not None and days > 0:
        return to_utc(utc_now() - timedelta(days=days))
    last: datetime | None = None
    try:
        async with session_scope(get_engine(settings)) as session:
            last = await TaskRepository(session).last_run_at(source)
    except Exception:  # noqa: BLE001 - 首次运行（库/表缺失）时回退默认窗口
        last = None
    if last is not None:
        return last
    return to_utc(utc_now() - timedelta(days=settings.collect_default_days))


def normalize_batch(
    items: list[RawItem],
    *,
    source: str,
    normalized_at: datetime | None = None,
) -> NormalizeOutcome:
    """把一批 ``RawItem`` 归一化并**合并**（纯函数，无 IO）。

    论文类源（``PAPER_SOURCES``）不参与漏洞归一化，返回空结果（P6 才落论文实体）。

    Args:
        items: ``RawItem`` 列表。
        source: 源标识。
        normalized_at: 归一化时间（UTC）；同一批次统一注入以保证合并结果确定。

    Returns:
        :class:`NormalizeOutcome`（含合并前成功条数、失败条数与合并后实体）。
    """
    if source in PAPER_SOURCES:
        return NormalizeOutcome(merged=[], ok_count=0, failed_count=0)
    failed = 0
    built: list[UnifiedVuln] = []
    for item in items:
        try:
            built.append(build_unified_vuln(item, normalized_at=normalized_at))
        except Exception as exc:  # noqa: BLE001 - 单条归一化失败不应中断整批
            failed += 1
            logger.warning(f"归一化失败 source={source} source_id={item.source_id}：{exc!r}")
    return NormalizeOutcome(merged=merge_unified_vulns(built), ok_count=len(built), failed_count=failed)


async def collect_source(
    source: str,
    *,
    since: datetime,
    settings: Settings,
    limit: int = 0,
    dry_run: bool = False,
    normalize: bool = False,
    mode: str = "incremental",
    normalized_at: datetime | None = None,
    connector_kwargs: dict[str, object] | None = None,
) -> CollectStats:
    """采集单个源并落库（可选：同步归一化 + 去重合并到 ``unified_vuln``）。

    Args:
        source: 源标识。
        since: 增量起点（UTC）。
        settings: 全局配置。
        limit: 最多处理条数（0 表示不限）；同时作为采集器的 ``max_records`` 提前止损。
        dry_run: ``True`` 时不写入数据库（仍记录任务状态）。
        normalize: ``True`` 时对每条 ``RawItem`` 走 L2 归一化、合并后 upsert 到 ``unified_vuln``。
        mode: 采集模式（写入 ``task_run.meta`` 便于运维追溯）。
        normalized_at: 归一化时间（UTC）；缺省取批次开始时刻。
        connector_kwargs: 采集器构造参数；``None`` 时按 ``sources.yaml`` 的 ``params`` 自动推导。

    Returns:
        :class:`CollectStats` 统计结果。
    """
    stats = CollectStats(source=source, since=since, mode=mode, normalize_requested=normalize)
    extra_kwargs = (
        connector_kwargs
        if connector_kwargs is not None
        else supported_connector_kwargs(settings, source)
    )
    connector = create_connector(source, settings=settings, max_records=limit or None, **extra_kwargs)
    engine = get_engine(settings)
    started = time.perf_counter()
    task_id: int | None = None
    try:
        async with session_scope(engine) as session:
            task_id = await TaskRepository(session).start(
                source=source,
                meta={
                    "since": since.isoformat(),
                    "limit": limit,
                    "dry_run": dry_run,
                    "normalize": normalize,
                    "mode": mode,
                },
            )

        items = await connector.fetch_incremental(since)
        stats.fetched = len(items)
        selected = items[:limit] if limit > 0 else items
        stats.processed = len(selected)

        if dry_run:
            async with session_scope(engine) as session:
                await TaskRepository(session).succeeded(
                    task_id, fetched=stats.fetched, created=0, skipped=0, meta={"dry_run": True}
                )
        else:
            batch_at = normalized_at or utc_now()
            async with session_scope(engine) as session:
                raw_repo = RawRepository(session)
                for item in selected:
                    result = await raw_repo.upsert(item)
                    stats.created += int(result.created)
                    stats.skipped += int(not result.created)

                if normalize:
                    # P4 任务 1：先收集全部 UnifiedVuln → 合并 → 再 upsert，
                    # 避免「同 CVE 多源 / 同源多条目」互相覆盖字段。
                    outcome = normalize_batch(selected, source=source, normalized_at=batch_at)
                    stats.norm_failed = outcome.failed_count
                    stats.norm_ok = outcome.ok_count
                    stats.merged_count = outcome.merged_count
                    stats.skipped_count = outcome.folded_count
                    stats.normalized = outcome.merged
                    vuln_repo = VulnRepository(session)
                    for vuln in outcome.merged:
                        outcome_row = await vuln_repo.upsert_with_status(vuln)
                        stats.norm_created += int(outcome_row.created)
                        stats.norm_skipped += int(not outcome_row.created)

                await TaskRepository(session).succeeded(
                    task_id,
                    fetched=stats.fetched,
                    created=stats.created,
                    skipped=stats.skipped,
                    meta={
                        "normalize": normalize,
                        "mode": mode,
                        "norm_ok": stats.norm_ok,
                        "norm_failed": stats.norm_failed,
                        "merged_count": stats.merged_count,
                        "skipped_count": stats.skipped_count,
                        "norm_created": stats.norm_created,
                        "norm_skipped": stats.norm_skipped,
                    },
                )
        stats.status = "succeeded"
    except Exception as exc:  # noqa: BLE001 - CLI 需把失败原因完整带回
        stats.status = "failed"
        stats.error = f"{type(exc).__name__}: {exc}"
        if task_id is not None:
            try:
                async with session_scope(engine) as session:
                    await TaskRepository(session).failed(task_id, stats.error)
            except Exception as inner:  # noqa: BLE001 - 记录失败本身不应再抛
                stats.extra["record_error"] = str(inner)
    finally:
        stats.duration_s = time.perf_counter() - started
        await connector.aclose()
    return stats


async def merge_and_upsert(
    vulns: list[UnifiedVuln],
    *,
    settings: Settings,
    engine: AsyncEngine | None = None,
) -> MergeOutcome:
    """跨源合并后统一写库（P4 去重落地）。

    Args:
        vulns: 各源归一化结果（可含同一 CVE 的多条记录）。
        settings: 全局配置。
        engine: 目标引擎；``None`` 时按 ``settings`` 取默认引擎。

    Returns:
        :class:`MergeOutcome`（含合并前后条数与新增 / 更新计数）。
    """
    merged = merge_unified_vulns(vulns)
    created = 0
    updated = 0
    async with session_scope(engine or get_engine(settings)) as session:
        repo = VulnRepository(session)
        for vuln in merged:
            outcome = await repo.upsert_with_status(vuln)
            created += int(outcome.created)
            updated += int(not outcome.created)
    return MergeOutcome(input_count=len(vulns), merged_count=len(merged), created=created, updated=updated)


def print_stats(stats: CollectStats, *, verbose: bool = False) -> None:
    """打印单个源的采集统计。

    Args:
        stats: 统计结果。
        verbose: 是否打印附加诊断信息。
    """
    flag = "OK  " if stats.status == "succeeded" else "FAIL"
    print(
        f"[{flag} {stats.source}] mode={stats.mode} since={stats.since.isoformat()} "
        f"拉取={stats.fetched} 处理={stats.processed} 新增={stats.created} "
        f"跳过={stats.skipped} 耗时={stats.duration_s:.2f}s"
    )
    if stats.error:
        print(f"    错误：{stats.error}")
    if stats.status == "succeeded" and stats.normalize_requested:
        if stats.source in PAPER_SOURCES:
            print("    归一化：跳过（论文源只落 raw_item，论文实体在 P6 处理）")
        else:
            print(
                f"    归一化：合并={stats.merged_count} 折叠={stats.skipped_count} "
                f"新增={stats.norm_created} 更新={stats.norm_skipped} 失败={stats.norm_failed}"
            )
    if verbose and stats.extra:
        print(f"    附加：{stats.extra}")




