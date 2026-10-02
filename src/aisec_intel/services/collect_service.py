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

任务登记（``task_run``）为**旁路**：:func:`record_task_result` 吞掉登记异常并留痕，
保证「账没记上」不会把已成功的采集标成失败（Day17 压测实测到的降级模式并发场景）。
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Literal

from aisec_intel.config import Settings, SourcesConfig, load_sources_config
from aisec_intel.connectors import (
    BaseConnector,
    UnknownSourceError,
    available_sources,
    create_connector,
)
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import to_utc, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.normalize.dedupe import merge_unified_vulns
from aisec_intel.normalize.pipeline import build_unified_vuln
from aisec_intel.services.alert_service import emit_alerts_safely
from aisec_intel.services.metrics_service import record_collect
from aisec_intel.services.self_heal import fetch_with_self_heal
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

CVE_SOURCES: frozenset[str] = frozenset({"nvd", "epss", "kev"})
"""支持「按 CVE 单条拉取」的源（§8.1 最小演示路径）。

- ``nvd``：走 ``cveId`` 参数（不设时间窗）；
- ``epss``：走 ``cve=`` 精确查询；
- ``kev``：全量目录一次请求后按 ``cveID`` 过滤。

OSV / GHSA 的 API 以生态包或仓库为入口（无 CVE 直查），故不在此列。
"""

CVE_LOOKBACK_START: datetime = datetime(1999, 1, 1, tzinfo=UTC)
"""单条采集通道的起点（等价「不限时间」），避免历史 CVE 被增量窗口过滤掉。"""

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


@dataclass(slots=True)
class CveCollectResult:
    """按 CVE 单条采集的结果（§8.1 最小演示路径）。

    Attributes:
        cve_ids: 请求的 CVE 编号（已规范化、去重保序）。
        sources: 实际参与的源（与注册表取交集后）。
        stats: 各源统计（含 ``task_run`` 留痕）。
        merge: 跨源合并写库结果；``dry_run`` 或未归一化时为 ``None``。
    """

    cve_ids: list[str]
    sources: list[str]
    stats: list[CollectStats] = field(default_factory=list)
    merge: MergeOutcome | None = None

    @property
    def failed(self) -> int:
        """失败的源数量。"""
        return sum(1 for stats in self.stats if stats.status != "succeeded")

    @property
    def created(self) -> int:
        """``raw_item`` 新增条数合计。"""
        return sum(stats.created for stats in self.stats)

    @property
    def merged_count(self) -> int:
        """合并后的漏洞实体数（未归一化时为 0）。"""
        return 0 if self.merge is None else self.merge.merged_count


def normalize_cve_ids(values: Sequence[str]) -> list[str]:
    """规范化 CVE 编号列表（去空白 + 大写 + 去重保序）。

    Args:
        values: 原始编号（可含空白、大小写混杂、重复项）。

    Returns:
        规范化后的编号列表（空项被丢弃）。
    """
    normalized: list[str] = []
    for value in values:
        cleaned = str(value).strip().upper()
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


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


async def record_task_result(
    engine: AsyncEngine,
    task_id: int | None,
    *,
    stats: CollectStats,
    error: str | None = None,
    fetched: int = 0,
    created: int = 0,
    skipped: int = 0,
    meta: dict[str, Any] | None = None,
) -> None:
    """把采集结果写回 ``task_run``（**任务登记失败不得影响采集结论**）。

    Args:
        engine: 目标引擎。
        task_id: 任务主键；``None`` 时直接返回（未登记任务的调用方）。
        stats: 当前源的统计对象（用于留痕与计数）。
        error: 失败原因；非空时标记任务失败，否则标记成功。
        fetched: 源侧拉取条数（成功路径）。
        created: ``raw_item`` 新增条数（成功路径）。
        skipped: 指纹重复跳过条数（成功路径）。
        meta: 附加信息（成功路径）。

    Note:
        典型场景（Day17 压测实测）：降级模式使用内存 SQLite（``StaticPool`` 单连接），
        并发采集时多个会话共享同一连接，任务行可能被其它会话的事务回滚，
        导致 ``succeeded`` / ``failed`` 抛 ``LookupError: task_run 中不存在 id=N``。
        此时「账没记上」不应把**已成功**的采集标成失败，故此处吞掉异常并写入
        ``stats.extra["task_record_error"]``。
    """
    if task_id is None:
        return
    try:
        async with session_scope(engine) as session:
            repo = TaskRepository(session)
            if error:
                await repo.failed(task_id, error)
            else:
                await repo.succeeded(
                    task_id, fetched=fetched, created=created, skipped=skipped, meta=meta
                )
    except Exception as exc:  # noqa: BLE001 - 任务登记是旁路，不得改变采集结论
        stats.extra["task_record_error"] = f"{type(exc).__name__}: {exc}"
        logger.warning(f"task_run 状态更新失败（已忽略）：task_id={task_id} {type(exc).__name__}: {exc}")


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

        items, healed_url = await fetch_with_self_heal(connector, lambda: connector.fetch_incremental(since))
        if healed_url:
            stats.extra["self_heal_url"] = healed_url
        stats.fetched = len(items)
        selected = items[:limit] if limit > 0 else items
        stats.processed = len(selected)

        if dry_run:
            await record_task_result(
                engine, task_id, stats=stats, fetched=stats.fetched, meta={"dry_run": True}
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

                await record_task_result(
                    engine,
                    task_id,
                    stats=stats,
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
        await record_task_result(engine, task_id, stats=stats, error=stats.error)
    finally:
        stats.duration_s = time.perf_counter() - started
        await connector.aclose()
        # Day17 任务 3.2 / 3.3：采集指标 + 失败率告警评估（旁路，不改变返回语义）
        record_collect(
            source, fetched=stats.fetched, failed=stats.status != "succeeded", duration_s=stats.duration_s
        )
        emit_alerts_safely()
    return stats


def build_cve_connector(source: str, cve_ids: list[str], *, settings: Settings) -> BaseConnector:
    """按源构造「单条采集」用连接器（注入 CVE 参数）。

    Args:
        source: 源标识（须在 :data:`CVE_SOURCES` 内）。
        cve_ids: CVE 编号列表。
        settings: 全局配置。

    Returns:
        采集器实例（调用方负责 ``aclose()``）。
    """
    kwargs = supported_connector_kwargs(settings, source)
    if source == "epss":
        kwargs["cve_ids"] = list(cve_ids)
    return create_connector(source, settings=settings, **kwargs)


async def fetch_cve_items(source: str, connector: BaseConnector, cve_ids: list[str]) -> list[RawItem]:
    """从连接器取指定 CVE 的条目（优先 ``fetch_cves``，否则走增量接口后过滤）。

    Args:
        source: 源标识。
        connector: 已实例化的采集器。
        cve_ids: CVE 编号列表。

    Returns:
        仅包含请求编号的 ``RawItem`` 列表。
    """
    fetcher = getattr(connector, "fetch_cves", None)
    if callable(fetcher):
        items = list(await fetcher(list(cve_ids)))
    else:
        items = list(await connector.fetch_incremental(CVE_LOOKBACK_START))
    wanted = {cve_id.upper() for cve_id in cve_ids}
    return [item for item in items if item.source_id.upper() in wanted]


async def collect_cves(
    cve_ids: Sequence[str],
    *,
    settings: Settings,
    sources: Sequence[str] | None = None,
    dry_run: bool = False,
    normalize: bool = True,
) -> CveCollectResult:
    """按 CVE 单条采集 → 归一化 → 跨源合并 → 写入 ``unified_vuln``（§8.1 最小演示路径）。

    每个源单独登记 ``task_run``（可用 ``--source nvd`` 只跑一条），
    最后把各源结果**合并**成一条实体再 upsert，避免多源互相覆盖（P4 去重语义）。

    Warning:
        ``VulnRepository.upsert`` 对**标量字段**是「后写覆盖」，仅 ``trace_ids`` / ``sources``
        取并集。因此**逐源分开重跑**会让该实体只剩最后一个源的视图（如 ``kev`` / ``epss_score``
        被清空）；需要完整并集时应**一次带上全部相关源**，例如
        ``--source nvd,epss,kev --cve CVE-2024-3400``（演示路径即如此）。

    Args:
        cve_ids: CVE 编号列表（大小写不敏感，去重保序）。
        settings: 全局配置。
        sources: 参与的源；``None`` 时取 :data:`CVE_SOURCES` 与注册表的交集。
        dry_run: ``True`` 时只拉取不落库（仍登记任务）。
        normalize: ``True`` 时走完整 L2 流水线并合并写库。

    Returns:
        :class:`CveCollectResult`。

    Raises:
        ValueError: 未提供任何有效 CVE 编号。
    """
    wanted = normalize_cve_ids(cve_ids)
    if not wanted:
        raise ValueError("--cve 需要至少一个 CVE 编号（如 --cve CVE-2024-3400）")

    registered = set(available_sources())
    resolved = [source for source in (sources or sorted(CVE_SOURCES)) if source in registered and source in CVE_SOURCES]
    result = CveCollectResult(cve_ids=wanted, sources=resolved)
    engine = get_engine(settings)
    batch_at = utc_now()
    merged_vulns: list[UnifiedVuln] = []

    for source in resolved:
        stats = CollectStats(
            source=source,
            since=CVE_LOOKBACK_START,
            mode="by-cve",
            normalize_requested=normalize,
        )
        started = time.perf_counter()
        task_id: int | None = None
        connector: BaseConnector | None = None
        try:
            async with session_scope(engine) as session:
                task_id = await TaskRepository(session).start(
                    source=source,
                    meta={"cve_ids": wanted, "dry_run": dry_run, "normalize": normalize, "mode": "by-cve"},
                )

            connector = build_cve_connector(source, wanted, settings=settings)
            fetched_items, healed_url = await fetch_with_self_heal(
                connector, partial(fetch_cve_items, source, connector, wanted)
            )
            items = list(fetched_items)
            if healed_url:
                stats.extra["self_heal_url"] = healed_url
            stats.fetched = len(items)
            stats.processed = len(items)

            if not dry_run:
                async with session_scope(engine) as session:
                    raw_repo = RawRepository(session)
                    for item in items:
                        upsert = await raw_repo.upsert(item)
                        stats.created += int(upsert.created)
                        stats.skipped += int(not upsert.created)

                if normalize:
                    outcome = normalize_batch(items, source=source, normalized_at=batch_at)
                    stats.norm_failed = outcome.failed_count
                    stats.norm_ok = outcome.ok_count
                    stats.merged_count = outcome.merged_count
                    stats.skipped_count = outcome.folded_count
                    stats.normalized = outcome.merged
                    merged_vulns.extend(outcome.merged)

            await record_task_result(
                engine,
                task_id,
                stats=stats,
                fetched=stats.fetched,
                created=stats.created,
                skipped=stats.skipped,
                meta={
                    "cve_ids": wanted,
                    "normalize": normalize,
                    "merged_count": stats.merged_count,
                    "norm_failed": stats.norm_failed,
                },
            )
            stats.status = "succeeded"
        except Exception as exc:  # noqa: BLE001 - 单源失败不阻断其它源（异常隔离）
            stats.status = "failed"
            stats.error = f"{type(exc).__name__}: {exc}"
            await record_task_result(engine, task_id, stats=stats, error=stats.error)
        finally:
            stats.duration_s = time.perf_counter() - started
            if connector is not None:
                await connector.aclose()
            # Day17 任务 3.2 / 3.3：采集指标 + 失败率告警评估（旁路）
            record_collect(
                source,
                fetched=stats.fetched,
                failed=stats.status != "succeeded",
                duration_s=stats.duration_s,
            )
            emit_alerts_safely()
        result.stats.append(stats)

    if normalize and not dry_run and merged_vulns:
        result.merge = await merge_and_upsert(merged_vulns, settings=settings, engine=engine)
    return result


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




