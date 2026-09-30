"""采集入口脚本（PROJECT_PLAN.md §4.3 / §5.3 P2）。

用法::

    python -m scripts.run_collect --source kev --since 2024-01-01
    python -m scripts.run_collect --source kev --since 2024-01-01 --limit 5
    python -m scripts.run_collect --source all --limit 100
    python -m scripts.run_collect --source kev --dry-run      # 只采集不落库
    python -m scripts.run_collect --list-sources

执行流程：
    1. 解析 ``--since``（缺省取 ``task_repo.last_run_at(source)``，再退化为 ``now - COLLECT_DEFAULT_DAYS``）；
    2. 实例化采集器（限流 / 超时 / 重试由 ``BaseConnector`` + ``HttpClient`` 统一处理）；
    3. 逐条写入 ``raw_item``（内容寻址幂等，重复内容自动跳过）；
    4. 在 ``task_run`` 记录 started / succeeded / failed 与统计；
    5. 打印「拉取 / 处理 / 新增 / 跳过」与耗时。

数据库来源：``DATABASE_URL`` > ``DEGRADED_MODE=true`` 时的 SQLite > ``PG_DSN``（§11.1）。
目标库不可用时脚本会给出可操作提示（例如改用 ``DEGRADED_MODE=true``）。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# 允许在未执行 `pip install -e .` 的情况下直接以 `python -m scripts.run_collect` 运行
_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.connectors import (  # noqa: E402
    BaseConnector,
    UnknownSourceError,
    available_sources,
    create_connector,
)
from aisec_intel.models.base import to_utc, utc_now  # noqa: E402
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.repositories.raw_repo import RawRepository  # noqa: E402
from aisec_intel.storage.repositories.task_repo import TaskRepository  # noqa: E402

ALL_SOURCES = "all"
"""``--source all`` 的取值。"""


@dataclass(slots=True)
class CollectStats:
    """单个源的采集统计。

    Attributes:
        source: 源标识。
        since: 增量起点（UTC）。
        fetched: 源侧拉取条数（过滤后、限制前）。
        processed: 本次处理条数（受 ``--limit`` 限制）。
        created: 新增条数。
        skipped: 跳过条数（指纹已存在）。
        duration_s: 耗时（秒）。
        status: ``succeeded`` / ``failed``。
        error: 失败原因。
        extra: 附加诊断信息。
    """

    source: str
    since: datetime
    fetched: int = 0
    processed: int = 0
    created: int = 0
    skipped: int = 0
    duration_s: float = 0.0
    status: str = "succeeded"
    error: str | None = None
    extra: dict[str, object] = field(default_factory=dict)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="多源安全情报采集入口")
    parser.add_argument("--source", default=None, help="源标识（kev）或 all；逗号分隔可多选")
    parser.add_argument("--since", default=None, help="增量起点：YYYY-MM-DD 或 ISO8601（缺省用上次成功时间）")
    parser.add_argument("--limit", type=int, default=0, help="每个源最多处理条数（0 = 不限）")
    parser.add_argument("--dry-run", action="store_true", help="只采集不落库")
    parser.add_argument("--list-sources", action="store_true", help="列出所有已注册源及其限流配置")
    parser.add_argument("--verbose", action="store_true", help="额外打印采集器元信息")
    return parser.parse_args(argv)


def resolve_sources(source_arg: str | None, *, list_sources: bool) -> list[str]:
    """解析 ``--source`` 参数。

    Args:
        source_arg: 用户传入的源标识（``None`` / ``all`` / 逗号分隔列表）。
        list_sources: 是否为 ``--list-sources`` 模式。

    Returns:
        源标识列表（字典序、去重）。

    Raises:
        SystemExit: 未提供 ``--source`` 且非 ``--list-sources``。
        UnknownSourceError: 出现未注册的源。
    """
    if list_sources:
        return []
    if not source_arg:
        raise SystemExit("缺少 --source（可用 --list-sources 查看已注册源）")
    if source_arg.strip().lower() == ALL_SOURCES:
        return available_sources()
    requested = [part.strip().lower() for part in source_arg.split(",") if part.strip()]
    known = set(available_sources())
    unknown = [name for name in requested if name not in known]
    if unknown:
        raise UnknownSourceError(f"未注册的源 {unknown}；可用源：{sorted(known)}")
    return sorted(set(requested))


async def resolve_since(
    source: str,
    *,
    explicit: datetime | None,
    settings: Settings,
) -> datetime:
    """决定某个源的增量起点。

    优先级：显式传入 > ``task_run`` 上次成功时间 > ``now - COLLECT_DEFAULT_DAYS``。

    Args:
        source: 源标识。
        explicit: 用户显式指定的起点。
        settings: 全局配置。

    Returns:
        UTC ``datetime``。
    """
    if explicit is not None:
        return explicit
    engine = get_engine(settings)
    last: datetime | None = None
    try:
        async with session_scope(engine) as session:
            last = await TaskRepository(session).last_run_at(source)
    except Exception:  # noqa: BLE001 - 首次运行（库/表缺失）时回退默认窗口
        last = None
    if last is not None:
        return last
    return to_utc(utc_now() - timedelta(days=settings.collect_default_days))


async def collect_source(
    source: str,
    *,
    since: datetime,
    limit: int,
    dry_run: bool,
    settings: Settings,
) -> CollectStats:
    """采集单个源并落库。

    Args:
        source: 源标识。
        since: 增量起点（UTC）。
        limit: 最多处理条数（0 表示不限）。
        dry_run: ``True`` 时不写入 ``raw_item``（仍记录任务状态）。
        settings: 全局配置。

    Returns:
        :class:`CollectStats` 统计结果。
    """
    stats = CollectStats(source=source, since=since)
    connector = create_connector(source, settings=settings)
    engine = get_engine(settings)
    started = time.perf_counter()
    task_id: int | None = None
    try:
        async with session_scope(engine) as session:
            task_id = await TaskRepository(session).start(
                source=source,
                meta={"since": since.isoformat(), "limit": limit, "dry_run": dry_run},
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
            async with session_scope(engine) as session:
                raw_repo = RawRepository(session)
                for item in selected:
                    result = await raw_repo.upsert(item)
                    stats.created += int(result.created)
                    stats.skipped += int(not result.created)
                await TaskRepository(session).succeeded(
                    task_id,
                    fetched=stats.fetched,
                    created=stats.created,
                    skipped=stats.skipped,
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


def print_stats(stats: CollectStats, *, verbose: bool = False) -> None:
    """打印单个源的采集统计。

    Args:
        stats: 统计结果。
        verbose: 是否打印附加诊断信息。
    """
    flag = "OK  " if stats.status == "succeeded" else "FAIL"
    print(
        f"[{flag} {stats.source}] since={stats.since.isoformat()} "
        f"拉取={stats.fetched} 处理={stats.processed} 新增={stats.created} "
        f"跳过={stats.skipped} 耗时={stats.duration_s:.2f}s"
    )
    if stats.error:
        print(f"    错误：{stats.error}")
    if verbose and stats.extra:
        print(f"    附加：{stats.extra}")


async def run(args: argparse.Namespace) -> int:
    """执行采集流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 全部成功；1 存在失败源；2 参数或环境错误）。
    """
    settings = Settings()

    if args.list_sources:
        print("已注册源：")
        for name in available_sources():
            connector = create_connector(name, settings=settings)
            info = connector.describe()
            print(f"  - {name}: rate_limit={info['rate_limit']} timeout={info['timeout']}s enabled={info['enabled']}")
            await connector.aclose()
        return 0

    sources = resolve_sources(args.source, list_sources=False)
    explicit_since = BaseConnector.to_utc_datetime(args.since) if args.since else None
    if args.since and explicit_since is None:
        print(f"[错误] 无法解析 --since={args.since!r}")
        return 2

    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode}")
    failures = 0
    for source in sources:
        since = await resolve_since(source, explicit=explicit_since, settings=settings)
        stats = await collect_source(source, since=since, limit=args.limit, dry_run=args.dry_run, settings=settings)
        print_stats(stats, verbose=args.verbose)
        failures += int(stats.status != "succeeded")

    if failures:
        print(f"[提示] 有 {failures} 个源失败；若为数据库不可用，可尝试设置 DEGRADED_MODE=true 后重跑。")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        进程退出码。
    """
    args = parse_args(argv)
    try:
        return asyncio.run(run(args))
    except SystemExit as exc:
        print(f"[错误] {exc}")
        return 2
    except UnknownSourceError as exc:
        print(f"[错误] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
