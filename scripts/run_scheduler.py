"""调度器启动入口（PROJECT_PLAN.md §5.5 P4）。

用法::

    python -m scripts.run_scheduler --list                       # 只打印调度计划
    python -m scripts.run_scheduler --mode incremental           # 常驻（Ctrl+C 优雅退出）
    python -m scripts.run_scheduler --mode full --limit 200      # 全量模式
    python -m scripts.run_scheduler --source kev,epss            # 只调度指定源
    python -m scripts.run_scheduler --run-now                    # 启动即触发一轮，再按间隔调度
    python -m scripts.run_scheduler --once                       # 跑一轮后退出（CI / 冒烟）
    python -m scripts.run_scheduler --run-seconds 30             # 运行 30 秒后优雅停机（演练）

退出码：0 正常结束；1 环境或参数错误；2 无法解析参数。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.connectors import UnknownSourceError  # noqa: E402
from aisec_intel.services.collect_service import ALL_SOURCES, resolve_sources  # noqa: E402
from aisec_intel.services.scheduler import CollectScheduler  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="多源采集调度器（APScheduler）")
    parser.add_argument("--source", default=None, help=f"只调度指定源（逗号分隔）或 {ALL_SOURCES}")
    parser.add_argument(
        "--mode",
        choices=["incremental", "full"],
        default="incremental",
        help="incremental=按 task_run 游标增量（默认）；full=从 2024-01-01 全量拉",
    )
    parser.add_argument("--limit", type=int, default=0, help="每个源每轮最多处理条数（0 = 不限）")
    parser.add_argument("--normalize", action="store_true", help="同步归一化并合并写入 unified_vuln")
    parser.add_argument("--run-now", action="store_true", help="启动立即触发一轮（随后按间隔调度）")
    parser.add_argument("--once", action="store_true", help="跑完一轮即退出（隐含 --run-now）")
    parser.add_argument("--run-seconds", type=float, default=0.0, help="运行指定秒数后优雅停机（0 = 常驻）")
    parser.add_argument("--shutdown-timeout", type=float, default=30.0, help="优雅停机等待上限（秒）")
    parser.add_argument("--list", action="store_true", help="只打印调度计划，不启动")
    return parser.parse_args(argv)


def print_plan(scheduler: CollectScheduler) -> None:
    """打印调度计划（源 / 间隔 / 参数）。

    Args:
        scheduler: 调度器实例（已 ``build_specs``）。
    """
    print(f"[调度计划] 共 {len(scheduler.specs)} 个源，mode={scheduler._mode}")  # noqa: SLF001 - CLI 展示内部模式
    for spec in scheduler.specs:
        params = ", ".join(f"{key}={value}" for key, value in spec.parameters.items()) or "-"
        print(f"  - {spec.source:<10} 每 {spec.interval_minutes:>4} 分钟  config={spec.config_source}  {params}")


def print_summary(scheduler: CollectScheduler) -> None:
    """打印本轮/本次运行的采集汇总。

    Args:
        scheduler: 调度器实例（含 ``stats_history``）。
    """
    print(f"\n[运行汇总] 共执行 {len(scheduler.stats_history)} 个 job")
    for stats in scheduler.stats_history:
        flag = "OK  " if stats.status == "succeeded" else "FAIL"
        print(
            f"  [{flag} {stats.source}] 拉取={stats.fetched} 处理={stats.processed} "
            f"新增={stats.created} 合并={stats.merged_count} 折叠={stats.skipped_count} "
            f"耗时={stats.duration_s:.2f}s"
        )
        if stats.error:
            print(f"      错误：{stats.error}")


async def run(args: argparse.Namespace) -> int:
    """启动调度器。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码。
    """
    settings = Settings()
    sources = resolve_sources(args.source, list_sources=False) if args.source else None
    scheduler = CollectScheduler(
        settings=settings,
        mode=args.mode,
        limit=args.limit,
        normalize=args.normalize,
        sources=sources,
        run_immediately=args.run_now or args.once,
        shutdown_timeout=args.shutdown_timeout,
    )
    scheduler.build_specs()
    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode}")
    print_plan(scheduler)

    if args.list:
        return 0

    if args.once:
        await scheduler.start()
        await scheduler.wait_until_idle(timeout=args.shutdown_timeout)
        await scheduler.shutdown()
        print_summary(scheduler)
        return 0

    if args.run_seconds > 0:
        stop = asyncio.Event()
        asyncio.get_running_loop().call_later(args.run_seconds, stop.set)
        await scheduler.serve_forever(stop_event=stop)
        print_summary(scheduler)
        return 0

    print("[提示] 调度器常驻中，Ctrl+C（SIGINT）或 SIGTERM 触发优雅停机。")
    await scheduler.serve_forever()
    print_summary(scheduler)
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
    except RuntimeError as exc:
        print(f"[错误] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
