"""调度器启动入口（PROJECT_PLAN.md §5.5 P4；Day19 分层 pipeline）。

用法::

    python -m scripts.run_scheduler --list                         # 只打印调度计划（按配置模式）
    python -m scripts.run_scheduler --list --mode per-source       # 看原来的「每源一个 job」计划
    python -m scripts.run_scheduler                                # 常驻（分层 pipeline，Ctrl+C 优雅退出）
    python -m scripts.run_scheduler --mode per-source              # 每源一个 job（原逻辑，仍可选）
    python -m scripts.run_scheduler --collect-mode full --limit 200  # 全量采集语义
    python -m scripts.run_scheduler --no-graph --no-vector         # 只跑采集 + 富化两层
    python -m scripts.run_scheduler --source kev,epss              # 只调度指定源（pipeline 采集层生效）
    python -m scripts.run_scheduler --run-now                      # 启动即触发一轮，再按间隔调度
    python -m scripts.run_scheduler --once                         # 跑一轮后退出（CI / 冒烟）
    python -m scripts.run_scheduler --run-now --run-seconds 120    # 运行 120 秒后优雅停机（演练）

调度布局（``--mode``，优先级：**CLI > 环境变量 > configs/sources.yaml > 默认**）：

- ``pipeline``（默认）：采集 2h / 富化 6h / 图谱 12h / 向量 12h，共 4 个 job；
  首次触发按 0/10/20/30 分钟错开（``--run-now`` / ``--once`` 时四层立即各触发一轮，覆盖错开）。
- ``per-source``：每个启用源一个 job，间隔取 ``sources.yaml`` 的 ``interval_minutes``。

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

from aisec_intel.config import (  # noqa: E402
    PIPELINE_STAGES,
    SCHEDULER_MODES,
    Settings,
    load_sources_config,
)
from aisec_intel.connectors import UnknownSourceError  # noqa: E402
from aisec_intel.services.collect_service import ALL_SOURCES, resolve_sources  # noqa: E402
from aisec_intel.services.scheduler import CollectScheduler, resolve_scheduler_mode  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="多源采集调度器（APScheduler，支持分层 pipeline）")
    parser.add_argument("--source", default=None, help=f"只调度指定源（逗号分隔）或 {ALL_SOURCES}")
    parser.add_argument(
        "--mode",
        choices=[*SCHEDULER_MODES, "per-source"],
        default=None,
        help="调度布局：pipeline=分层流水线（默认，4 个 job）；per-source=每源一个 job（原逻辑）",
    )
    parser.add_argument(
        "--collect-mode",
        choices=["incremental", "full"],
        default="incremental",
        help="采集语义：incremental=按 task_run 游标增量（默认）；full=从 2024-01-01 全量拉",
    )
    parser.add_argument("--limit", type=int, default=0, help="每个源每轮最多处理条数（0 = 不限）")
    parser.add_argument(
        "--normalize",
        action="store_true",
        help="per-source 模式同步归一化（pipeline 采集层固定开启，此开关只影响 per-source）",
    )
    parser.add_argument("--run-now", action="store_true", help="启动立即触发一轮（随后按间隔调度）")
    parser.add_argument("--once", action="store_true", help="跑完一轮即退出（隐含 --run-now）")
    parser.add_argument("--run-seconds", type=float, default=0.0, help="运行指定秒数后优雅停机（0 = 常驻）")
    parser.add_argument("--shutdown-timeout", type=float, default=30.0, help="优雅停机等待上限（秒）")
    parser.add_argument("--list", action="store_true", help="只打印调度计划（当前模式 + job 列表），不启动")
    parser.add_argument(
        "--collect",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="pipeline 采集层开关（默认开；--no-collect 关闭）",
    )
    parser.add_argument(
        "--enrich",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="pipeline 富化层开关（默认开；--no-enrich 关闭）",
    )
    parser.add_argument(
        "--graph",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="pipeline 图谱层开关（默认开；--no-graph 关闭）",
    )
    parser.add_argument(
        "--vector",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="pipeline 向量层开关（默认开；--no-vector 关闭）",
    )
    return parser.parse_args(argv)


def resolve_pipeline_stages(args: argparse.Namespace) -> list[str]:
    """按 ``--collect/--enrich/--graph/--vector`` 开关解析参与调度的阶段。

    Args:
        args: 命令行参数。

    Returns:
        启用中的阶段名列表（顺序固定为 采集 → 富化 → 图谱 → 向量）。
    """
    return [stage for stage in PIPELINE_STAGES if getattr(args, stage) is not False]


def print_plan(scheduler: CollectScheduler) -> None:
    """打印调度计划（pipeline 四层 / per-source 每源）。

    Args:
        scheduler: 调度器实例（已 ``build_plan``）。
    """
    if scheduler.is_pipeline:
        active = [spec for spec in scheduler.pipeline_specs if spec.enabled]
        print(
            f"[调度计划] 模式=pipeline（分层流水线），共 {len(active)} 个 job，"
            f"collect_mode={scheduler.collect_mode}"
        )
        for pipe_spec in scheduler.pipeline_specs:
            flag = "" if pipe_spec.enabled else "  [已关闭]"
            print(
                f"  - {pipe_spec.job_id:<16} 每 {pipe_spec.interval_hours:>2} 小时  "
                f"首触发=+{pipe_spec.initial_offset_minutes:>2} 分钟  {pipe_spec.command}{flag}"
            )
        return
    print(
        f"[调度计划] 模式=per_source（每源一个 job），共 {len(scheduler.specs)} 个源，"
        f"collect_mode={scheduler.collect_mode}"
    )
    for source_spec in scheduler.specs:
        params = ", ".join(f"{key}={value}" for key, value in source_spec.parameters.items()) or "-"
        print(
            f"  - {source_spec.source:<10} 每 {source_spec.interval_minutes:>4} 分钟  "
            f"config={source_spec.config_source}  {params}"
        )


def print_summary(scheduler: CollectScheduler) -> None:
    """打印本次运行的汇总（pipeline 层粒度 + 采集源粒度）。

    Args:
        scheduler: 调度器实例（含 ``pipeline_history`` / ``stats_history``）。
    """
    if scheduler.is_pipeline:
        print(f"\n[分层汇总] pipeline 阶段共执行 {len(scheduler.pipeline_history)} 次")
        for stage in scheduler.pipeline_history:
            flag = "OK  " if stage.status == "succeeded" else "FAIL"
            print(f"  [{flag} {stage.stage:<7}] {stage.detail} 耗时={stage.duration_s:.2f}s")
            if stage.error:
                print(f"      错误：{stage.error}")
    print(f"\n[采集汇总] 共执行 {len(scheduler.stats_history)} 个源 job")
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
    config = load_sources_config(settings=settings)
    scheduler_mode = resolve_scheduler_mode(args.mode, settings=settings, config=config)
    stages = resolve_pipeline_stages(args)
    sources = resolve_sources(args.source, list_sources=False) if args.source else None
    scheduler = CollectScheduler(
        settings=settings,
        config=config,
        mode=args.collect_mode,
        limit=args.limit,
        normalize=args.normalize,
        sources=sources,
        run_immediately=args.run_now or args.once,
        shutdown_timeout=args.shutdown_timeout,
        scheduler_mode=scheduler_mode,
        pipeline_stages=stages,
    )
    scheduler.build_plan()
    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode}")
    if scheduler.is_pipeline and not stages:
        print("[警告] 四层全部被 --no-* 关闭，将不会注册任何 job。")
    print_plan(scheduler)

    if args.list:
        return 0

    if args.once:
        scheduler.start()
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
    _make_console_robust()
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


def _make_console_robust() -> None:
    """让控制台输出「不可编码字符 → ``?``」而不是抛 ``UnicodeEncodeError``。

    Windows 控制台默认 GBK：pipeline 子进程的输出摘要可能含 GBK 无法编码的字符
    （Day19 实测：``load_graph`` 的 SQL 报错回显里带 ``U+FFFD``），一旦 ``print`` 抛异常
    就会中断运行汇总。这里只放宽编码错误策略，不改变正常输出。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover - 非文本流（pytest 捕获 / 重定向对象）
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):  # pragma: no cover - 已关闭的流
            continue


if __name__ == "__main__":
    raise SystemExit(main())
