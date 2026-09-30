"""采集入口脚本（PROJECT_PLAN.md §5.5 P4 CLI）。

核心逻辑全部在 :mod:`aisec_intel.services.collect_service`（CLI 与调度器共用同一份实现），
本脚本只负责**参数解析、打印与退出码**。

用法::

    python -m scripts.run_collect --source kev --since 2024-01-01
    python -m scripts.run_collect --source all --mode incremental --days 7 --normalize
    python -m scripts.run_collect --source all --mode full --limit 2000
    python -m scripts.run_collect --source arxiv --limit 3            # 论文源（只落 raw_item）
    python -m scripts.run_collect --source kev --dry-run              # 只采集不落库
    python -m scripts.run_collect --list-sources

执行流程：
    1. 解析起点（``--since`` > ``--days`` > ``--mode full`` 固定起点
       > ``task_repo.last_run_at(source)`` > ``now - COLLECT_DEFAULT_DAYS``）；
    2. 实例化采集器（限流 / 超时 / 重试由 ``BaseConnector`` + ``HttpClient`` 统一处理；
       ``--limit`` 同时作为 ``max_records`` 让采集器提前止损）；
    3. 逐条写入 ``raw_item``（内容寻址幂等，重复内容自动跳过）；
    4. ``--normalize`` 时先收集全部 ``UnifiedVuln``，调用 ``merge_unified_vulns`` **合并后**
       再 upsert 到 ``unified_vuln``（单源内合并 + 多源跨源合并）；论文源（arxiv/openalex）不写漏洞表；
    5. 每个源在 ``task_run`` 记录 started / succeeded / failed 与统计；
    6. 打印「合并 / 折叠 / 新增 / 更新」与耗时；多源运行时追加**跨源合并**汇总行。

数据库来源：``DATABASE_URL`` > ``DEGRADED_MODE=true`` 时的 SQLite > ``PG_DSN``（§11.1）。
目标库不可用时脚本会给出可操作提示（例如改用 ``DEGRADED_MODE=true``）。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# 允许在未执行 `pip install -e .` 的情况下直接以 `python -m scripts.run_collect` 运行
_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.connectors import UnknownSourceError, available_sources, create_connector  # noqa: E402
from aisec_intel.services.collect_service import (  # noqa: E402
    ALL_SOURCES,
    FULL_MODE_START,
    PAPER_SOURCES,
    CollectStats,
    collect_source,
    enabled_sources_from_config,
    merge_and_upsert,
    parse_since,
    print_stats,
    resolve_since,
    resolve_sources,
)

__all__ = [
    "ALL_SOURCES",
    "FULL_MODE_START",
    "PAPER_SOURCES",
    "CollectStats",
    "collect_source",
    "enabled_sources_from_config",
    "main",
    "merge_and_upsert",
    "parse_args",
    "parse_since",
    "print_stats",
    "resolve_since",
    "resolve_sources",
    "run",
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="多源安全情报采集入口")
    parser.add_argument("--source", default=None, help=f"源标识（kev）或 {ALL_SOURCES}；逗号分隔可多选")
    parser.add_argument("--since", default=None, help="增量起点：YYYY-MM-DD 或 ISO8601（缺省用上次成功时间）")
    parser.add_argument(
        "--mode",
        choices=["incremental", "full"],
        default="incremental",
        help="incremental=按游标增量（默认）；full=从固定起点（2024-01-01）全量",
    )
    parser.add_argument("--days", type=int, default=0, help="显式回看天数（覆盖游标；0 = 不指定）")
    parser.add_argument("--limit", type=int, default=0, help="每个源最多处理条数（0 = 不限）")
    parser.add_argument("--dry-run", action="store_true", help="只采集不落库")
    parser.add_argument(
        "--normalize",
        action="store_true",
        help="落库后同步归一化：RawItem → build_unified_vuln → merge_unified_vulns → unified_vuln",
    )
    parser.add_argument("--list-sources", action="store_true", help="列出所有已注册源及其限流配置")
    parser.add_argument("--verbose", action="store_true", help="额外打印采集器元信息")
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    """执行采集流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 全部成功；1 存在失败源；2 参数或环境错误）。
    """
    settings = Settings()

    if args.list_sources:
        print("[已注册源]")
        for name in available_sources():
            connector = create_connector(name, settings=settings)
            info = connector.describe()
            print(
                f"  - {name:<10} rate_limit={info['rate_limit']:<6} "
                f"timeout={info['timeout']}s enabled={info['enabled']}"
            )
            await connector.aclose()
        return 0

    sources = resolve_sources(args.source, list_sources=False)
    explicit_since = parse_since(args.since)
    if args.since and explicit_since is None:
        print(f"[错误] 无法解析 --since={args.since!r}")
        return 2

    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode} | mode={args.mode}")
    failures = 0
    results: list[CollectStats] = []
    for source in sources:
        since = await resolve_since(
            source,
            explicit=explicit_since,
            days=args.days or None,
            mode=args.mode,
            settings=settings,
        )
        stats = await collect_source(
            source,
            since=since,
            settings=settings,
            limit=args.limit,
            dry_run=args.dry_run,
            normalize=args.normalize,
            mode=args.mode,
        )
        print_stats(stats, verbose=args.verbose)
        results.append(stats)
        failures += int(stats.status != "succeeded")

    if args.normalize and not args.dry_run and len(sources) > 1:
        collected = [vuln for stats in results for vuln in stats.normalized]
        if collected:
            outcome = await merge_and_upsert(collected, settings=settings)
            print(
                f"[跨源合并] 归一化 {outcome.input_count} 条 → 合并 {outcome.merged_count} 条实体"
                f"（折叠 {outcome.folded_count}，新增 {outcome.created}，更新 {outcome.updated}）"
            )

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

