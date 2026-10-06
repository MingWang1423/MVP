"""失败重试队列入口（Day23 任务 2；PROJECT_PLAN.md §12.19 ``scripts/retry_failed.py``）。

用法::

    python -m scripts.retry_failed                        # 默认：本轮最多 50 条，单条最多重试 3 次
    python -m scripts.retry_failed --limit 5              # 小批量演练
    python -m scripts.retry_failed --cve CVE-2024-27537    # 人工定向重试单条（忽略队列顺序）
    python -m scripts.retry_failed --max-attempts 3        # 覆盖最大重试次数
    python -m scripts.retry_failed --no-llm                # 离线降级（无 Key / 断网，走检索折算）
    python -m scripts.retry_failed --no-persist            # 只跑不落库（演练）
    python -m scripts.retry_failed --list                  # 只列出重试队列，不执行重试

与调度器的关系：``CollectScheduler`` 每日 02:00（cron ``0 2 * * *``）自动跑同一函数
（``maintenance:retry-failed`` job）；本脚本提供等价的**手动触发**入口。

退出码：0 = 本轮全部恢复或队列为空；1 = 存在仍失败 / 永久失败条目；2 = 参数或环境错误。
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
from aisec_intel.services.enrich_service import (  # noqa: E402
    DEFAULT_RETRY_BATCH_SIZE,
    MAX_RETRY_ATTEMPTS,
    RetryReport,
    count_retry_attempts,
    llm_available,
    load_retry_candidates,
    retry_failed,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="富化失败重试队列（needs_human → 自动重试 → 永久失败）")
    parser.add_argument("--limit", type=int, default=DEFAULT_RETRY_BATCH_SIZE, help="本轮最多处理条数")
    parser.add_argument("--max-attempts", type=int, default=MAX_RETRY_ATTEMPTS, help="单条最大重试次数")
    parser.add_argument("--cve", default=None, help="只重试指定漏洞（人工定向，忽略队列顺序）")
    parser.add_argument("--no-llm", action="store_true", help="禁用 LLM（走检索折算降级路径）")
    parser.add_argument("--no-persist", action="store_true", help="只跑不落库（演练）")
    parser.add_argument("--list", action="store_true", help="只列出重试队列后退出")
    parser.add_argument("--verbose", action="store_true", help="打印逐条重试明细")
    return parser.parse_args(argv)


def print_report(report: RetryReport, *, verbose: bool = False, max_attempts: int = MAX_RETRY_ATTEMPTS) -> None:
    """打印一轮重试结果。

    Args:
        report: 重试汇总。
        verbose: 是否打印逐条明细（含已重试次数与失败原因）。
        max_attempts: 最大重试次数（明细里的分母）。
    """
    print(f"\n[失败重试队列] {report.summary()}")
    if verbose:
        for outcome in report.outcomes:
            reason = f" | {outcome.error}" if outcome.error else ""
            print(
                f"  - {outcome.cve_id:<18} 第 {outcome.attempts_after}/{max_attempts} 次 "
                f"状态={outcome.status} 复核={outcome.review_status}{reason}"
            )


async def run(args: argparse.Namespace) -> int:
    """执行失败重试队列。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 全部恢复 / 队列为空；1 存在失败条目）。
    """
    settings = Settings()
    if args.list:
        candidates = await load_retry_candidates(settings, limit=args.limit)
        print(f"[队列] review_status='needs_human' 候选 {len(candidates)} 条（最多显示 {args.limit} 条）")
        for entity in candidates:
            print(f"  - {entity.vuln_id:<18} 已重试={count_retry_attempts(entity)}/{args.max_attempts}")
        return 0

    has_llm = llm_available(settings) and not args.no_llm
    print(
        f"[环境] DSN={settings.effective_storage_dsn} | provider={settings.llm_provider} | "
        f"LLM={'on' if has_llm else 'off（检索折算降级）'} | 上限={args.limit} 条 | "
        f"单条最多重试={args.max_attempts} 次 | persist={not args.no_persist}"
    )
    report = await retry_failed(
        settings,
        limit=args.limit,
        max_attempts=args.max_attempts,
        cve_id=args.cve,
        use_llm=has_llm,
        persist=not args.no_persist,
    )
    print_report(report, verbose=args.verbose or report.scanned > 0, max_attempts=args.max_attempts)
    return 1 if (report.retry_failed or report.permanently_failed) else 0


def main(argv: list[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        进程退出码。
    """
    try:
        return asyncio.run(run(parse_args(argv)))
    except SystemExit as exc:  # pragma: no cover - argparse 自身退出
        print(f"[错误] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
