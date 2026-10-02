"""采集数据质量报告（PROJECT_PLAN.md §5.5 P4 / §6.2 P4 验收）。

统计维度（全部离线可复现，不调用 LLM）：

1. **采集条数**：``raw_item`` 表中该源在时间窗内的记录数；
2. **归一化成功率**：对条目重放 L2 纯函数 ``build_unified_vuln``（确定性），
   成功 / 失败条数与成功率；
3. **字段完整率**：``description`` / ``cvss`` / ``cwe`` / ``references`` 四类字段的非空占比；
4. **源覆盖率**：``configs/sources.yaml`` 声明启用的源 vs 实际有数据的源。

输出：``reports/data_quality.md``（Markdown 表格，禁用 CSV 交付，§11.3）。

Note:
    纯函数（:class:`SourceQuality` / :func:`evaluate_source` / :func:`evaluate_all` /
    :func:`render_markdown`）已于 Day16 下沉到
    :mod:`aisec_intel.services.quality_service`，供 ``GET /api/v1/data-quality`` 与
    本脚本**共用同一份口径**；本模块保留同名再导出，保证既有调用方（含单测）不受影响。

用法::

    python -m scripts.data_quality                              # 全量窗口
    python -m scripts.data_quality --since 2024-01-01
    python -m scripts.data_quality --days 7 --source nvd,kev
    python -m scripts.data_quality --limit 500 --out reports/data_quality.md

退出码：0 生成成功；1 数据库不可用（例如未起 PostgreSQL，可设置 DEGRADED_MODE=true）。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models.base import iso_z, utc_now  # noqa: E402
from aisec_intel.models.raw_item import RawItem  # noqa: E402
from aisec_intel.services.collect_service import (  # noqa: E402
    enabled_sources_from_config,
    parse_since,
    resolve_sources,
)
from aisec_intel.services.quality_service import (  # noqa: E402
    FIELD_NAMES,
    MAX_ROWS_PER_SOURCE,
    SourceQuality,
    evaluate_all,
    evaluate_source,
    format_percent,
    render_markdown,
)
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.repositories.raw_repo import RawRepository  # noqa: E402

DEFAULT_OUTPUT: str = "reports/data_quality.md"
"""默认报告落点（``reports/`` 允许落文档，§11.3）。"""

__all__ = [
    "DEFAULT_OUTPUT",
    "FIELD_NAMES",
    "MAX_ROWS_PER_SOURCE",
    "SourceQuality",
    "collect_raw_items",
    "evaluate_all",
    "evaluate_source",
    "main",
    "parse_args",
    "render_markdown",
    "run",
]


async def collect_raw_items(
    settings: Settings,
    *,
    sources: list[str],
    since: datetime | None = None,
    limit: int = 0,
) -> dict[str, list[RawItem]]:
    """从 ``raw_item`` 表按源读取条目（一次会话内完成，避免频繁建连）。

    Args:
        settings: 全局配置。
        sources: 源标识列表。
        since: 仅统计该时间之后的记录（UTC）；``None`` 表示全量。
        limit: 每源最多读取条数（0 表示使用 :data:`MAX_ROWS_PER_SOURCE`）。

    Returns:
        ``{源标识: [RawItem, ...]}``。
    """
    row_limit = limit if limit > 0 else MAX_ROWS_PER_SOURCE
    result: dict[str, list[RawItem]] = {}
    async with session_scope(get_engine(settings)) as session:
        repo = RawRepository(session)
        for source in sources:
            result[source] = await repo.list_by_source(source, limit=row_limit, since=since)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="采集数据质量报告（Markdown）")
    parser.add_argument("--since", default=None, help="统计起点：YYYY-MM-DD 或 ISO8601（缺省 = 全量）")
    parser.add_argument("--days", type=int, default=0, help="统计最近 N 天（未指定 --since 时生效）")
    parser.add_argument("--source", default=None, help="只统计指定源（逗号分隔）；缺省 = sources.yaml 启用源")
    parser.add_argument("--limit", type=int, default=0, help="每源最多评估条数（0 = 默认上限 10000）")
    parser.add_argument("--out", default=DEFAULT_OUTPUT, help=f"报告输出路径（默认 {DEFAULT_OUTPUT}；'-' = 只打印）")
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    """生成数据质量报告。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 成功；1 数据库不可用；2 参数错误）。
    """
    settings = Settings()
    since = parse_since(args.since)
    if args.since and since is None:
        print(f"[错误] 无法解析 --since={args.since!r}")
        return 2
    if since is None and args.days > 0:
        since = utc_now() - timedelta(days=args.days)

    declared = enabled_sources_from_config(settings)
    sources = resolve_sources(args.source, list_sources=False) if args.source else declared
    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode}")
    print(f"[窗口] since={iso_z(since) if since else '全量'} | 统计源={sources}")

    try:
        grouped = await collect_raw_items(settings, sources=sources, since=since, limit=args.limit)
    except Exception as exc:  # noqa: BLE001 - CLI 需给出可操作提示
        print(f"[失败] {type(exc).__name__}: {exc}")
        print("[提示] 数据库不可用时可设置 DEGRADED_MODE=true 后重跑（SQLite 降级）。")
        return 1

    qualities = evaluate_all(grouped, sources=sources)
    markdown = render_markdown(
        qualities, declared=declared, since=since, generated_at=utc_now(), limit=args.limit
    )
    for item in qualities:
        print(
            f"  {item.source:<10} 类型={item.kind:<5} 采集={item.raw_count:<6} "
            f"归一化成功率={format_percent(item.success_rate):<7} "
            f"完整率(desc/cvss/cwe/ref)="
            + "/".join(format_percent(item.completeness(name)) for name in FIELD_NAMES)
        )

    if args.out.strip() == "-":
        print(markdown)
        return 0
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown, encoding="utf-8")
    print(f"[完成] 报告已写入 {target.resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        进程退出码。
    """
    return asyncio.run(run(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())


