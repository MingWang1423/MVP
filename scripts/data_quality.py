"""采集数据质量报告（PROJECT_PLAN.md §5.5 P4 / §6.2 P4 验收）。

统计维度（全部离线可复现，不调用 LLM）：

1. **采集条数**：``raw_item`` 表中该源在时间窗内的记录数；
2. **归一化成功率**：对条目重放 L2 纯函数 ``build_unified_vuln``（确定性），
   成功 / 失败条数与成功率；
3. **字段完整率**：``description`` / ``cvss`` / ``cwe`` / ``references`` 四类字段的非空占比；
4. **源覆盖率**：``configs/sources.yaml`` 声明启用的源 vs 实际有数据的源。

输出：``reports/data_quality.md``（Markdown 表格，禁用 CSV 交付，§11.3）。

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
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models.base import iso_z, utc_now  # noqa: E402
from aisec_intel.models.raw_item import RawItem  # noqa: E402
from aisec_intel.normalize.pipeline import build_unified_vuln  # noqa: E402
from aisec_intel.services.collect_service import (  # noqa: E402
    PAPER_SOURCES,
    enabled_sources_from_config,
    parse_since,
    resolve_sources,
)
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.repositories.raw_repo import RawRepository  # noqa: E402

DEFAULT_OUTPUT: str = "reports/data_quality.md"
"""默认报告落点（``reports/`` 允许落文档，§11.3）。"""

FIELD_NAMES: tuple[str, ...] = ("description", "cvss", "cwe", "references")
"""参与字段完整率统计的字段（与 §5.5 要求一致）。"""

MAX_ROWS_PER_SOURCE: int = 10000
"""单源最多读取的 ``raw_item`` 行数（``--limit 0`` 时使用，防止超大库拖垮脚本）。"""


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
        """归一化成功率（无数据时返回 0.0）。"""
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


def evaluate_all(
    grouped: dict[str, list[RawItem]],
    *,
    sources: list[str],
) -> list[SourceQuality]:
    """对全部指定源做评估（含「零数据」源，便于暴露采集缺口）。

    Args:
        grouped: ``collect_raw_items`` 的输出。
        sources: 期望统计的源标识列表（顺序被保留）。

    Returns:
        :class:`SourceQuality` 列表。
    """
    qualities = [evaluate_source(source, grouped.get(source, [])) for source in sources]
    qualities.sort(key=lambda item: (item.kind, item.source))
    return qualities


def _pct(value: float) -> str:
    """把比率格式化为百分比文本。"""
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
            f"{item.normalized_ok} | {item.normalized_failed} | {_pct(item.success_rate)} |"
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
        cells = " | ".join(_pct(item.completeness(name)) for name in FIELD_NAMES)
        lines.append(f"| {item.source} | {cells} |")

    missing = [name for name in declared if name not in with_data]
    lines += [
        "",
        "## 3. 源覆盖率",
        "",
        f"- 声明启用源：{len(declared)} 个 → {'、'.join(declared) if declared else '（无）'}",
        f"- 实际有数据源：{len(with_data)} 个 → {'、'.join(with_data) if with_data else '（无）'}",
        f"- **源覆盖率：{_pct(coverage)}**",
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
        lines.append(
            f"- 四字段平均完整率："
            f"description={_pct(sum(item.field_complete.get('description', 0) for item in qualities) / total_ok)}、"
            f"cvss={_pct(sum(item.field_complete.get('cvss', 0) for item in qualities) / total_ok)}、"
            f"cwe={_pct(sum(item.field_complete.get('cwe', 0) for item in qualities) / total_ok)}、"
            f"references={_pct(sum(item.field_complete.get('references', 0) for item in qualities) / total_ok)}"
        )
    lines += [
        "- 备注：论文源（arxiv / openalex）在 P4 只落 `raw_item`，不写入 `unified_vuln`，"
        "其 `cvss` / `cwe` 完整率天然为 0%（P6 由论文实体与图谱承载）。",
        "",
    ]
    return "\n".join(lines)


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
            f"归一化成功率={_pct(item.success_rate):<7} "
            f"完整率(desc/cvss/cwe/ref)="
            + "/".join(_pct(item.completeness(name)) for name in FIELD_NAMES)
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


