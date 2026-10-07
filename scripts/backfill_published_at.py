"""发布时间回填脚本（Day26；见 PROJECT_PLAN.md §12.22 与 §10.1 时间口径）。

背景：``unified_vuln.published_at`` 曾出现「被入库时间冒充」的问题（API 层
``published_at or normalized_at`` 兜底、EPSS 行的模型评分日期被当成发布时间）。修复后
（Day26）发布时间**只取源侧字段**，历史数据因此需要按新口径回填：

1. 读全部 ``raw_item``（保真原文，内容寻址，保留可审计版本历史）；
2. 逐条走既有归一化路径 :func:`aisec_intel.normalize.pipeline.build_unified_vuln` 重算发布时间
   （纯函数，保证与「重新归一化」结果一致，不另写一套解析逻辑）；
3. 按主键（:func:`aisec_intel.normalize.dedupe.primary_key`，CVE 优先）聚合，取**最早**非空值
   （与 ``merge_group`` / ``merge_for_update`` 的合并规则一致）；
4. 与库中现值比较，**只更新确有差异的行**；默认不把「非空」置为 ``NULL``（需 ``--null-out``）。

用法::

    python -m scripts.backfill_published_at                      # dry-run：只报告差异与覆盖率
    python -m scripts.backfill_published_at --apply              # 写库（仅非空更新）
    python -m scripts.backfill_published_at --apply --null-out   # 同时把「重算为空」的行置 NULL
    python -m scripts.backfill_published_at --limit 500          # 小样本演练
    python -m scripts.backfill_published_at --dsn sqlite+aiosqlite:///./data/aisec.db
    python -m scripts.backfill_published_at --verbose            # 打印逐条变更明细

输出：``updated X / unchanged Y / nulled Z / skipped-null N / unresolved W`` + 按源统计的
发布时间覆盖率（回填前 → 回填后）。
退出码：``0`` = 成功（含无差异）；``1`` = 读库 / 写库失败。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sqlalchemy import select, update  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models.base import iso_z  # noqa: E402
from aisec_intel.models.raw_item import RawItem  # noqa: E402
from aisec_intel.normalize.dedupe import primary_key  # noqa: E402
from aisec_intel.normalize.pipeline import build_unified_vuln  # noqa: E402
from aisec_intel.storage.database import create_engine, session_scope  # noqa: E402
from aisec_intel.storage.models.raw import RawItemRow  # noqa: E402
from aisec_intel.storage.models.vuln import UnifiedVulnRow  # noqa: E402

VulnSnapshot = tuple[str, list[str] | None, datetime | None]
"""库中一行 ``unified_vuln`` 的只读快照：``(vuln_id, sources, published_at)``。"""


@dataclass(frozen=True, slots=True)
class BackfillPlan:
    """回填计划（dry-run 与 ``--apply`` 共用同一份计算结果）。

    Attributes:
        targets: 所有「能被 raw_item 覆盖到」的主键 → 重算后的发布时间（可能为 ``None``）。
        changes: 需要写入的差异行（``vuln_id`` → 新值）；非空更新 + 允许的空值更新。
        skipped_nulls: 重算为空但**未**写入的行（``vuln_id`` → 现值），``--null-out`` 关闭时出现。
        unresolved: 库中存在、但没有任何 raw_item 能映射到的主键（保持原值不动）。
        before: 回填前按源统计的 ``(总数, 有发布时间数)``。
        after: 回填后（计划生效后）按源统计的同口径覆盖数。
    """

    targets: dict[str, datetime | None]
    changes: dict[str, datetime | None]
    skipped_nulls: dict[str, datetime | None]
    unresolved: list[str]
    before: dict[str, tuple[int, int]]
    after: dict[str, tuple[int, int]]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="按 Day26 时间口径回填 unified_vuln.published_at（默认 dry-run）")
    parser.add_argument("--apply", action="store_true", help="真正写库（缺省为 dry-run，只报告）")
    parser.add_argument(
        "--null-out",
        action="store_true",
        help="允许把「重算为空」的行置 NULL（如 EPSS 单源行的模型日期）；不加则只报告不写",
    )
    parser.add_argument("--limit", type=int, default=None, help="最多处理的 raw_item 条数（演练用）")
    parser.add_argument("--dsn", default=None, help="覆盖 DSN（缺省取 Settings.effective_storage_dsn）")
    parser.add_argument("--verbose", action="store_true", help="打印逐条变更明细")
    return parser.parse_args(argv)


def as_utc(value: datetime | None) -> datetime | None:
    """把不确定时区的时间视为 UTC（SQLite 降级模式会回传 naive 时间）。

    Args:
        value: 任意时间或 ``None``。

    Returns:
        带 UTC 时区的时间；``None`` 原样返回。
    """
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def same_moment(left: datetime | None, right: datetime | None) -> bool:
    """判断两个时间是否为同一时刻（容忍 1 秒内的存储精度差）。

    Args:
        left: 时间 A。
        right: 时间 B。

    Returns:
        同一时刻返回 ``True``。
    """
    left_utc, right_utc = as_utc(left), as_utc(right)
    if left_utc is None or right_utc is None:
        return left_utc is None and right_utc is None
    return abs((left_utc - right_utc).total_seconds()) < 1.0


def coverage_by_source(rows: list[VulnSnapshot]) -> dict[str, tuple[int, int]]:
    """按源统计发布时间覆盖率（一条多源记录对每个源各计一次）。

    Args:
        rows: ``unified_vuln`` 只读快照列表。

    Returns:
        ``{源: (总数, 有发布时间数)}``（按源名排序）。
    """
    stats: dict[str, list[int]] = {}
    for _vuln_id, sources, published in rows:
        for source in sorted(set(sources or [])):
            bucket = stats.setdefault(source, [0, 0])
            bucket[0] += 1
            if published is not None:
                bucket[1] += 1
    return {source: (total, hits) for source, (total, hits) in sorted(stats.items())}


def format_coverage(
    stats: dict[str, tuple[int, int]],
    *,
    previous: dict[str, tuple[int, int]] | None = None,
) -> str:
    """把覆盖率统计渲染成多行文本。

    Args:
        stats: ``{源: (总数, 有发布时间数)}``。
        previous: 回填前的同口径统计；给出时在行尾附「回填前」对照。

    Returns:
        多行文本（每源一行）。
    """
    if not stats:
        return "  （无数据）"
    lines: list[str] = []
    for source, (total, hits) in stats.items():
        percent = (hits / total * 100) if total else 0.0
        before = ""
        if previous is not None and source in previous:
            before = f"  ← 回填前 {previous[source][1]}/{previous[source][0]}"
        lines.append(f"  - {source:<14} {hits}/{total} ({percent:.1f}%){before}")
    return "\n".join(lines)


def recompute_targets(raw_items: list[RawItem]) -> tuple[dict[str, datetime | None], int]:
    """用既有归一化路径重算每个主键的发布时间（纯函数，不重复实现解析逻辑）。

    合并口径与 :func:`aisec_intel.normalize.dedupe.merge_group` 一致：同一主键的多个采集件
    取**最早**的非空发布时间；全部为空则结果为 ``None``（源未提供，不取入库时间兜底）。

    Args:
        raw_items: L1 采集件列表（``raw_item`` 表全量或其子集）。

    Returns:
        ``(targets, failed)``：``targets`` 为 ``主键 → 重算值``；``failed`` 为无法确定
        ``vuln_id`` 的脏数据条数（与 :func:`~aisec_intel.normalize.pipeline.build_many`
        同一策略：跳过）。
    """
    grouped: dict[str, list[datetime]] = {}
    failed = 0
    for raw in raw_items:
        try:
            entity = build_unified_vuln(raw, normalized_at=raw.fetched_at)
        except ValueError:  # 既非规范 ID 也无 source_id：与 build_many 一致地跳过
            failed += 1
            continue
        bucket = grouped.setdefault(primary_key(entity), [])
        if entity.published_at is not None:
            bucket.append(entity.published_at)
    return {key: (min(values) if values else None) for key, values in grouped.items()}, failed


def build_plan(vuln_rows: list[VulnSnapshot], targets: dict[str, datetime | None], *, null_out: bool) -> BackfillPlan:
    """对比「重算值」与「库中现值」，生成回填计划（纯函数）。

    Args:
        vuln_rows: ``unified_vuln`` 只读快照。
        targets: :func:`recompute_targets` 的输出。
        null_out: 是否允许把「重算为空」的行置 ``NULL``（``False`` 时只记录不写）。

    Returns:
        :class:`BackfillPlan`（含变更明细与「前 / 后」覆盖率对照）。
    """
    changes: dict[str, datetime | None] = {}
    skipped: dict[str, datetime | None] = {}
    unresolved: list[str] = []
    planned: list[VulnSnapshot] = []
    for vuln_id, sources, current in vuln_rows:
        if vuln_id not in targets:
            # 没有任何 raw_item 能映射到该主键（如别名归一化后的历史残留）：保持原值不动
            unresolved.append(vuln_id)
            planned.append((vuln_id, sources, current))
            continue
        target = targets[vuln_id]
        if same_moment(current, target):
            planned.append((vuln_id, sources, current))
            continue
        if target is None and not null_out:
            skipped[vuln_id] = current
            planned.append((vuln_id, sources, current))
            continue
        changes[vuln_id] = target
        planned.append((vuln_id, sources, target))
    return BackfillPlan(
        targets=targets,
        changes=changes,
        skipped_nulls=skipped,
        unresolved=unresolved,
        before=coverage_by_source(vuln_rows),
        after=coverage_by_source(planned),
    )


async def load_vuln_rows(session: AsyncSession) -> list[VulnSnapshot]:
    """读取全部 ``unified_vuln`` 的发布时间快照（只取三列，避免拉取大 JSON 字段）。

    Args:
        session: 异步会话。

    Returns:
        ``(vuln_id, sources, published_at)`` 快照列表。
    """
    stmt = select(UnifiedVulnRow.vuln_id, UnifiedVulnRow.sources, UnifiedVulnRow.published_at)
    return [
        (vuln_id, list(sources or []), published_at)
        for vuln_id, sources, published_at in (await session.execute(stmt)).all()
    ]


async def load_snapshots(
    session: AsyncSession,
    *,
    limit: int | None = None,
) -> tuple[list[RawItem], list[VulnSnapshot]]:
    """读取回填所需的只读快照（``raw_item`` 领域对象 + ``unified_vuln`` 三列）。

    Args:
        session: 异步会话（本进程内唯一，避免与其它任务争抢连接）。
        limit: 最多读取的 ``raw_item`` 条数（按 ``fetched_at`` 倒序取最近若干条）；``None`` 表示全量。

    Returns:
        ``(raw_items, vuln_rows)``。
    """
    raw_stmt = select(RawItemRow).order_by(RawItemRow.fetched_at.desc())
    if limit:
        raw_stmt = raw_stmt.limit(max(1, limit))
    raw_items = [row.to_domain() for row in (await session.execute(raw_stmt)).scalars()]
    return raw_items, await load_vuln_rows(session)


async def apply_changes(session: AsyncSession, changes: dict[str, datetime | None]) -> int:
    """把回填计划写入 ``unified_vuln.published_at``（逐行 UPDATE，同事务提交）。

    Args:
        session: 异步会话。
        changes: ``vuln_id → 新值``（值可为 ``None``）。

    Returns:
        实际执行的 UPDATE 行数。
    """
    for vuln_id, value in changes.items():
        await session.execute(
            update(UnifiedVulnRow).where(UnifiedVulnRow.vuln_id == vuln_id).values(published_at=value)
        )
    return len(changes)


def print_plan(plan: BackfillPlan, *, verbose: bool = False, preview: int = 20) -> None:
    """打印回填计划与覆盖率对照。

    Args:
        plan: 回填计划。
        verbose: 是否打印逐条变更明细。
        preview: 明细最多打印多少条（超出部分只提示条数）。
    """
    nulled = sum(1 for value in plan.changes.values() if value is None)
    print(
        f"\n[回填计划] updated={len(plan.changes)}（其中置空 nulled={nulled}）"
        f" | 跳过置空 skipped-null={len(plan.skipped_nulls)}"
        f" | 无 raw_item 映射 unresolved={len(plan.unresolved)}"
    )
    if verbose:
        for vuln_id, value in sorted(plan.changes.items())[:preview]:
            print(f"  * {vuln_id:<18} → {iso_z(value) if value else 'NULL'}")
        if len(plan.changes) > preview:
            print(f"  * …… 其余 {len(plan.changes) - preview} 条略")
        for vuln_id, value in sorted(plan.skipped_nulls.items())[:preview]:
            print(f"  . {vuln_id:<18} 保持 {iso_z(value) if value else 'NULL'}（加 --null-out 可置空）")
        if len(plan.skipped_nulls) > preview:
            print(f"  . …… 其余 {len(plan.skipped_nulls) - preview} 条略")
    print("[发布时间覆盖率：回填前]")
    print(format_coverage(plan.before))
    print("[发布时间覆盖率：回填后（计划生效）]")
    print(format_coverage(plan.after, previous=plan.before))


async def run(args: argparse.Namespace) -> int:
    """执行回填流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（``0`` 成功；``1`` 读库 / 写库失败）。
    """
    settings = Settings(database_url=args.dsn) if args.dsn else Settings()
    print(
        f"[环境] DSN={settings.effective_storage_dsn} | mode={'apply' if args.apply else 'dry-run'} "
        f"| null-out={args.null_out} | limit={args.limit or 'all'}"
    )
    engine = create_engine(settings.effective_storage_dsn)
    try:
        async with session_scope(engine) as session:
            raw_items, vuln_rows = await load_snapshots(session, limit=args.limit)
            print(f"[读取] raw_item={len(raw_items)} 条 | unified_vuln={len(vuln_rows)} 条")
            targets, failed = recompute_targets(raw_items)
            plan = build_plan(vuln_rows, targets, null_out=args.null_out)
            print_plan(plan, verbose=args.verbose)
            if failed:
                print(f"[警告] {failed} 条采集件无法确定 vuln_id，已跳过（与 build_many 同一策略）")
            if not args.apply:
                print("[写入] dry-run：未改动数据库（加 --apply 生效）")
            elif not plan.changes:
                print("[写入] 无差异，未执行 UPDATE")
            else:
                written = await apply_changes(session, plan.changes)
                print(f"[写入] 已更新 {written} 行 published_at")
                print("[发布时间覆盖率：回填后（实测）]")
                print(format_coverage(coverage_by_source(await load_vuln_rows(session)), previous=plan.before))
            unchanged = len(vuln_rows) - len(plan.changes) - len(plan.skipped_nulls) - len(plan.unresolved)
            print(
                f"\n[合计] updated={len(plan.changes)} unchanged={unchanged} "
                f"skipped-null={len(plan.skipped_nulls)} unresolved={len(plan.unresolved)}"
            )
    except Exception as exc:  # noqa: BLE001 - CLI 需要把任何读库失败收敛为可操作提示
        print(f"[FAIL] {type(exc).__name__}: {exc}（检查 DATABASE_URL / docker compose ps）")
        return 1
    finally:
        await engine.dispose()
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