"""采集源登记同步脚本（PROJECT_PLAN.md §2 / §5.4）。

把**代码里注册的采集器**同步到数据库 ``source`` 表（幂等 upsert），并顺带刷新
``last_run_at`` 冗余游标，供前端「采集运维」页与 P4 调度器使用。

用法::

    python -m scripts.seed_sources                 # 按注册表全量同步
    python -m scripts.seed_sources --list          # 只打印登记结果
    python -m scripts.seed_sources --disable ghsa  # 停用某个源
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
from aisec_intel.connectors import available_sources, create_connector  # noqa: E402
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.repositories.source_repo import SourceRepository, SourceSpec  # noqa: E402
from aisec_intel.storage.repositories.task_repo import TaskRepository  # noqa: E402


def build_specs(settings: Settings) -> list[SourceSpec]:
    """由连接器注册表构建登记入参。

    Args:
        settings: 全局配置（用于判断源是否可用，如 GHSA 需要 Token）。

    Returns:
        源登记入参列表（按源标识排序）。

    Raises:
        RuntimeError: 采集器实例创建失败。
    """
    specs: list[SourceSpec] = []
    for name in available_sources():
        connector = create_connector(name, settings=settings)
        info = connector.describe()
        specs.append(
            SourceSpec(
                name=name,
                connector_class=str(info["class"]),
                rate_limit=str(info["rate_limit"]),
                timeout_s=float(info["timeout"]),
                enabled=bool(info["enabled"]),
                display_name=name.upper(),
                meta={"source_url": connector.source_url},
            )
        )
    return specs


async def sync_sources(settings: Settings, *, disable: list[str] | None = None) -> tuple[int, int]:
    """执行登记同步（含可选停用）。

    Args:
        settings: 全局配置。
        disable: 需要停用的源标识列表。

    Returns:
        ``(created, updated)`` 计数。
    """
    engine = get_engine(settings)
    specs = build_specs(settings)
    async with session_scope(engine) as session:
        repo = SourceRepository(session)
        created, updated = await repo.upsert_many(specs)
        for name in disable or []:
            await repo.set_enabled(name, enabled=False)
        task_repo = TaskRepository(session)
        for spec in specs:
            cursor = await task_repo.last_run_at(spec.name)
            if cursor is not None:
                await repo.sync_last_run_at(spec.name, cursor)
    return created, updated


async def list_sources(settings: Settings) -> None:
    """打印当前登记的源。

    Args:
        settings: 全局配置。
    """
    engine = get_engine(settings)
    async with session_scope(engine) as session:
        rows = await SourceRepository(session).list_all()
    if not rows:
        print("[提示] source 表为空，请先执行 python -m scripts.init_db 再运行本脚本。")
        return
    print("已登记源：")
    for row in rows:
        flag = "启用" if row.enabled else "停用"
        last = row.last_run_at.isoformat() if row.last_run_at else "-"
        print(f"  - {row.name:<6} class={row.connector_class:<16} limit={row.rate_limit:<6} {flag} last_run={last}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="采集源登记同步")
    parser.add_argument("--list", action="store_true", help="只打印当前登记结果")
    parser.add_argument("--disable", nargs="*", default=[], help="停用指定源（如 --disable ghsa）")
    return parser.parse_args(argv)


async def run(args: argparse.Namespace) -> int:
    """脚本主流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码。
    """
    settings = Settings()
    print(f"[环境] DSN={settings.effective_storage_dsn} | degraded={settings.degraded_mode}")
    try:
        if not args.list:
            created, updated = await sync_sources(settings, disable=list(args.disable))
            print(f"[完成] 源登记同步：新增={created} 更新={updated}")
        await list_sources(settings)
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI 需给出明确失败原因
        print(f"[失败] {type(exc).__name__}: {exc}")
        print("[提示] 请先执行 python -m scripts.init_db；数据库不可用时设置 DEGRADED_MODE=true。")
        return 1


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
