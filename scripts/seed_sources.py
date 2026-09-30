"""采集源登记同步脚本（PROJECT_PLAN.md §2 / §5.4）。

以 ``configs/sources.yaml`` 为**权威声明**（开关 / 调度间隔 / 限流 / 超时 / 源特有参数），
与「连接器注册表」取交集后幂等 upsert 到数据库 ``source`` 表：

    - YAML 中声明的源 → 使用 YAML 配置（并刷新 ``last_run_at`` 冗余游标）；
    - YAML 未声明但已注册的源 → 回退注册表默认值（``config_source=registry-default``）；
    - YAML 声明但未注册的源 → 登记为**停用**（``registered=false``），便于运维页提示待实现。

用法::

    python -m scripts.seed_sources                 # 按 configs/sources.yaml 同步
    python -m scripts.seed_sources --list          # 只打印登记结果
    python -m scripts.seed_sources --disable ghsa  # 额外停用某个源
    python -m scripts.seed_sources --config configs/sources.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings, SourcesConfig, load_sources_config  # noqa: E402
from aisec_intel.connectors import available_sources, create_connector  # noqa: E402
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.repositories.source_repo import SourceRepository, SourceSpec  # noqa: E402
from aisec_intel.storage.repositories.task_repo import TaskRepository  # noqa: E402


def build_specs(settings: Settings, *, sources_config: SourcesConfig | None = None) -> list[SourceSpec]:
    """构建登记入参（YAML 优先，注册表兜底）。

    Args:
        settings: 全局配置（用于判断源是否可用，如 GHSA 需要 Token）。
        sources_config: 采集源配置；``None`` 时读取 ``Settings.sources_config_path``。

    Returns:
        源登记入参列表（已注册源在前，YAML 中未注册的源追加在后）。
    """
    config = sources_config if sources_config is not None else load_sources_config(settings=settings)
    specs: list[SourceSpec] = []
    registered = available_sources()

    for name in registered:
        connector = create_connector(name, settings=settings)
        info = connector.describe()
        entry = config.for_source(name)
        params = entry.params if entry else {}
        params_meta = {key: json.dumps(value, ensure_ascii=False) for key, value in params.items()}
        specs.append(
            SourceSpec(
                name=name,
                connector_class=str(info["class"]),
                rate_limit=entry.rate_limit if entry else str(info["rate_limit"]),
                timeout_s=entry.timeout_s if entry else float(info["timeout"]),
                # 双重开关：YAML 声明启用 **且** 连接器自身可用（如 GHSA 需要 Token）
                enabled=bool(entry.enabled if entry else True) and bool(info["enabled"]),
                display_name=name.upper(),
                meta={
                    "source_url": connector.source_url,
                    "interval_minutes": str(entry.interval_minutes) if entry else "60",
                    "config_source": "sources.yaml" if entry else "registry-default",
                    **params_meta,
                },
            )
        )

    for name in sorted(set(config.sources) - set(registered)):
        entry = config.sources[name]
        specs.append(
            SourceSpec(
                name=name,
                connector_class="(未注册)",
                rate_limit=entry.rate_limit,
                timeout_s=entry.timeout_s,
                enabled=False,
                display_name=name.upper(),
                meta={"config_source": "sources.yaml", "registered": "false"},
            )
        )
    return specs


async def sync_sources(
    settings: Settings,
    *,
    sources_config: SourcesConfig | None = None,
    disable: list[str] | None = None,
) -> tuple[int, int]:
    """执行登记同步（含可选停用与游标刷新）。

    Args:
        settings: 全局配置。
        sources_config: 采集源配置；``None`` 时读取 ``Settings.sources_config_path``。
        disable: 需要额外停用的源标识列表。

    Returns:
        ``(created, updated)`` 计数。
    """
    engine = get_engine(settings)
    specs = build_specs(settings, sources_config=sources_config)
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
    parser.add_argument("--config", default=None, help="采集源配置路径（默认 configs/sources.yaml）")
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
        sources_config = load_sources_config(args.config, settings=settings)
        print(f"[配置] sources.yaml：声明 {len(sources_config.sources)} 个源，启用 {sources_config.enabled_sources}")
        if not args.list:
            created, updated = await sync_sources(
                settings, sources_config=sources_config, disable=list(args.disable)
            )
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
