"""数据库初始化脚本（PROJECT_PLAN.md §2 / §5.2 P1）。

行为：
    1. 打印生效 DSN（``DATABASE_URL`` > 降级 SQLite > ``PG_DSN``）；
    2. 执行 ``alembic upgrade head``（与运行时同一套配置，见 ``alembic/env.py``）；
    3. 打印实际建出的表清单，便于验收核对。

用法::

    python -m scripts.init_db
    set DEGRADED_MODE=true && python -m scripts.init_db     # 全本地 SQLite 降级模式
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine as create_sync_engine  # noqa: E402
from sqlalchemy import inspect  # noqa: E402

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.storage import models  # noqa: E402,F401  导入以注册全部映射

REPO_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"


def sync_dsn(async_dsn: str) -> str:
    """把异步 DSN 转为同步 DSN（仅用于反射表清单）。

    Args:
        async_dsn: ``sqlite+aiosqlite:///...`` 或 ``postgresql+asyncpg://...``。

    Returns:
        对应的同步 DSN。
    """
    return async_dsn.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")


def list_tables(dsn: str) -> list[str]:
    """反射数据库中的表清单（失败返回空列表，不阻断迁移流程）。

    Args:
        dsn: 同步 DSN。

    Returns:
        表名列表（字典序）。
    """
    try:
        engine = create_sync_engine(dsn)
    except Exception as exc:  # noqa: BLE001 - 反射失败不应影响已完成的迁移
        print(f"[警告] 无法反射表清单：{type(exc).__name__}: {exc}")
        return []
    try:
        return sorted(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def main() -> int:
    """执行迁移并打印结果。

    Returns:
        进程退出码（0 成功；1 失败）。
    """
    settings = Settings()
    dsn = settings.effective_storage_dsn
    print(f"[环境] DSN={dsn} | degraded={settings.degraded_mode}")

    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    try:
        command.upgrade(config, "head")
    except Exception as exc:  # noqa: BLE001 - CLI 需给出明确失败原因
        print(f"[失败] alembic upgrade head 出错：{type(exc).__name__}: {exc}")
        print("[提示] 若数据库不可用，可设置 DEGRADED_MODE=true 使用本地 SQLite。")
        return 1

    print("[完成] 迁移已应用到 head。")
    if dsn.startswith("sqlite"):
        tables = list_tables(sync_dsn(dsn))
        print(f"[表] {tables}")
    else:
        print("[提示] PostgreSQL 已就绪，可在 DBeaver/psql 中查看表结构。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
