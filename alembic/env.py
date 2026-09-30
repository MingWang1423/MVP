"""Alembic 迁移环境（异步引擎，PROJECT_PLAN.md §5.2）。

DSN 不写在 ``alembic.ini`` 中，而是复用运行时配置
:attr:`aisec_intel.config.Settings.effective_storage_dsn`
（优先级：``DATABASE_URL`` > 降级 SQLite > ``PG_DSN``），保证迁移与运行时**永远同一个库**。

常用命令::

    alembic upgrade head                                   # 应用到最新
    alembic revision --autogenerate -m "add raw_item" -m ...  # 生成迁移
    alembic downgrade -1                                   # 回滚一步
    alembic upgrade head --sql > migrate.sql               # 离线生成 SQL

Note:
    ``alembic.ini`` 中的 ``prepend_sys_path = src`` 已把 ``src`` 加入 ``sys.path``，
    因此这里可以直接 ``import aisec_intel``。
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from aisec_intel.config import Settings
from aisec_intel.storage import models  # noqa: F401  导入以注册全部 ORM 映射
from aisec_intel.storage.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_database_url() -> str:
    """返回迁移所用 DSN。

    Returns:
        与运行时一致的 SQLAlchemy 异步 DSN。
    """
    return Settings().effective_storage_dsn


def run_migrations_offline() -> None:
    """离线模式：不连接数据库，仅按元数据生成 SQL（``--sql``）。"""
    context.configure(
        url=get_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """在给定同步连接上执行迁移（由 ``run_sync`` 调用）。

    Args:
        connection: SQLAlchemy 同步连接。
    """
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """创建异步引擎并执行迁移（使用 ``NullPool``，迁移结束即释放连接）。"""
    engine = create_async_engine(get_database_url(), poolclass=NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    """在线模式：真实连接数据库执行迁移。"""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
