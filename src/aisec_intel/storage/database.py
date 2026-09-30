"""SQLAlchemy 2.0 异步引擎与会话工厂（PROJECT_PLAN.md §5.2 / §11.1）。

DSN 来源优先级：``DATABASE_URL``（显式覆盖）> 降级 SQLite（``DEGRADED_MODE=true``）> ``PG_DSN``，
统一由 :attr:`aisec_intel.config.Settings.effective_storage_dsn` 解析。

支持的本地形态：

- ``sqlite+aiosqlite:///:memory:``：内存库（单元测试，**自动启用 StaticPool 复用单连接**）
- ``sqlite+aiosqlite:///./data/aisec.db``：文件库（降级模式，见 §11.1）
- ``postgresql+asyncpg://...``：生产 PostgreSQL
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from aisec_intel.config import Settings, get_settings
from aisec_intel.storage.base import Base

_ENGINES: dict[str, AsyncEngine] = {}
"""按 DSN 缓存的引擎，避免重复创建连接池。"""


def create_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
    """按 DSN 创建异步引擎。

    Args:
        database_url: SQLAlchemy 异步 DSN。
        echo: 是否回显 SQL（调试用）。

    Returns:
        新建的 ``AsyncEngine``；内存 SQLite 自动使用 ``StaticPool`` 与
        ``check_same_thread=False``，否则每个连接会看到独立的空库。
    """
    kwargs: dict[str, Any] = {"echo": echo}
    if database_url.startswith("sqlite") and ":memory:" in database_url:
        kwargs["poolclass"] = StaticPool
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_async_engine(database_url, **kwargs)


def get_engine(settings: Settings | None = None, *, echo: bool = False) -> AsyncEngine:
    """获取当前配置对应的引擎（按 DSN 缓存）。

    Args:
        settings: 配置对象；默认使用 :func:`aisec_intel.config.get_settings`。
        echo: 是否回显 SQL（仅首次创建时生效）。

    Returns:
        可复用的 ``AsyncEngine``。
    """
    resolved = settings or get_settings()
    url = resolved.effective_storage_dsn
    if url not in _ENGINES:
        _ENGINES[url] = create_engine(url, echo=echo)
    return _ENGINES[url]


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """创建会话工厂。

    Args:
        engine: 目标引擎。

    Returns:
        配置为 ``expire_on_commit=False``（提交后仍可读取属性）的会话工厂。
    """
    return async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@asynccontextmanager
async def session_scope(engine: AsyncEngine | None = None) -> AsyncIterator[AsyncSession]:
    """以事务方式提供会话（异常自动回滚，退出自动关闭）。

    Args:
        engine: 目标引擎；``None`` 时使用 :func:`get_engine`。

    Yields:
        处于活动状态的 ``AsyncSession``。

    Examples:
        >>> async with session_scope(engine) as session:  # doctest: +SKIP
        ...     repo = VulnRepository(session)
        ...     await repo.upsert(vuln)
    """
    factory = create_session_factory(engine or get_engine())
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def init_models(engine: AsyncEngine) -> None:
    """依据 ORM 元数据建表（仅测试与降级模式；生产环境必须走 Alembic）。

    Args:
        engine: 目标引擎。
    """
    from aisec_intel.storage import models as _models  # noqa: F401  导入以注册所有映射

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_models(engine: AsyncEngine) -> None:
    """删除 ORM 元数据中的所有表（测试清理用）。

    Args:
        engine: 目标引擎。
    """
    from aisec_intel.storage import models as _models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def ping(engine: AsyncEngine) -> bool:
    """探活：执行 ``SELECT 1``。

    Args:
        engine: 目标引擎。

    Returns:
        连接可用返回 ``True``，否则返回 ``False``。
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - 探活需要吞掉所有连接类异常
        return False
    return True


async def dispose_engines() -> None:
    """释放并清空所有缓存引擎（进程退出或测试清理用）。"""
    for url, engine in list(_ENGINES.items()):
        await engine.dispose()
        _ENGINES.pop(url, None)
