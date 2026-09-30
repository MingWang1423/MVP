"""Neo4j 官方驱动的异步薄封装（PROJECT_PLAN.md §5.7 ``storage/neo4j_client.py``）。

职责（只做「连接 + 执行 + 重试」三件事，不含任何业务语义）：

1. 按 :class:`~aisec_intel.config.Settings` 惰性创建 ``AsyncGraphDatabase`` 驱动
   （``NEO4J_ENABLED=false`` 或未安装驱动时**不报错**，由调用方决定降级策略）；
2. 统一 ``session()`` 上下文与 ``run()`` 执行入口，所有语句走参数化查询
   （标签 / 关系类型先经 :mod:`aisec_intel.graph.schema` 白名单校验再拼接）；
3. 驱动层自带事务重试（``max_transaction_retry_time``，应对集群瞬时故障）。

仓储层与业务代码只依赖本类，**禁止**在业务代码里直接 ``new`` 驱动。
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_DATABASE: str = "neo4j"
"""默认数据库名（Neo4j 5 社区版即 ``neo4j``）。"""

DEFAULT_POOL_SIZE: int = 8
"""连接池上限（演示规模足够；批量灌图靠 UNWIND 批处理而非放大连接数）。"""

DEFAULT_RETRY_TIME_S: float = 15.0
"""驱动层事务重试窗口（秒）：瞬时故障自动重试，超时后抛出由调用方处理。"""


class Neo4jUnavailableError(RuntimeError):
    """Neo4j 不可用（未安装驱动 / 连接失败 / 显式停用）。"""


class Neo4jClient:
    """Neo4j 异步客户端（惰性连接、可复用、需显式 :meth:`aclose`）。

    Attributes:
        uri: Bolt 地址。
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
        pool_size: int = DEFAULT_POOL_SIZE,
        retry_time_s: float = DEFAULT_RETRY_TIME_S,
    ) -> None:
        """初始化客户端（不建立连接）。

        Args:
            settings: 全局配置；``None`` 时使用 :func:`aisec_intel.config.get_settings`。
            uri: 覆盖 ``NEO4J_URI``。
            user: 覆盖 ``NEO4J_USER``。
            password: 覆盖 ``NEO4J_PASSWORD``（明文，仅内部传递，不落日志）。
            database: 数据库名；``None`` 时用 :data:`DEFAULT_DATABASE`。
            pool_size: 连接池上限。
            retry_time_s: 驱动层事务重试窗口（秒）。
        """
        resolved = settings or get_settings()
        self._settings = resolved
        self.uri = uri or resolved.neo4j_uri
        self._user = user or resolved.neo4j_user
        self._password = password if password is not None else resolved.neo4j_password.get_secret_value()
        self._database = database or DEFAULT_DATABASE
        self._pool_size = max(1, pool_size)
        self._retry_time_s = max(0.0, retry_time_s)
        self._driver: Any | None = None

    @property
    def enabled(self) -> bool:
        """配置层面是否启用图数据库（``NEO4J_ENABLED``）。"""
        return bool(self._settings.neo4j_enabled)

    @property
    def connected(self) -> bool:
        """驱动是否已创建。"""
        return self._driver is not None

    @property
    def database(self) -> str:
        """当前数据库名。"""
        return self._database

    def _ensure_driver(self) -> Any:
        """惰性创建驱动（未启用 / 未安装依赖时抛 :class:`Neo4jUnavailableError`）。

        Returns:
            ``neo4j.AsyncDriver`` 实例。

        Raises:
            Neo4jUnavailableError: 配置停用或缺少 ``neo4j`` 依赖。
        """
        if self._driver is not None:
            return self._driver
        if not self.enabled:
            raise Neo4jUnavailableError("NEO4J_ENABLED=false：图谱功能按设计停用")
        try:
            from neo4j import AsyncGraphDatabase
        except ImportError as exc:  # pragma: no cover - 依赖缺失属环境问题
            raise Neo4jUnavailableError("未安装 neo4j 驱动：pip install neo4j") from exc
        self._driver = AsyncGraphDatabase.driver(
            self.uri,
            auth=(self._user, self._password),
            max_connection_pool_size=self._pool_size,
            max_transaction_retry_time=self._retry_time_s,
        )
        logger.info(f"Neo4j 驱动已创建：{self.uri}（database={self._database}）")
        return self._driver

    @asynccontextmanager
    async def session(self) -> AsyncIterator[Any]:
        """打开一个异步会话（``async with``）。

        Yields:
            ``neo4j.AsyncSession``。

        Raises:
            Neo4jUnavailableError: 驱动不可用。
        """
        driver = self._ensure_driver()
        async with driver.session(database=self._database) as session:
            yield session

    async def run(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """执行单条 Cypher 并返回记录（无 ``RETURN`` 时返回空列表）。

        Args:
            cypher: Cypher 语句（标签 / 关系类型须已通过白名单校验）。
            params: 参数字典。

        Returns:
            记录字典列表。

        Raises:
            Neo4jUnavailableError: 驱动不可用或执行失败（统一包装为领域错误，便于上层降级）。
        """
        try:
            async with self.session() as session:
                result = await session.run(cypher, params or {})
                records = await result.data()
        except Neo4jUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - 统一包装，便于上层降级
            raise Neo4jUnavailableError(f"Neo4j 执行失败（{type(exc).__name__}: {exc}）：{cypher[:120]}") from exc
        return [dict(record) for record in records]

    async def run_statements(self, statements: Iterable[str]) -> int:
        """逐条执行语句（schema 初始化用；均带 ``IF NOT EXISTS``，可重复执行）。

        Args:
            statements: Cypher 语句序列。

        Returns:
            成功执行的语句条数。

        Raises:
            Neo4jUnavailableError: 任一语句执行失败。
        """
        count = 0
        async with self.session() as session:
            for statement in statements:
                await session.run(statement)
                count += 1
        logger.info(f"Neo4j schema 语句执行完成：{count} 条")
        return count

    async def ping(self) -> bool:
        """探活：``RETURN 1``。

        Returns:
            连接与查询均成功返回 ``True``；任何异常返回 ``False``（探活不得中断主流程）。
        """
        try:
            await self.run("RETURN 1 AS ok")
        except Exception as exc:  # noqa: BLE001 - 探活需吞掉所有异常
            logger.warning(f"Neo4j 探活失败：{exc}")
            return False
        return True

    async def aclose(self) -> None:
        """关闭驱动并释放连接池（幂等）。"""
        if self._driver is None:
            return
        await self._driver.close()
        self._driver = None
        logger.info("Neo4j 驱动已关闭")
