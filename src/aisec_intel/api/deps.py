"""FastAPI 依赖与进程内限流（Day11 任务 5；PROJECT_PLAN.md §5.8 ``api/deps.py``）。

本模块集中三件事，供路由层 ``Depends`` 复用：

1. 配置与存储会话（:func:`get_settings_dep` / :func:`get_retrieval_service`）；
2. **进程内限流**（:class:`RateLimiter`，默认每分钟 60 次/调用方，见 §5.8 任务要求）；
3. LLM 开关（:func:`get_use_llm`）——降级模式下全链路走确定性路径。

依赖均可在测试中用 ``app.dependency_overrides`` 替换（无需真实 PG / Neo4j / LLM）。
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, status

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.services.retrieval_service import RetrievalService
from aisec_intel.storage.database import get_engine, session_scope

logger = get_logger(__name__)

RATE_LIMIT_PER_MINUTE: int = 60
"""默认限流额度（每分钟每调用方 60 次，§5.8 任务 5 硬性要求）。"""

RATE_LIMIT_WINDOW_S: float = 60.0
"""限流窗口（秒）。"""


@dataclass(slots=True)
class RateLimiter:
    """进程内滑动窗口限流器（单机部署足够；多副本应换 Redis）。

    Attributes:
        limit: 窗口内允许的请求数。
        window_s: 窗口长度（秒）。
    """

    limit: int = RATE_LIMIT_PER_MINUTE
    window_s: float = RATE_LIMIT_WINDOW_S
    clock: Callable[[], float] = time.monotonic
    _hits: dict[str, list[float]] = field(default_factory=dict, repr=False)

    def allow(self, key: str) -> bool:
        """记录一次访问并判断是否放行。

        Args:
            key: 调用方标识（通常为客户端 IP）。

        Returns:
            未超限返回 ``True``；超限返回 ``False``（调用方应回 429）。
        """
        now = self.clock()
        window_start = now - self.window_s
        hits = [item for item in self._hits.get(key, []) if item > window_start]
        if len(hits) >= max(1, self.limit):
            self._hits[key] = hits
            return False
        hits.append(now)
        self._hits[key] = hits
        return True

    def reset(self) -> None:
        """清空计数（测试与运维重置用）。"""
        self._hits.clear()


_limiter = RateLimiter()
"""进程级限流器单例（路由通过 :func:`get_rate_limiter` 取用）。"""


def get_settings_dep() -> Settings:
    """提供全局配置（可在测试中覆盖）。

    Returns:
        进程级 :class:`~aisec_intel.config.Settings` 单例。
    """
    return get_settings()


def get_rate_limiter() -> RateLimiter:
    """提供限流器单例。

    Returns:
        进程级 :class:`RateLimiter`。
    """
    return _limiter


def rate_limit(request: Request, limiter: RateLimiter = Depends(get_rate_limiter)) -> None:
    """限流依赖：超出额度抛 ``429 Too Many Requests``。

    Args:
        request: 当前请求（取客户端地址作为限流键）。
        limiter: 限流器。

    Raises:
        HTTPException: 超出每分钟额度。
    """
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"请求过于频繁：每分钟最多 {limiter.limit} 次（按调用方计数）",
        )


async def get_retrieval_service(settings: Settings = Depends(get_settings_dep)) -> AsyncIterator[RetrievalService]:
    """提供检索服务（每次请求一个会话，退出时释放连接）。

    Args:
        settings: 全局配置。

    Yields:
        绑定当前请求会话的 :class:`~aisec_intel.services.retrieval_service.RetrievalService`。
    """
    async with session_scope(get_engine(settings)) as session:
        service = RetrievalService(session, settings=settings)
        try:
            yield service
        finally:
            await service.aclose()


def get_use_llm(settings: Settings = Depends(get_settings_dep)) -> bool:
    """是否启用 LLM（``DEGRADED_MODE=true`` 或未配置 Key 时为 ``False``）。

    Args:
        settings: 全局配置。

    Returns:
        启用返回 ``True``。
    """
    return (not settings.degraded_mode) and settings.has_llm_api_key
