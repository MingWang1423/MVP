"""令牌桶限流器（PROJECT_PLAN.md §5.3 P2）。

用途：所有采集器在发请求前必须 ``await limiter.acquire()``，以遵守源方限流约定：

| 源 | 规格 | 含义 |
|---|---|---|
| NVD（无 Key） | ``5/30`` | 30 秒内最多 5 次（§11.1 ``NVD_RATE_LIMIT_NO_KEY``） |
| NVD（有 Key） | ``50/30`` | 30 秒内最多 50 次（§11.1 ``NVD_RATE_LIMIT_WITH_KEY``） |
| 其他源（默认） | ``10/1`` | 10 req/s |

实现要点：令牌桶 + ``asyncio.Lock``（并发安全）；时间与睡眠函数可注入，便于**无真实等待**的单元测试。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from aisec_intel.config import Settings, get_settings

DEFAULT_RATE_LIMIT: str = "10/1"
"""非 NVD 源的默认限流规格（10 req/s）。"""

NVD_SOURCE_NAME: str = "nvd"
"""需要特殊限流处理的源标识。"""

TimeFunc = Callable[[], float]
SleepFunc = Callable[[float], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class RateSpec:
    """限流规格：``window`` 秒内允许 ``count`` 次请求。

    Attributes:
        count: 窗口内允许的请求次数。
        window: 窗口长度（秒）。
    """

    count: int
    window: float

    def __post_init__(self) -> None:
        """校验规格合法性。

        Raises:
            ValueError: ``count`` 或 ``window`` 非正数。
        """
        if self.count <= 0:
            raise ValueError(f"限流次数必须为正数，实际为 {self.count}")
        if self.window <= 0:
            raise ValueError(f"限流窗口必须为正数，实际为 {self.window}")

    @property
    def rate(self) -> float:
        """折算后的速率（req/s）。"""
        return self.count / self.window

    @classmethod
    def parse(cls, spec: str) -> RateSpec:
        """解析 ``"次数/窗口秒"`` 规格字符串。

        Args:
            spec: 形如 ``"5/30"``、``"10/1"``、``"50/30"``。

        Returns:
            解析后的 :class:`RateSpec`。

        Raises:
            ValueError: 格式非法。
        """
        parts = spec.strip().split("/")
        if len(parts) != 2:
            raise ValueError(f"限流规格格式应为 '次数/窗口秒'，实际为 {spec!r}")
        try:
            count = int(parts[0].strip())
            window = float(parts[1].strip())
        except ValueError as exc:
            raise ValueError(f"限流规格解析失败：{spec!r}") from exc
        return cls(count=count, window=window)


class RateLimiter:
    """异步令牌桶限流器。

    Attributes:
        rate: 令牌补充速率（tokens/s）。
        capacity: 桶容量（burst）。
    """

    def __init__(
        self,
        rate: float,
        *,
        burst: float | None = None,
        time_func: TimeFunc = time.monotonic,
        sleep_func: SleepFunc = asyncio.sleep,
    ) -> None:
        """初始化令牌桶。

        Args:
            rate: 令牌补充速率（tokens/s），必须为正数。
            burst: 桶容量；默认 ``max(1.0, rate)``（约 1 秒的令牌量）。
            time_func: 单调时钟函数（测试可注入假时钟）。
            sleep_func: 异步睡眠函数（测试可注入空实现）。

        Raises:
            ValueError: ``rate`` 非正数。
        """
        if rate <= 0:
            raise ValueError(f"rate 必须为正数，实际为 {rate}")
        self._rate = rate
        self._capacity = burst if burst is not None else max(1.0, rate)
        if self._capacity <= 0:
            raise ValueError(f"burst 必须为正数，实际为 {self._capacity}")
        self._tokens = self._capacity
        self._updated = time_func()
        self._time_func = time_func
        self._sleep_func = sleep_func
        self._lock = asyncio.Lock()
        self.total_waited_s = 0.0
        """累计等待时长（秒），用于采集统计与可观测性。"""

    @property
    def rate(self) -> float:
        """令牌补充速率（tokens/s）。"""
        return self._rate

    @property
    def capacity(self) -> float:
        """桶容量。"""
        return self._capacity

    @property
    def available_tokens(self) -> float:
        """当前可用令牌数（只读，不含补充计算）。"""
        return self._tokens

    def _refill(self) -> None:
        """按经过的时间补充令牌（不超过桶容量）。"""
        now = self._time_func()
        elapsed = max(0.0, now - self._updated)
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._updated = now

    async def acquire(self, tokens: float = 1.0) -> float:
        """获取 ``tokens`` 个令牌（不足时等待）。

        Args:
            tokens: 需要的令牌数，默认 1.0。

        Returns:
            本次调用实际等待的秒数（0 表示无需等待）。
        """
        if tokens <= 0:
            raise ValueError(f"tokens 必须为正数，实际为 {tokens}")
        waited = 0.0
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    self.total_waited_s += waited
                    return waited
                deficit = tokens - self._tokens
                sleep_for = deficit / self._rate
                await self._sleep_func(sleep_for)
                waited += sleep_for

    @classmethod
    def from_spec(
        cls,
        spec: str,
        *,
        time_func: TimeFunc = time.monotonic,
        sleep_func: SleepFunc = asyncio.sleep,
    ) -> RateLimiter:
        """按规格字符串构造限流器（burst 取窗口内允许的请求数）。

        Args:
            spec: 见 :meth:`RateSpec.parse`。
            time_func: 单调时钟函数。
            sleep_func: 异步睡眠函数。

        Returns:
            配置好的 ``RateLimiter``。
        """
        parsed = RateSpec.parse(spec)
        return cls(parsed.rate, burst=float(parsed.count), time_func=time_func, sleep_func=sleep_func)

    @classmethod
    def for_source(
        cls,
        source: str,
        *,
        settings: Settings | None = None,
        time_func: TimeFunc = time.monotonic,
        sleep_func: SleepFunc = asyncio.sleep,
    ) -> RateLimiter:
        """按源标识构造限流器（NVD 依据是否有 API Key 自动选择规格）。

        Args:
            source: 源标识，如 ``"nvd"`` / ``"kev"``。
            settings: 全局配置；默认使用 :func:`aisec_intel.config.get_settings`。
            time_func: 单调时钟函数。
            sleep_func: 异步睡眠函数。

        Returns:
            配置好的 ``RateLimiter``。
        """
        resolved = settings or get_settings()
        spec = DEFAULT_RATE_LIMIT
        if source.lower() == NVD_SOURCE_NAME:
            spec = resolved.nvd_rate_limit_with_key if resolved.has_nvd_api_key else resolved.nvd_rate_limit_no_key
        return cls.from_spec(spec, time_func=time_func, sleep_func=sleep_func)
