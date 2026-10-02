"""Day3 限流器测试（PROJECT_PLAN.md §5.3）。

使用可注入的假时钟与假睡眠，**不产生真实等待**，同时能精确断言等待时长。
"""

from __future__ import annotations

import pytest

from aisec_intel.config import Settings
from aisec_intel.connectors.rate_limiter import DEFAULT_RATE_LIMIT, RateLimiter, RateSpec


class FakeClock:
    """可控时钟：``sleep`` 会把时间向前推进，从而让令牌桶循环收敛。"""

    def __init__(self) -> None:
        """初始化时钟与睡眠记录。"""
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        """返回当前（虚拟）时间。"""
        return self.now

    async def sleep(self, seconds: float) -> None:
        """记录睡眠时长并推进虚拟时间。

        Args:
            seconds: 请求的睡眠秒数。
        """
        self.sleeps.append(seconds)
        self.now += seconds


def make_settings(**overrides: object) -> Settings:
    """构造不读取 ``.env`` 的配置对象。"""
    return Settings(_env_file=None, **overrides)


class TestRateSpec:
    """``RateSpec`` 解析测试。"""

    @pytest.mark.parametrize(
        ("spec", "count", "window"),
        [("5/30", 5, 30.0), ("10/1", 10, 1.0), ("50/30", 50, 30.0), (" 2 / 0.5 ", 2, 0.5)],
    )
    def test_parse_valid_specs(self, spec: str, count: int, window: float) -> None:
        """合法规格可解析出次数与窗口。"""
        parsed = RateSpec.parse(spec)
        assert parsed.count == count
        assert parsed.window == window

    def test_nvd_spec_rate(self) -> None:
        """NVD 无 Key 规格折算为 5/30 ≈ 0.1667 req/s。"""
        assert RateSpec.parse("5/30").rate == pytest.approx(5 / 30)

    @pytest.mark.parametrize("spec", ["5", "5/", "/30", "abc/def", "5/0", "0/30"])
    def test_invalid_specs_raise(self, spec: str) -> None:
        """非法规格抛出 ``ValueError``。"""
        with pytest.raises(ValueError):
            RateSpec.parse(spec)


class TestRateLimiter:
    """令牌桶行为测试。"""

    async def test_burst_then_throttle(self) -> None:
        """容量内的请求无需等待，超出后按速率等待。"""
        clock = FakeClock()
        limiter = RateLimiter(rate=2.0, burst=2.0, time_func=clock.time, sleep_func=clock.sleep)

        assert await limiter.acquire() == 0.0
        assert await limiter.acquire() == 0.0
        waited = await limiter.acquire()  # 令牌耗尽，需等待 1/2 秒
        assert waited == pytest.approx(0.5)
        assert clock.sleeps == [pytest.approx(0.5)]

    async def test_tokens_refill_over_time(self) -> None:
        """时间推进后令牌自动回补。"""
        clock = FakeClock()
        limiter = RateLimiter(rate=1.0, burst=1.0, time_func=clock.time, sleep_func=clock.sleep)
        await limiter.acquire()
        clock.now += 1.0
        assert await limiter.acquire() == 0.0

    async def test_total_waited_accumulates(self) -> None:
        """累计等待时长可观测（供采集统计使用）。"""
        clock = FakeClock()
        limiter = RateLimiter(rate=1.0, burst=1.0, time_func=clock.time, sleep_func=clock.sleep)
        await limiter.acquire()
        await limiter.acquire()
        await limiter.acquire()
        assert limiter.total_waited_s == pytest.approx(2.0)

    async def test_multi_token_acquire(self) -> None:
        """一次获取多个令牌时按缺口等待。"""
        clock = FakeClock()
        limiter = RateLimiter(rate=1.0, burst=3.0, time_func=clock.time, sleep_func=clock.sleep)
        assert await limiter.acquire(3) == 0.0
        assert await limiter.acquire(2) == pytest.approx(2.0)

    async def test_invalid_constructor_args(self) -> None:
        """非法速率 / 容量 / 令牌数均报错。"""
        with pytest.raises(ValueError):
            RateLimiter(rate=0)
        with pytest.raises(ValueError):
            RateLimiter(rate=1.0, burst=0)
        limiter = RateLimiter(rate=1.0)
        with pytest.raises(ValueError):
            await limiter.acquire(0)

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_from_spec_sets_burst_to_window_count()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_from_spec_sets_burst_to_window_count: {type(exc).__name__}: {exc}")
        try:
            self._case_test_default_rate_limit_for_other_sources()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_default_rate_limit_for_other_sources: {type(exc).__name__}: {exc}")
        try:
            self._case_test_nvd_rate_limit_without_key()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_nvd_rate_limit_without_key: {type(exc).__name__}: {exc}")
        try:
            self._case_test_nvd_rate_limit_with_key()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_nvd_rate_limit_with_key: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_from_spec_sets_burst_to_window_count(self) -> None:
        """``from_spec`` 的 burst 等于窗口内允许次数。"""
        limiter = RateLimiter.from_spec("5/30")
        assert limiter.rate == pytest.approx(5 / 30)
        assert limiter.capacity == pytest.approx(5.0)

    def _case_test_default_rate_limit_for_other_sources(self) -> None:
        """非 NVD 源使用默认 10 req/s。"""
        limiter = RateLimiter.for_source("kev", settings=make_settings())
        assert limiter.rate == pytest.approx(RateSpec.parse(DEFAULT_RATE_LIMIT).rate)

    def _case_test_nvd_rate_limit_without_key(self) -> None:
        """NVD 无 Key 时使用 5/30。"""
        limiter = RateLimiter.for_source("nvd", settings=make_settings())
        assert limiter.rate == pytest.approx(5 / 30)

    def _case_test_nvd_rate_limit_with_key(self) -> None:
        """NVD 有 Key 时使用 50/30。"""
        settings = make_settings(nvd_api_key="unit-test-key")
        limiter = RateLimiter.for_source("nvd", settings=settings)
        assert limiter.rate == pytest.approx(50 / 30)