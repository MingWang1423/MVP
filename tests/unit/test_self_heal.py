"""Day17 任务 4.1：自愈（重试 / 镜像切换 / 自愈日志）测试（``services/self_heal.py``）。

覆盖点：
    1. 指数退避序列（无抖动 → 可精确断言）与 ``max_delay_s`` 封顶；
    2. ``retry_async``：首次成功不等待 / 重试后成功 / 耗尽后抛出**最后一次**异常；
    3. ``apply_fallback_url``：通用机制覆写采集器入口 URL（KEV 主站 → GitHub 镜像）；
    4. ``fetch_with_self_heal``：主地址耗尽后自动切镜像并返回生效地址；
    5. 自愈事件写入 ``selfheal.log``（JSON 单行）与 ``aisec_self_heal_total`` 指标。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from aisec_intel.config import Settings
from aisec_intel.services.self_heal import (
    ACTION_EXHAUSTED,
    ACTION_FALLBACK,
    ACTION_RETRY,
    DEFAULT_BASE_DELAY_S,
    SELF_HEAL_LOGGER_NAME,
    SelfHealEvent,
    apply_fallback_url,
    backoff_delays,
    configure_self_heal_log,
    fallback_urls,
    fetch_with_self_heal,
    log_self_heal,
    retry_async,
)

PRIMARY_URL = "https://www.cisa.gov/primary.json"
"""主入口地址（``_FakeConnector.catalog_url`` 的初值）。"""


class _FakeConnector:
    """最小采集器替身（只暴露自愈机制需要的最小面：``source_name`` + 入口 URL）。"""

    source_name = "kev"
    catalog_url = PRIMARY_URL

    def __init__(self, *, items: int = 2) -> None:
        self.calls: list[str] = []
        self._items = items

    async def fetch(self) -> list[dict[str, int]]:
        """主地址始终失败、镜像地址成功（用于验证切换逻辑）。"""
        self.calls.append(self.catalog_url)
        if self.catalog_url == PRIMARY_URL:
            raise RuntimeError("primary url down")
        return [{"i": index} for index in range(self._items)]


class _AlwaysDownConnector(_FakeConnector):
    """主地址与镜像地址都失败（用于验证向调用方透传最后一次异常）。"""

    async def fetch(self) -> list[dict[str, int]]:
        """任何地址都抛异常。"""
        self.calls.append(self.catalog_url)
        raise RuntimeError("down")


class _BareConnector:
    """没有任何入口 URL 属性的采集器（应命中「无备用地址 → 降级留痕」分支）。"""

    source_name = "demo"


async def _instant_sleep(delay: float) -> None:
    """无副作用休眠替身（避免单测真实等待）。"""
    del delay


class TestBackoff:
    def test_backoff_sequence(self) -> None:
        """序列为 ``base * 2^n``，并被 ``max_delay_s`` 封顶。"""
        assert backoff_delays(attempts=1) == []
        assert backoff_delays(attempts=3) == [0.5, 1.0]
        assert backoff_delays(attempts=5, base_delay_s=0.5, max_delay_s=2.0) == [0.5, 1.0, 2.0, 2.0]
        assert DEFAULT_BASE_DELAY_S == 0.5



class TestRetryAsync:
    async def test_first_attempt_success_no_sleep(self) -> None:
        """首次成功不产生等待，也不记录 retry 事件。"""
        waits: list[float] = []

        async def _sleep(delay: float) -> None:
            waits.append(delay)

        calls = {"n": 0}

        async def _op() -> str:
            calls["n"] += 1
            return "ok"

        result = await retry_async(_op, component="collect", label="kev", sleep=_sleep)
        assert result == "ok" and calls["n"] == 1 and waits == []

    async def test_retry_then_recover(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """第 2 次成功：等待序列为 ``[0.5]``，并记录 retry + recovered 自愈事件。"""
        import aisec_intel.services.self_heal as module

        waits: list[float] = []
        events: list[SelfHealEvent] = []
        monkeypatch.setattr(module, "log_self_heal", events.append)

        async def _sleep(delay: float) -> None:
            waits.append(delay)

        calls = {"n": 0}

        async def _op() -> int:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("flaky")
            return 7

        result = await retry_async(_op, component="collect", label="kev", sleep=_sleep)
        assert result == 7
        assert waits == [0.5]
        assert [event.action for event in events] == [ACTION_RETRY, "recovered"]

    async def test_exhausted_raises_last_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """3 次尝试全部失败：等待 ``[0.5, 1.0]``，抛出最后一次异常并记录 exhausted。"""
        import aisec_intel.services.self_heal as module

        waits: list[float] = []
        events: list[SelfHealEvent] = []
        monkeypatch.setattr(module, "log_self_heal", events.append)

        async def _sleep(delay: float) -> None:
            waits.append(delay)

        counter = {"n": 0}

        async def _op() -> None:
            counter["n"] += 1
            raise RuntimeError(f"boom-{counter['n']}")

        with pytest.raises(RuntimeError, match="boom-3"):
            await retry_async(_op, component="collect", label="kev", sleep=_sleep)
        assert waits == [0.5, 1.0]
        assert counter["n"] == 3
        assert events[-1].action == ACTION_EXHAUSTED
        assert events[-1].attempt == 3

    def test_fallback_urls_registered_for_kev(self) -> None:
        """KEV 主站故障时登记的镜像地址为 GitHub kev-data 仓库。"""
        urls = fallback_urls("KEV")
        assert urls and "raw.githubusercontent.com" in urls[0]
        assert fallback_urls("unknown-source") == ()



class TestFallbackSwitching:
    def test_apply_fallback_url_overrides_entry_point(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """通用机制：覆写采集器入口 URL 类属性并记录 fallback 事件。"""
        import aisec_intel.services.self_heal as module

        events: list[SelfHealEvent] = []
        monkeypatch.setattr(module, "log_self_heal", events.append)
        connector = _FakeConnector()
        assert apply_fallback_url(connector, "https://mirror.test/kev.json") is True
        assert connector.catalog_url == "https://mirror.test/kev.json"
        assert events[0].action == ACTION_FALLBACK
        assert events[0].details["attr"] == "catalog_url"

    def test_apply_fallback_url_without_entry_point(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """未声明入口 URL 属性时返回 ``False`` 并记为 degraded。"""
        import aisec_intel.services.self_heal as module

        events: list[SelfHealEvent] = []
        monkeypatch.setattr(module, "log_self_heal", events.append)
        assert apply_fallback_url(_BareConnector(), "https://mirror.test/x") is False
        assert events[0].action == "degraded"

    async def test_fetch_with_self_heal_switches_to_mirror(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """主地址耗尽 → 自动切 GitHub 镜像成功，返回生效地址。"""
        import aisec_intel.services.self_heal as module

        monkeypatch.setattr(module, "log_self_heal", lambda event: None)
        connector = _FakeConnector(items=3)
        items, healed_url = await fetch_with_self_heal(connector, connector.fetch, sleep=_instant_sleep)
        assert len(items) == 3
        assert healed_url is not None and "raw.githubusercontent.com" in healed_url
        # 前 3 次打主地址，之后才切镜像
        assert connector.calls[:3] == [PRIMARY_URL] * 3
        assert connector.calls[-1] == healed_url

    async def test_fetch_with_self_heal_raises_when_all_die(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """镜像也失败时抛出最后一次异常（调用方按单源失败处理，不阻断其它源）。"""
        import aisec_intel.services.self_heal as module

        monkeypatch.setattr(module, "log_self_heal", lambda event: None)
        connector = _AlwaysDownConnector()
        with pytest.raises(RuntimeError, match="down"):
            await fetch_with_self_heal(connector, connector.fetch, sleep=_instant_sleep)



class TestSelfHealLog:
    def test_event_dict_shape(self) -> None:
        """事件字典字段固定（``kind`` / ``component`` / ``action``，时间带 ``Z``）。"""
        payload = SelfHealEvent(component="qa", action="degraded", reason="vector down", label="vector").as_dict()
        assert payload["kind"] == "self_heal"
        assert str(payload["occurred_at"]).endswith("Z")
        assert payload["label"] == "vector"
        assert payload["details"] == {}

    def test_log_written_to_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """自愈日志落到独立滚动文件（JSON 单行，含 ``kind`` 字段）。"""
        import aisec_intel.services.self_heal as module

        target = tmp_path / "selfheal.log"
        monkeypatch.setattr(
            module,
            "configure_self_heal_log",
            lambda settings=None: configure_self_heal_log(Settings(self_heal_log_path=str(target))),
        )
        selfheal_logger = logging.getLogger(SELF_HEAL_LOGGER_NAME)
        selfheal_logger.handlers.clear()
        try:
            log_self_heal(SelfHealEvent(component="collect", action="fallback", reason="mirror", label="kev"))
            for handler in selfheal_logger.handlers:
                handler.flush()
            payload = json.loads(target.read_text(encoding="utf-8").splitlines()[-1])
            assert payload["details"]["kind"] == "self_heal"
            assert payload["details"]["component"] == "collect"
            assert payload["event"] == "collect.fallback"
        finally:
            for handler in list(selfheal_logger.handlers):
                handler.close()
            selfheal_logger.handlers.clear()

    def test_metrics_counter_incremented(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """每次自愈事件累加 ``aisec_self_heal_total{component,action}``。"""
        import aisec_intel.services.self_heal as module
        from aisec_intel.services.metrics_service import M_SELF_HEAL, MetricsRegistry

        fresh = MetricsRegistry()
        monkeypatch.setattr(module, "METRICS", fresh)
        monkeypatch.setattr(module, "configure_self_heal_log", lambda settings=None: None)
        log_self_heal(SelfHealEvent(component="llm", action="fallback", reason="500"))
        log_self_heal(SelfHealEvent(component="llm", action="fallback", reason="500"))
        assert fresh.counter(M_SELF_HEAL, {"component": "llm", "action": "fallback"}) == 2
