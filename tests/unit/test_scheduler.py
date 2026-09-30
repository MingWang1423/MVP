"""Day6 调度器测试（PROJECT_PLAN.md §5.5 P4 任务 2）。

用假调度器（:class:`FakeScheduler`）替代 APScheduler，验证 job 装配、模式传递、
异常隔离与优雅停机；末尾另有一条真实 ``AsyncIOScheduler`` 装配冒烟用例。
"""

from __future__ import annotations

import asyncio
import signal
from pathlib import Path
from typing import Any

import pytest

from aisec_intel.config import Settings, SourcesConfig, load_sources_config
from aisec_intel.services.collect_service import FULL_MODE_START, CollectStats
from aisec_intel.services.scheduler import CollectScheduler

CONFIG_BODY = """version: 1
defaults:
  interval_minutes: 60
sources:
  kev:
    interval_minutes: 15
  epss:
    interval_minutes: 30
    params:
      page_limit: 5
"""


class FakeScheduler:
    """记录 ``add_job`` 调用的假调度器（不依赖 APScheduler）。"""

    def __init__(self) -> None:
        """初始化空的 job 表与状态标记。"""
        self.jobs: dict[str, dict[str, Any]] = {}
        self.started = False
        self.running = False
        self.shutdown_wait: bool | None = None

    def add_job(self, func: Any, **kwargs: Any) -> None:
        self.jobs[kwargs["id"]] = {"func": func, **kwargs}

    def start(self) -> None:
        self.started = True
        self.running = True

    def shutdown(self, wait: bool = False) -> None:
        self.shutdown_wait = wait
        self.running = False

    def get_job(self, job_id: str) -> None:
        return None


def make_settings() -> Settings:
    """构造不读取 ``.env`` 的配置对象。"""
    return Settings(_env_file=None)


def make_config(tmp_path: Path) -> SourcesConfig:
    """写出临时 ``sources.yaml`` 并加载。"""
    path = tmp_path / "sources.yaml"
    path.write_text(CONFIG_BODY, encoding="utf-8")
    return load_sources_config(path)


def make_scheduler(tmp_path: Path, **overrides: Any) -> tuple[CollectScheduler, FakeScheduler]:
    """构造注入了假调度器的采集调度器。"""
    fake = FakeScheduler()
    scheduler = CollectScheduler(
        settings=make_settings(),
        config=make_config(tmp_path),
        sources=overrides.pop("sources", ["kev", "epss"]),
        scheduler=fake,
        **overrides,
    )
    return scheduler, fake


def fake_stats(source: str, **overrides: Any) -> CollectStats:
    """构造一个统计对象（避免真实采集）。"""
    from aisec_intel.models.base import utc_now

    return CollectStats(source=source, since=utc_now(), **overrides)


class TestBuildSpecs:
    """调度规格装配（间隔来自 ``configs/sources.yaml``）。"""

    def test_intervals_and_params_come_from_yaml(self, tmp_path: Path) -> None:
        """每个源一个规格，间隔与 params 均取自 YAML。"""
        scheduler, _ = make_scheduler(tmp_path)
        specs = {spec.source: spec for spec in scheduler.build_specs()}
        assert set(specs) == {"kev", "epss"}
        assert specs["kev"].interval_minutes == 15
        assert specs["epss"].interval_minutes == 30
        assert specs["epss"].parameters == {"page_limit": 5}
        assert specs["kev"].config_source == "sources.yaml"

    def test_undeclared_source_falls_back_to_defaults(self, tmp_path: Path) -> None:
        """YAML 未声明的源取 ``defaults.interval_minutes``。"""
        scheduler, _ = make_scheduler(tmp_path, sources=["kev", "nvd"])
        specs = {spec.source: spec for spec in scheduler.build_specs()}
        assert specs["nvd"].interval_minutes == 60
        assert specs["nvd"].config_source == "defaults"


class TestJobRegistration:
    """job 注册行为。"""

    def test_one_job_per_enabled_source(self, tmp_path: Path) -> None:
        """每个源注册一个 interval job，间隔单位分钟。"""
        scheduler, fake = make_scheduler(tmp_path)
        assert scheduler.add_jobs() == 2
        assert set(fake.jobs) == {"collect:kev", "collect:epss"}
        kev_job = fake.jobs["collect:kev"]
        assert kev_job["minutes"] == 15
        assert kev_job["args"] == ["kev"]
        assert kev_job["max_instances"] == 1
        assert kev_job["coalesce"] is True
        assert kev_job["next_run_time"] is None

    def test_run_immediately_sets_next_run_time(self, tmp_path: Path) -> None:
        """``--run-now`` 时首次触发时间为当前时刻。"""
        scheduler, fake = make_scheduler(tmp_path, run_immediately=True)
        scheduler.add_jobs()
        assert fake.jobs["collect:kev"]["next_run_time"] is not None

    def test_start_starts_underlying_scheduler(self, tmp_path: Path) -> None:
        """``start()`` 会启动底层调度器并返回 job 数。"""
        scheduler, fake = make_scheduler(tmp_path)
        assert scheduler.start() == 2
        assert fake.started is True
        assert scheduler.running is True


class TestRunSource:
    """job 业务逻辑（调用 ``collect_service``）。"""

    async def test_forwards_mode_limit_and_normalize(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``run_source`` 把模式 / 上限 / 归一化开关透传给采集服务。"""
        captured: dict[str, Any] = {}

        async def fake_resolve_since(source: str, **kwargs: Any) -> Any:
            captured["since_call"] = {"source": source, **kwargs}
            return FULL_MODE_START

        async def fake_collect_source(source: str, **kwargs: Any) -> CollectStats:
            captured["collect_call"] = {"source": source, **kwargs}
            return fake_stats(source, fetched=2, processed=2, created=1, merged_count=1)

        monkeypatch.setattr("aisec_intel.services.scheduler.resolve_since", fake_resolve_since)
        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", fake_collect_source)
        seen: list[CollectStats] = []
        scheduler, _ = make_scheduler(tmp_path, mode="full", limit=7, normalize=True, on_stats=seen.append)

        stats = await scheduler.run_source("kev")

        assert captured["since_call"]["mode"] == "full"
        assert captured["collect_call"]["since"] == FULL_MODE_START
        assert captured["collect_call"]["limit"] == 7
        assert captured["collect_call"]["normalize"] is True
        assert captured["collect_call"]["mode"] == "full"
        assert stats.source == "kev"
        assert [item.source for item in scheduler.stats_history] == ["kev"]
        assert [item.source for item in seen] == ["kev"]

    async def test_job_failure_is_isolated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """单源异常不会抛出（调度器继续运行），且不污染统计历史。"""

        async def boom(source: str, **kwargs: Any) -> CollectStats:
            raise RuntimeError("源侧 500")

        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", boom)
        scheduler, _ = make_scheduler(tmp_path)

        result = await scheduler._run_job("kev")  # noqa: SLF001 - 直接验证 job 包装器

        assert result is None
        assert scheduler.stats_history == []
        assert scheduler.inflight == set()

    async def test_reentrant_job_is_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """同一源上一轮未结束时跳过本次触发（防止重入）。"""
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow(source: str, **kwargs: Any) -> CollectStats:
            started.set()
            await release.wait()
            return fake_stats(source)

        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", slow)
        scheduler, _ = make_scheduler(tmp_path)
        first = asyncio.create_task(scheduler._run_job("kev"))  # noqa: SLF001
        await started.wait()

        second = await scheduler._run_job("kev")  # noqa: SLF001
        assert second is None

        release.set()
        assert (await first) is not None


class TestLifecycle:
    """优雅停机与信号处理。"""

    async def test_serve_forever_starts_and_shuts_down(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``serve_forever`` 启动后按外部事件停机，并关闭底层调度器。"""
        installed: list[int] = []
        scheduler, fake = make_scheduler(tmp_path)
        monkeypatch.setattr(
            scheduler, "install_signal_handlers", lambda **kwargs: installed.extend([2, 15]) or [2, 15]
        )
        stop = asyncio.Event()
        stop.set()

        await scheduler.serve_forever(stop_event=stop)

        assert fake.started is True
        assert fake.shutdown_wait is False
        assert installed == [signal.SIGINT, signal.SIGTERM]

    async def test_shutdown_waits_for_inflight_job(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """停机时等待执行中的 job 收尾（不丢任务）。"""
        started = asyncio.Event()

        async def slow(source: str, **kwargs: Any) -> CollectStats:
            started.set()
            await asyncio.sleep(0.05)
            return fake_stats(source, fetched=1)

        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", slow)
        scheduler, _ = make_scheduler(tmp_path, shutdown_timeout=2.0)
        task = asyncio.create_task(scheduler._run_job("kev"))  # noqa: SLF001
        await started.wait()

        drained = await scheduler.shutdown(timeout=2.0)
        await task

        assert drained is True
        assert scheduler.inflight == set()
        assert len(scheduler.stats_history) == 1

    async def test_shutdown_times_out_on_stuck_job(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """job 卡住时按超时返回 ``False``（不再无限等待）。"""
        started = asyncio.Event()
        release = asyncio.Event()

        async def stuck(source: str, **kwargs: Any) -> CollectStats:
            started.set()
            await release.wait()
            return fake_stats(source)

        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", stuck)
        scheduler, _ = make_scheduler(tmp_path)
        task = asyncio.create_task(scheduler._run_job("kev"))  # noqa: SLF001
        await started.wait()

        drained = await scheduler.shutdown(timeout=0.05)
        release.set()
        await task

        assert drained is False

    def test_request_stop_sets_event(self, tmp_path: Path) -> None:
        """``request_stop`` 置位停止事件（信号回调的实际动作）。"""
        scheduler, _ = make_scheduler(tmp_path)
        assert scheduler._stop_event.is_set() is False  # noqa: SLF001
        scheduler.request_stop(signal.SIGTERM)
        assert scheduler._stop_event.is_set() is True  # noqa: SLF001

    def test_signal_handler_falls_back_on_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """事件循环不支持 ``add_signal_handler`` 时退化为 ``signal.signal``。"""
        calls: list[tuple[int, Any]] = []

        class NoSignalLoop:
            def add_signal_handler(self, *args: Any, **kwargs: Any) -> None:
                raise NotImplementedError

        monkeypatch.setattr(signal, "signal", lambda sig, handler: calls.append((int(sig), handler)))
        scheduler, _ = make_scheduler(tmp_path)

        installed = scheduler.install_signal_handlers(loop=NoSignalLoop())  # type: ignore[arg-type]

        assert installed == [signal.SIGINT, signal.SIGTERM]
        assert [sig for sig, _ in calls] == [signal.SIGINT, signal.SIGTERM]
        scheduler._restore_signals()  # noqa: SLF001
        assert len(calls) == 4  # 安装 2 次 + 恢复 2 次


class TestRealScheduler:
    """真实 APScheduler 装配冒烟（依赖已安装）。"""

    def test_default_scheduler_is_async_io_scheduler(self, tmp_path: Path) -> None:
        """默认装配得到 ``AsyncIOScheduler``（UTC 时区）。"""
        pytest.importorskip("apscheduler", reason="需要 apscheduler")
        from apscheduler.schedulers.asyncio import AsyncIOScheduler

        scheduler, _ = make_scheduler(tmp_path)
        scheduler._scheduler = None  # noqa: SLF001 - 强制走默认装配
        assert isinstance(scheduler.scheduler, AsyncIOScheduler)


