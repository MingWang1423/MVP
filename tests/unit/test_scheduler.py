"""调度器测试（PROJECT_PLAN.md §5.5 P4 任务 2 + Day19 分层 pipeline）。

用假调度器（:class:`FakeScheduler`）替代 APScheduler，验证：

1. **per-source 模式**（原逻辑）：每源一个 job 的规格装配、模式传递、异常隔离与优雅停机；
2. **pipeline 模式**（Day19）：四层间隔（采集 2h / 富化 6h / 图谱 12h / 向量 12h）、
   首次触发错开（0/10/20/30 分钟）、``--no-<stage>`` 收窄、子进程命令拼装与失败隔离。

末尾另有一条真实 ``AsyncIOScheduler`` 装配冒烟用例。
"""

from __future__ import annotations

import asyncio
import signal
from pathlib import Path
from typing import Any

import pytest

from aisec_intel.config import SchedulerConfig, Settings, SourcesConfig, load_sources_config
from aisec_intel.services.collect_service import FULL_MODE_START, CollectStats
from aisec_intel.services.scheduler import (
    CollectScheduler,
    PipelineConfig,
    _console_safe_text,
    _tail_lines,
    make_pipeline_specs,
    normalize_scheduler_mode,
    resolve_pipeline_config,
    resolve_scheduler_mode,
)

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

PIPELINE_CONFIG_BODY = """version: 1
defaults:
  interval_minutes: 60
sources:
  kev:
    interval_minutes: 15
scheduler:
  mode: pipeline
  pipeline:
    collect_interval_hours: 2
    enrich_interval_hours: 6
    graph_interval_hours: 12
    vector_interval_hours: 12
    enrich:
      batch_size: 50
      only_high_risk: true
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


def make_settings(**overrides: Any) -> Settings:
    """构造不读取 ``.env`` 的配置对象。

    Args:
        **overrides: 显式覆盖的配置项（会进入 ``model_fields_set``，用于验证优先级）。

    Returns:
        :class:`Settings` 实例。
    """
    return Settings(_env_file=None, **overrides)


def make_config(tmp_path: Path, body: str = CONFIG_BODY) -> SourcesConfig:
    """写出临时 ``sources.yaml`` 并加载。

    Args:
        tmp_path: 临时目录。
        body: YAML 正文（默认不含 ``scheduler`` 段）。

    Returns:
        解析后的 :class:`SourcesConfig`。
    """
    path = tmp_path / "sources.yaml"
    path.write_text(body, encoding="utf-8")
    return load_sources_config(path)


def make_scheduler(tmp_path: Path, **overrides: Any) -> tuple[CollectScheduler, FakeScheduler]:
    """构造注入了假调度器的采集调度器（默认走 **per-source** 模式）。

    Args:
        tmp_path: 临时目录。
        **overrides: 覆盖 ``CollectScheduler`` 构造参数。

    Returns:
        ``(scheduler, fake_scheduler)``。
    """
    fake = FakeScheduler()
    scheduler = CollectScheduler(
        settings=make_settings(),
        config=make_config(tmp_path),
        sources=overrides.pop("sources", ["kev", "epss"]),
        scheduler_mode=overrides.pop("scheduler_mode", "per_source"),
        scheduler=fake,
        **overrides,
    )
    return scheduler, fake


def make_pipeline_scheduler(
    tmp_path: Path, **overrides: Any
) -> tuple[CollectScheduler, FakeScheduler, list[list[str]]]:
    """构造 pipeline 模式的调度器（子进程执行器被桩替换）。

    Args:
        tmp_path: 临时目录。
        **overrides: 覆盖 ``CollectScheduler`` 构造参数。

    Returns:
        ``(scheduler, fake_scheduler, calls)``；``calls`` 记录每次子进程调用的 argv。
    """
    fake = FakeScheduler()
    calls: list[list[str]] = []

    async def runner(argv: Any) -> tuple[int, str]:
        calls.append([str(item) for item in argv])
        return 0, "[OK] stub output"

    scheduler = CollectScheduler(
        settings=make_settings(),
        config=make_config(tmp_path, PIPELINE_CONFIG_BODY),
        sources=overrides.pop("sources", ["kev"]),
        scheduler_mode="pipeline",
        scheduler=fake,
        command_runner=overrides.pop("command_runner", runner),
        **overrides,
    )
    return scheduler, fake, calls


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
        """每个源注册一个 interval job，另加 1 个每日失败重试 job（Day23 任务 2）。"""
        scheduler, fake = make_scheduler(tmp_path)
        assert scheduler.add_jobs() == 3
        assert set(fake.jobs) == {"collect:kev", "collect:epss", "maintenance:retry-failed"}
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
        """``start()`` 会启动底层调度器并返回 job 数（含失败重试 job）。"""
        scheduler, fake = make_scheduler(tmp_path)
        assert scheduler.start() == 3
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


class TestSchedulerModeResolution:
    """调度模式解析：CLI > 显式 Settings（环境变量）> ``sources.yaml`` > 默认。"""

    def test_cli_wins_over_settings_and_yaml(self, tmp_path: Path) -> None:
        """``--mode`` 优先级最高（并兼容 per-source / per_source 两种写法）。"""
        settings = make_settings(scheduler_mode="per_source")
        config = make_config(tmp_path, PIPELINE_CONFIG_BODY)
        assert resolve_scheduler_mode("pipeline", settings=settings, config=config) == "pipeline"
        assert resolve_scheduler_mode("per-source", settings=settings, config=config) == "per_source"

    def test_explicit_settings_win_over_yaml(self, tmp_path: Path) -> None:
        """环境变量 / 显式 Settings 优先于 YAML。"""
        settings = make_settings(scheduler_mode="per_source")
        config = make_config(tmp_path, PIPELINE_CONFIG_BODY)
        assert resolve_scheduler_mode(None, settings=settings, config=config) == "per_source"

    def test_yaml_used_when_settings_not_explicit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Settings 未显式设置时读 ``scheduler.mode``（支持 per-source 写法）。"""
        monkeypatch.delenv("SCHEDULER_MODE", raising=False)
        settings = Settings(_env_file=None)
        assert "scheduler_mode" not in settings.model_fields_set
        config = make_config(tmp_path, PIPELINE_CONFIG_BODY.replace("mode: pipeline", "mode: per-source"))
        assert resolve_scheduler_mode(None, settings=settings, config=config) == "per_source"

    def test_invalid_value_falls_back(self, tmp_path: Path) -> None:
        """无法识别的取值回退（不让调度器起不来）。"""
        settings = make_settings(scheduler_mode="bogus")
        config = make_config(tmp_path, PIPELINE_CONFIG_BODY)
        assert resolve_scheduler_mode(None, settings=settings, config=config) == "pipeline"

    def test_normalize_scheduler_mode_variants(self) -> None:
        """归一化函数兼容大小写与连字符，非法值显式报错。"""
        assert normalize_scheduler_mode("per-source") == "per_source"
        assert normalize_scheduler_mode("PER_SOURCE") == "per_source"
        assert normalize_scheduler_mode(None) == "pipeline"
        with pytest.raises(ValueError, match="未知调度模式"):
            normalize_scheduler_mode("weekly")


class TestPipelinePlan:
    """分层 pipeline 规格装配（纯函数）。"""

    def test_sources_config_parses_scheduler_section(self, tmp_path: Path) -> None:
        """``scheduler:`` 段被解析为 :class:`SchedulerConfig`。"""
        config = make_config(tmp_path, PIPELINE_CONFIG_BODY)
        assert isinstance(config.scheduler, SchedulerConfig)
        assert config.scheduler.mode == "pipeline"
        assert config.scheduler.pipeline.collect_interval_hours == 2
        assert config.scheduler.pipeline.enrich.batch_size == 50
        assert config.scheduler.pipeline.enrich.only_high_risk is True

    def test_four_stages_intervals_offsets_and_commands(self, tmp_path: Path) -> None:
        """四层规格：间隔 2/6/12/12 小时、错开 0/10/20/30 分钟、命令可复现。"""
        specs = {
            spec.stage: spec
            for spec in make_pipeline_specs(make_settings(), make_config(tmp_path, PIPELINE_CONFIG_BODY))
        }
        assert list(specs) == ["collect", "enrich", "graph", "vector"]
        assert [specs[stage].interval_hours for stage in specs] == [2, 6, 12, 12]
        assert [specs[stage].initial_offset_minutes for stage in specs] == [0, 10, 20, 30]
        assert specs["collect"].job_id == "pipeline:collect"
        assert specs["collect"].interval_minutes == 120
        assert specs["collect"].command == "内置 collect_source(--source all) + normalize"
        assert specs["enrich"].command == "python -m scripts.run_enrich --limit 50 --only-missing --only-high-risk"
        assert specs["graph"].command == "python -m scripts.load_graph --all"
        assert specs["vector"].command == "python -m scripts.index_vectors --all"
        assert all(spec.enabled for spec in specs.values())

    def test_stage_subset_disables_others(self, tmp_path: Path) -> None:
        """``--no-<stage>``（stages 收窄）时对应层标记为停用。"""
        specs = make_pipeline_specs(
            make_settings(), make_config(tmp_path, PIPELINE_CONFIG_BODY), stages=["collect", "enrich"]
        )
        assert [spec.enabled for spec in specs] == [True, True, False, False]

    def test_yaml_wins_over_settings_for_pipeline_values(self, tmp_path: Path) -> None:
        """YAML 显式声明的 pipeline 参数优先于 Settings。"""
        settings = make_settings(pipeline_collect_interval_hours=9, pipeline_enrich_batch_size=7)
        values = resolve_pipeline_config(settings, make_config(tmp_path, PIPELINE_CONFIG_BODY))
        assert values == PipelineConfig(
            collect_interval_hours=2,
            enrich_interval_hours=6,
            graph_interval_hours=12,
            vector_interval_hours=12,
            enrich_batch_size=50,
            enrich_only_high_risk=True,
        )

    def test_settings_fallback_when_yaml_silent(self, tmp_path: Path) -> None:
        """YAML 未声明 ``scheduler`` 段时回退到 Settings（env / 内置默认）。"""
        settings = make_settings(
            pipeline_collect_interval_hours=3,
            pipeline_enrich_batch_size=9,
            pipeline_enrich_only_high_risk=False,
        )
        values = resolve_pipeline_config(settings, make_config(tmp_path))
        assert values.collect_interval_hours == 3
        assert values.enrich_batch_size == 9
        assert values.enrich_only_high_risk is False


class TestPipelineJobRegistration:
    """pipeline job 注册（4 个分层 job + 首次触发错开）。"""

    def test_registers_four_hour_jobs(self, tmp_path: Path) -> None:
        """按小时注册 4 个分层 job（另有 1 个每日失败重试 job），id 为 ``pipeline:<stage>``。"""
        scheduler, fake, _ = make_pipeline_scheduler(tmp_path)
        assert scheduler.is_pipeline is True
        assert scheduler.add_jobs() == 5
        assert set(fake.jobs) == {
            "pipeline:collect",
            "pipeline:enrich",
            "pipeline:graph",
            "pipeline:vector",
            "maintenance:retry-failed",
        }
        assert fake.jobs["pipeline:collect"]["hours"] == 2
        assert fake.jobs["pipeline:enrich"]["hours"] == 6
        assert fake.jobs["pipeline:graph"]["hours"] == 12
        assert fake.jobs["pipeline:vector"]["hours"] == 12
        assert fake.jobs["pipeline:enrich"]["args"] == ["enrich"]
        assert fake.jobs["pipeline:vector"]["max_instances"] == 1
        assert fake.jobs["pipeline:vector"]["coalesce"] is True

    def test_first_run_times_are_staggered(self, tmp_path: Path) -> None:
        """首次触发按 0/10/20/30 分钟错开。"""
        scheduler, fake, _ = make_pipeline_scheduler(tmp_path)
        scheduler.add_jobs()
        times = {
            stage: fake.jobs[f"pipeline:{stage}"]["next_run_time"]
            for stage in ("collect", "enrich", "graph", "vector")
        }
        assert times["collect"] < times["enrich"] < times["graph"] < times["vector"]
        deltas = [
            (times["enrich"] - times["collect"]).total_seconds(),
            (times["graph"] - times["enrich"]).total_seconds(),
            (times["vector"] - times["graph"]).total_seconds(),
        ]
        assert deltas == [600.0, 600.0, 600.0]

    def test_run_immediately_overrides_stagger(self, tmp_path: Path) -> None:
        """``--run-now`` / ``--once`` 时四层立即触发（同一时刻）。"""
        scheduler, fake, _ = make_pipeline_scheduler(tmp_path, run_immediately=True)
        scheduler.add_jobs()
        times = {fake.jobs[f"pipeline:{stage}"]["next_run_time"] for stage in ("collect", "enrich", "graph", "vector")}
        assert len(times) == 1

    def test_disabled_stage_is_not_registered(self, tmp_path: Path) -> None:
        """``--no-graph --no-vector`` 等价于 stages 只含前两层（失败重试 job 仍在）。"""
        scheduler, fake, _ = make_pipeline_scheduler(tmp_path, pipeline_stages=["collect", "enrich"])
        assert scheduler.add_jobs() == 3
        assert set(fake.jobs) == {"pipeline:collect", "pipeline:enrich", "maintenance:retry-failed"}

    def test_scheduled_jobs_reports_stage_ids(self, tmp_path: Path) -> None:
        """``scheduled_jobs`` 输出阶段 id 与间隔（分钟），末行为失败重试队列。"""
        scheduler, _, _ = make_pipeline_scheduler(tmp_path)
        scheduler.add_jobs()
        summary = scheduler.scheduled_jobs()
        assert [row["id"] for row in summary] == [
            "pipeline:collect",
            "pipeline:enrich",
            "pipeline:graph",
            "pipeline:vector",
            "maintenance:retry-failed",
        ]
        assert [row["interval_minutes"] for row in summary] == [120, 360, 720, 720, 1440]
        assert [row["stage"] for row in summary] == ["collect", "enrich", "graph", "vector", "retry"]
        assert summary[-1]["cron"] == "0 2 * * *"


class TestPipelineStageExecution:
    """pipeline 阶段执行（collect 进程内；enrich/graph/vector 子进程）。"""

    async def test_enrich_stage_runs_expected_command(self, tmp_path: Path) -> None:
        """富化层拼出 ``--limit N --only-missing --only-high-risk`` 并记录统计。"""
        scheduler, _, calls = make_pipeline_scheduler(tmp_path)
        stats = await scheduler.run_pipeline_stage("enrich")

        assert stats.status == "succeeded"
        assert calls == [["-m", "scripts.run_enrich", "--limit", "50", "--only-missing", "--only-high-risk"]]
        assert "退出码=0" in stats.detail
        assert scheduler.pipeline_history == [stats]

    async def test_graph_and_vector_stage_commands(self, tmp_path: Path) -> None:
        """图谱 / 向量层分别调 ``load_graph --all`` 与 ``index_vectors --all``。"""
        scheduler, _, calls = make_pipeline_scheduler(tmp_path)
        await scheduler.run_pipeline_stage("graph")
        await scheduler.run_pipeline_stage("vector")
        assert calls == [["-m", "scripts.load_graph", "--all"], ["-m", "scripts.index_vectors", "--all"]]

    async def test_collect_stage_runs_all_sources_with_normalize(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """采集层在进程内逐源调用 ``collect_source``，且强制 normalize。"""
        captured: list[dict[str, Any]] = []

        async def fake_resolve_since(source: str, **kwargs: Any) -> Any:
            return FULL_MODE_START

        async def fake_collect_source(source: str, **kwargs: Any) -> CollectStats:
            captured.append({"source": source, **kwargs})
            return fake_stats(source, fetched=1)

        monkeypatch.setattr("aisec_intel.services.scheduler.resolve_since", fake_resolve_since)
        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", fake_collect_source)
        scheduler, _, calls = make_pipeline_scheduler(tmp_path, sources=["kev", "epss"])

        stats = await scheduler.run_pipeline_stage("collect")

        assert stats.status == "succeeded"
        assert [row["source"] for row in captured] == ["kev", "epss"]
        assert all(row["normalize"] is True for row in captured)
        assert "成功=2" in stats.detail
        assert calls == []  # 采集层不启子进程

    async def test_collect_stage_isolates_source_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """单源异常不阻断其他源，阶段标记为 failed 但不抛异常。"""

        async def fake_resolve_since(source: str, **kwargs: Any) -> Any:
            return FULL_MODE_START

        async def boom(source: str, **kwargs: Any) -> CollectStats:
            raise RuntimeError("源侧 500")

        monkeypatch.setattr("aisec_intel.services.scheduler.resolve_since", fake_resolve_since)
        monkeypatch.setattr("aisec_intel.services.scheduler.collect_source", boom)
        scheduler, _, _ = make_pipeline_scheduler(tmp_path, sources=["kev", "epss"])

        stats = await scheduler.run_pipeline_stage("collect")

        assert stats.status == "failed"
        assert "失败=2" in stats.detail
        assert stats.error is not None

    async def test_subprocess_exception_is_isolated(self, tmp_path: Path) -> None:
        """执行器抛异常时 job 包装器吞掉异常并返回失败统计。"""

        async def failing(argv: Any) -> tuple[int, str]:
            raise RuntimeError("子进程启动失败")

        scheduler, _, _ = make_pipeline_scheduler(tmp_path, command_runner=failing)
        stats = await scheduler._run_pipeline_job("graph")  # noqa: SLF001

        assert stats is not None
        assert stats.status == "failed"
        assert "RuntimeError" in (stats.error or "")

    async def test_nonzero_exit_code_marks_failed(self, tmp_path: Path) -> None:
        """子进程非 0 退出码 → 阶段 failed（如 Neo4j 不可用）。"""

        async def bad(argv: Any) -> tuple[int, str]:
            return 1, "[FAIL] Neo4j 不可用"

        scheduler, _, _ = make_pipeline_scheduler(tmp_path, command_runner=bad)
        stats = await scheduler.run_pipeline_stage("graph")

        assert stats.status == "failed"
        assert "退出码 1" in (stats.error or "")

    async def test_reentrant_stage_is_skipped(self, tmp_path: Path) -> None:
        """同一层上一轮未结束时跳过本次触发（防重入）。"""
        started = asyncio.Event()
        release = asyncio.Event()

        async def slow(argv: Any) -> tuple[int, str]:
            started.set()
            await release.wait()
            return 0, "ok"

        scheduler, _, _ = make_pipeline_scheduler(tmp_path, command_runner=slow)
        first = asyncio.create_task(scheduler._run_pipeline_job("enrich"))  # noqa: SLF001
        await started.wait()

        skipped = await scheduler._run_pipeline_job("enrich")  # noqa: SLF001
        assert skipped is None

        release.set()
        assert (await first) is not None

    async def test_stage_detail_is_console_safe(self, tmp_path: Path) -> None:
        """子进程输出含 GBK 不可编码字符时，摘要被清洗（不中断汇总打印）。"""

        async def noisy(argv: Any) -> tuple[int, str]:
            return 1, "sqlite3.OperationalError: no such table \ufffd [Errno 22]"

        scheduler, _, _ = make_pipeline_scheduler(tmp_path, command_runner=noisy)
        stats = await scheduler.run_pipeline_stage("vector")

        assert "\ufffd" not in stats.detail
        assert "?" in stats.detail
        stats.detail.encode("gbk")  # 不应抛 UnicodeEncodeError


class TestConsoleSafeText:
    """``_console_safe_text`` / ``_tail_lines`` 纯函数（Windows GBK 控制台保护）。"""

    def test_replacement_and_encoding_fallback(self) -> None:
        """``U+FFFD`` → ``?``；目标编码装不下的字符也降级为 ``?``。"""
        assert _console_safe_text("ok \ufffd", encoding="gbk") == "ok ?"
        assert _console_safe_text("ok 🙂", encoding="gbk") == "ok ?"

    def test_max_chars_truncates_with_ellipsis(self) -> None:
        """超长文本按上限截断并加省略号。"""
        result = _console_safe_text("x" * 300, encoding="utf-8", max_chars=10)
        assert len(result) == 10
        assert result.endswith("…")

    def test_tail_lines_keeps_last_non_empty_lines(self) -> None:
        """``_tail_lines`` 只保留最后若干非空行并以 `` / `` 连接。"""
        text = "line1\n\nline2\n line3 \nline4\n"
        assert _tail_lines(text, limit=2, max_chars=100) == "line3 / line4"
        assert _tail_lines("", limit=2) == ""


class TestChildProcessReaping:
    """停机回收残留 pipeline 子进程（Day19 实测到孤儿 ``run_enrich`` 后加固）。"""

    class FakeProcess:
        """最小子进程替身（只需 ``returncode`` / ``kill`` / ``wait``）。"""

        def __init__(self, returncode: int | None = None) -> None:
            """初始化替身。

            Args:
                returncode: ``None`` 表示仍在运行。
            """
            self.returncode = returncode
            self.killed = False

        def kill(self) -> None:
            """标记为已终止。"""
            self.killed = True

        async def wait(self) -> int | None:
            """模拟等待子进程退出。"""
            self.returncode = -9 if self.killed else self.returncode
            return self.returncode

    async def test_terminate_children_kills_only_running(self, tmp_path: Path) -> None:
        """只 kill 仍在运行的子进程，已退出的不动，并清空登记表。"""
        scheduler, _, _ = make_pipeline_scheduler(tmp_path)
        running = self.FakeProcess()
        finished = self.FakeProcess(returncode=0)
        scheduler._child_processes.update({running, finished})  # noqa: SLF001

        reaped = await scheduler.terminate_pipeline_children()

        assert reaped == 1
        assert running.killed is True
        assert finished.killed is False
        assert scheduler._child_processes == set()  # noqa: SLF001

    async def test_shutdown_reaps_children(self, tmp_path: Path) -> None:
        """``shutdown()`` 在收尾阶段回收残留子进程。"""
        scheduler, _, _ = make_pipeline_scheduler(tmp_path)
        scheduler.start()
        process = self.FakeProcess()
        scheduler._child_processes.add(process)  # noqa: SLF001

        drained = await scheduler.shutdown(timeout=0.05)

        assert drained is True
        assert process.killed is True
        assert scheduler._child_processes == set()  # noqa: SLF001


class TestRetryJobRegistration:
    """每日失败重试队列 job（Day23 任务 2：``maintenance:retry-failed``，cron 0 2 * * *）。"""

    def test_cron_job_registered_with_daily_2am(self, tmp_path: Path) -> None:
        """注册为 cron job（hour=2 / minute=0），单实例 + 合并漏跑。"""
        scheduler, fake, _ = make_pipeline_scheduler(tmp_path)
        scheduler.add_jobs()
        job = fake.jobs["maintenance:retry-failed"]
        assert job["trigger"] == "cron"
        assert (job["hour"], job["minute"]) == (2, 0)
        assert job["max_instances"] == 1
        assert job["coalesce"] is True
        assert job["misfire_grace_time"] > 0

    def test_disabled_retry_job_is_not_registered(self, tmp_path: Path) -> None:
        """``--no-retry`` 时不注册维护 job，分层 4 层仍照常注册。"""
        scheduler, fake, _ = make_pipeline_scheduler(tmp_path, retry_enabled=False)
        assert scheduler.add_jobs() == 4
        assert "maintenance:retry-failed" not in fake.jobs
        assert scheduler.scheduled_jobs()[-1]["enabled"] is False

    async def test_run_retry_job_records_history(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """job 执行成功 → ``retry_history`` 记录扫描/恢复/永久失败计数。"""
        from aisec_intel.services import enrich_service

        async def fake_retry_failed(settings: Any, **kwargs: Any) -> Any:
            return enrich_service.RetryReport(
                scanned=3, recovered=2, retry_failed=0, permanently_failed=1, duration_s=0.4
            )

        monkeypatch.setattr(enrich_service, "retry_failed", fake_retry_failed)
        scheduler, _, _ = make_pipeline_scheduler(tmp_path)

        summary = await scheduler._run_retry_job()  # noqa: SLF001

        assert summary is not None and summary["status"] == "succeeded"
        assert (summary["scanned"], summary["recovered"], summary["permanently_failed"]) == (3, 2, 1)
        assert scheduler.retry_history[-1]["job_id"] == "maintenance:retry-failed"
        assert scheduler.inflight == set()

    async def test_run_retry_job_isolates_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """job 内异常被吞掉（不终止调度器），并在 ``retry_history`` 留下失败记录。"""
        from aisec_intel.services import enrich_service

        async def boom(settings: Any, **kwargs: Any) -> Any:
            raise RuntimeError("模拟重试队列崩溃")

        monkeypatch.setattr(enrich_service, "retry_failed", boom)
        scheduler, _, _ = make_pipeline_scheduler(tmp_path)

        result = await scheduler._run_retry_job()  # noqa: SLF001

        assert result is None
        assert scheduler.retry_history[-1]["status"] == "failed"
        assert "模拟重试队列崩溃" in scheduler.retry_history[-1]["detail"]
        assert scheduler.inflight == set()


