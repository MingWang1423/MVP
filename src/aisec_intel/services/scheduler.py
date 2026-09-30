"""采集调度器（PROJECT_PLAN.md §5.5 P4：多源周期采集、增量模式与优雅退出）。

基于 APScheduler ``AsyncIOScheduler``：

1. **每个启用源一个 interval job**，间隔取自 ``configs/sources.yaml`` 的 ``interval_minutes``
   （未声明的源取 ``defaults.interval_minutes``）；
2. job 内部调用 :func:`aisec_intel.services.collect_service.collect_source`，
   与 ``scripts/run_collect.py`` **共用同一份逻辑**（含游标、去重合并、任务留痕）；
3. **两种模式**：``incremental`` 用 ``task_repo.last_run_at`` 作 ``since``；
   ``full`` 从固定起点（``FULL_MODE_START`` = 2024-01-01）全量拉；
4. **优雅停机**：收到 ``SIGINT`` / ``SIGTERM`` 后停止接受新 job，等待执行中的 job 收尾
   （Windows 事件循环不支持 ``add_signal_handler`` 时自动退化为 ``signal.signal``）；
5. **单源失败隔离**：job 内部吞掉异常并记日志，任何源失败都不会终止调度器。

CLI 入口见 ``scripts/run_scheduler.py``。
"""

from __future__ import annotations

import asyncio
import signal
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from types import FrameType
from typing import Any

from aisec_intel.config import Settings, SourcesConfig, get_settings, load_sources_config
from aisec_intel.logging_config import get_logger
from aisec_intel.services.collect_service import (
    CollectStats,
    collect_source,
    enabled_sources_from_config,
    resolve_since,
    source_interval_minutes,
)

logger = get_logger(__name__)

SCHEDULER_TIMEZONE: str = "UTC"
"""调度器时区（全项目统一 UTC，§10.2 不变式 3）。"""

JOB_ID_PREFIX: str = "collect"
"""job id 前缀：``collect:<source>``。"""

DEFAULT_SHUTDOWN_TIMEOUT_S: float = 30.0
"""优雅停机等待执行中 job 的上限（秒）。"""

MISFIRE_GRACE_S: int = 300
"""错过触发点的宽限时间（秒）：进程重启后 5 分钟内的漏跑仍会补跑一次。"""


@dataclass(slots=True)
class ScheduleSpec:
    """单个源的调度规格。

    Attributes:
        source: 源标识。
        interval_minutes: 调度间隔（分钟）。
        enabled: 是否参与调度（YAML 开关）。
        config_source: 配置来源（``sources.yaml`` / ``defaults``）。
        parameters: 该源的 ``params``（仅用于日志展示）。
    """

    source: str
    interval_minutes: int
    enabled: bool = True
    config_source: str = "sources.yaml"
    parameters: dict[str, Any] = field(default_factory=dict)


class CollectScheduler:
    """多源周期采集调度器。

    Attributes:
        stats_history: 已完成 job 的统计（按完成顺序，供测试与运维页查询）。
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        config: SourcesConfig | None = None,
        mode: str = "incremental",
        limit: int = 0,
        normalize: bool = False,
        sources: Sequence[str] | None = None,
        run_immediately: bool = False,
        shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT_S,
        on_stats: Callable[[CollectStats], None] | None = None,
        scheduler: Any | None = None,
    ) -> None:
        """初始化调度器（不启动）。

        Args:
            settings: 全局配置；``None`` 时使用 :func:`aisec_intel.config.get_settings`。
            config: 源配置；``None`` 时读取 ``Settings.sources_config_path``。
            mode: ``incremental`` / ``full``。
            limit: 每源每次采集的处理条数上限（0 = 不限）。
            normalize: 是否同步归一化并写入 ``unified_vuln``。
            sources: 参与调度的源；``None`` 时取「YAML 启用 且 已注册」的源。
            run_immediately: ``True`` 时启动即触发一次（演示 / 冒烟用）。
            shutdown_timeout: 优雅停机等待上限（秒）。
            on_stats: 每次 job 完成后的回调（前端运维页 / 测试注入）。
            scheduler: 注入的调度器实例（测试用假实现）；``None`` 时使用 APScheduler。
        """
        self._settings = settings or get_settings()
        self._config = config if config is not None else load_sources_config(settings=self._settings)
        self._mode = mode
        self._limit = limit
        self._normalize = normalize
        self._requested = list(sources) if sources else enabled_sources_from_config(self._settings, config=self._config)
        self._run_immediately = run_immediately
        self._shutdown_timeout = shutdown_timeout
        self._on_stats = on_stats
        self._scheduler = scheduler
        self._specs: list[ScheduleSpec] = []
        self._inflight: set[str] = set()
        self._stop_event = asyncio.Event()
        self._loop_signals: list[int] = []
        self._os_signals: list[int] = []
        self.stats_history: list[CollectStats] = []

    # ---------- 规格装配 ----------

    def build_specs(self) -> list[ScheduleSpec]:
        """构建每个源的调度规格（间隔取自 ``sources.yaml``）。

        Returns:
            调度规格列表（按源标识排序）。
        """
        specs = [
            ScheduleSpec(
                source=source,
                interval_minutes=source_interval_minutes(self._settings, source, config=self._config),
                enabled=True,
                config_source=self._config_source(source),
                parameters=dict(entry.params) if (entry := self._config.for_source(source)) else {},
            )
            for source in self._requested
        ]
        self._specs = sorted(specs, key=lambda spec: spec.source)
        return self._specs

    def _config_source(self, source: str) -> str:
        """判断某源的间隔来自 ``sources.yaml`` 还是 ``defaults``。"""
        return "sources.yaml" if self._config.for_source(source) is not None else "defaults"

    @property
    def specs(self) -> list[ScheduleSpec]:
        """当前调度规格（未构建时为空列表）。"""
        return self._specs

    # ---------- APScheduler 装配 ----------

    @staticmethod
    def _default_scheduler() -> Any:
        """创建 APScheduler ``AsyncIOScheduler``（未安装时给出可操作提示）。

        Returns:
            调度器实例。

        Raises:
            RuntimeError: 未安装 ``apscheduler``。
        """
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
        except ImportError as exc:  # pragma: no cover - 依赖缺失时的可读提示
            raise RuntimeError(
                "未安装 APScheduler：python -m pip install -i "
                "https://pypi.tuna.tsinghua.edu.cn/simple 'apscheduler>=3.10,<4'"
            ) from exc
        return AsyncIOScheduler(timezone=SCHEDULER_TIMEZONE)

    @property
    def scheduler(self) -> Any:
        """底层调度器实例（惰性创建）。"""
        if self._scheduler is None:
            self._scheduler = self._default_scheduler()
        return self._scheduler

    def add_jobs(self) -> int:
        """为每个源注册 interval job（幂等：同 id 会被 APScheduler 替换）。

        Returns:
            注册的 job 数量。
        """
        specs = self._specs or self.build_specs()
        target = self.scheduler
        for spec in specs:
            if not spec.enabled:
                continue
            target.add_job(
                self._run_job,
                trigger="interval",
                minutes=spec.interval_minutes,
                args=[spec.source],
                id=f"{JOB_ID_PREFIX}:{spec.source}",
                name=f"collect {spec.source}（每 {spec.interval_minutes} 分钟）",
                max_instances=1,
                coalesce=True,
                misfire_grace_time=MISFIRE_GRACE_S,
                next_run_time=_now_for_apscheduler() if self._run_immediately else None,
            )
        logger.info(
            f"调度装配完成：{len(specs)} 个源，mode={self._mode}，"
            f"间隔={{{', '.join(f'{spec.source}:{spec.interval_minutes}m' for spec in specs)}}}"
        )
        return len(specs)

    def scheduled_jobs(self) -> list[dict[str, Any]]:
        """列出已注册 job 的摘要（供 CLI 打印）。

        Returns:
            ``[{"id", "source", "interval_minutes", "next_run_time"}, ...]``。
        """
        summary: list[dict[str, Any]] = []
        for spec in self._specs:
            job = None
            try:
                job = self.scheduler.get_job(f"{JOB_ID_PREFIX}:{spec.source}")
            except Exception:  # noqa: BLE001 - 假调度器 / 未启动时忽略
                job = None
            summary.append(
                {
                    "id": f"{JOB_ID_PREFIX}:{spec.source}",
                    "source": spec.source,
                    "interval_minutes": spec.interval_minutes,
                    "next_run_time": getattr(job, "next_run_time", None),
                }
            )
        return summary

    # ---------- job 执行 ----------

    async def run_source(self, source: str) -> CollectStats:
        """执行一次单源采集（job 的实际业务逻辑）。

        Args:
            source: 源标识。

        Returns:
            :class:`CollectStats` 统计结果。
        """
        since = await resolve_since(source, mode=self._mode, settings=self._settings)
        stats = await collect_source(
            source,
            since=since,
            settings=self._settings,
            limit=self._limit,
            normalize=self._normalize,
            mode=self._mode,
        )
        self.stats_history.append(stats)
        flag = "OK  " if stats.status == "succeeded" else "FAIL"
        logger.info(
            f"[{flag} {source}] mode={stats.mode} 拉取={stats.fetched} 处理={stats.processed} "
            f"新增={stats.created} 合并={stats.merged_count} 耗时={stats.duration_s:.2f}s"
        )
        if stats.error:
            logger.warning(f"[{source}] 采集失败：{stats.error}")
        if self._on_stats is not None:
            self._on_stats(stats)
        return stats

    async def _run_job(self, source: str) -> CollectStats | None:
        """job 包装器：保证任何异常都不会杀死调度器。

        Args:
            source: 源标识。

        Returns:
            正常完成时返回统计结果；失败时返回 ``None``。
        """
        if source in self._inflight:  # max_instances=1 之外的二次保险
            logger.warning(f"{source} 上一轮仍在执行，跳过本次触发")
            return None
        self._inflight.add(source)
        try:
            return await self.run_source(source)
        except Exception as exc:  # noqa: BLE001 - 单源失败不得中断调度
            logger.error(f"[{source}] job 异常：{type(exc).__name__}: {exc}")
            return None
        finally:
            self._inflight.discard(source)

    # ---------- 生命周期 ----------

    def start(self) -> int:
        """装配 job 并启动调度器（不阻塞）。

        Returns:
            注册的 job 数量。
        """
        count = self.add_jobs()
        self.scheduler.start()
        logger.info(f"调度器已启动（mode={self._mode}，{count} 个 job）")
        return count

    def request_stop(self, signum: int | None = None) -> None:
        """请求停机（信号回调与测试均可调用）。

        Args:
            signum: 触发停机的信号编号；``None`` 表示程序内部请求。
        """
        if signum is not None:
            logger.warning(f"收到信号 {signum}，开始优雅停机")
        self._stop_event.set()

    def install_signal_handlers(self, *, loop: asyncio.AbstractEventLoop | None = None) -> list[int]:
        """安装 ``SIGINT`` / ``SIGTERM`` 处理（Windows 自动退化）。

        Args:
            loop: 目标事件循环；``None`` 时取当前运行中的循环。

        Returns:
            已成功安装的信号编号列表。
        """
        target_loop = loop or asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                target_loop.add_signal_handler(sig, self.request_stop, sig)
                self._loop_signals.append(int(sig))
            except (NotImplementedError, RuntimeError, ValueError):
                # Windows 的 ProactorEventLoop 不支持 add_signal_handler → 退化为 signal.signal
                try:
                    signal.signal(sig, self._os_signal_handler)
                    self._os_signals.append(int(sig))
                except (ValueError, OSError):  # pragma: no cover - 非主线程
                    logger.warning(f"无法安装信号处理：{sig}")
        logger.info(f"信号处理已安装：loop={self._loop_signals} os={self._os_signals}")
        return [*self._loop_signals, *self._os_signals]

    def _os_signal_handler(self, signum: int, frame: FrameType | None) -> None:
        """同步信号回调（Windows 兜底），只做最轻量的置位动作。"""
        self.request_stop(signum)

    def _restore_signals(self) -> None:
        """恢复默认信号处理（避免影响同进程内的其他组件与测试）。"""
        for sig in self._os_signals:
            try:
                signal.signal(sig, signal.SIG_DFL)
            except (ValueError, OSError):  # pragma: no cover - 非主线程
                continue
        self._os_signals.clear()
        self._loop_signals.clear()

    @property
    def running(self) -> bool:
        """调度器是否处于运行状态。"""
        return bool(getattr(self._scheduler, "running", False))

    @property
    def inflight(self) -> set[str]:
        """正在执行中的源标识集合。"""
        return set(self._inflight)

    async def wait_until_idle(self, *, timeout: float | None = None) -> bool:
        """等待执行中的 job 全部结束。

        Args:
            timeout: 等待上限（秒）；``None`` 时取 ``shutdown_timeout``。

        Returns:
            全部结束返回 ``True``；超时返回 ``False``。
        """
        deadline = time.monotonic() + (timeout if timeout is not None else self._shutdown_timeout)
        while self._inflight and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        return not self._inflight

    async def shutdown(self, *, timeout: float | None = None) -> bool:
        """优雅停机：停止调度 → 等待执行中的 job → 恢复信号处理。

        Args:
            timeout: 等待执行中 job 的上限（秒）；``None`` 时取 ``shutdown_timeout``。

        Returns:
            在时限内全部收尾返回 ``True``，否则 ``False``（超时不再等待）。
        """
        self._stop_event.set()
        if self._scheduler is not None and getattr(self._scheduler, "running", False):
            self._scheduler.shutdown(wait=False)
        drained = await self.wait_until_idle(timeout=timeout)
        self._restore_signals()
        logger.info(f"调度器已停机（进行中 job 收尾：{'完成' if drained else '超时'}）")
        return drained

    async def serve_forever(self, *, stop_event: asyncio.Event | None = None) -> None:
        """启动调度器并阻塞，直到收到停止信号 / 外部事件。

        Args:
            stop_event: 外部停止事件（测试用）；``None`` 时使用内部事件（由信号触发）。
        """
        self.start()
        self.install_signal_handlers()
        event = stop_event or self._stop_event
        try:
            await event.wait()
        finally:
            await self.shutdown()


def _now_for_apscheduler() -> Any:
    """返回 APScheduler 可接受的「当前时间」（调用方负责时区一致）。

    Returns:
        带 UTC 时区的 ``datetime``（APScheduler 3.x 依据调度器时区换算）。
    """
    from aisec_intel.models.base import utc_now

    return utc_now()


