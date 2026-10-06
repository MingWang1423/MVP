"""采集调度器（PROJECT_PLAN.md §5.5 P4：多源周期采集、增量模式与优雅退出）。

基于 APScheduler ``AsyncIOScheduler``，支持**两种调度布局**（``scheduler_mode``）：

A. ``pipeline``（默认，分层流水线，Day19 新增）—— 每层一个 interval job，共 4 个：

   1. ``collect``（每 2h）：对全部启用源跑一轮 :func:`collect_source` **并同步归一化**；
   2. ``enrich``（每 6h）：子进程执行 ``python -m scripts.run_enrich --limit N --only-missing``
      （``--only-high-risk`` 由配置决定）；
   3. ``graph``（每 12h）：子进程执行 ``python -m scripts.load_graph --all``；
   4. ``vector``（每 12h）：子进程执行 ``python -m scripts.index_vectors --all``。

   首次触发按 **0 / 10 / 20 / 30 分钟**错开，避免四层同时抢占 DB / LLM 额度；
   ``run_immediately``（``--run-now`` / ``--once``）时四层立即各触发一轮（覆盖错开）。

B. ``per_source``（可选，保留原逻辑）—— **每个启用源一个 interval job**，
   间隔取自 ``configs/sources.yaml`` 的 ``interval_minutes``（未声明的源取 ``defaults.interval_minutes``）。

以上两种布局之外，还会注册 1 个**全局维护 job**（Day23 任务 2）：

- ``maintenance:retry-failed``（cron ``0 2 * * *``，每日凌晨 2 点）：跑一轮「失败重试队列」——
  扫描 ``review_status='needs_human'`` 的富化结论并自动重试，最多 3 次，
  用尽则标记 ``permanently_failed``（实现见
  :func:`aisec_intel.services.enrich_service.retry_failed`）。

共同行为：

- 采集 job 与 ``scripts/run_collect.py`` **共用同一份逻辑**（含游标、去重合并、任务留痕）；
- **两种采集模式**：``incremental`` 用 ``task_repo.last_run_at`` 作 ``since``；
  ``full`` 从固定起点（``FULL_MODE_START`` = 2024-01-01）全量拉；
- **优雅停机**：收到 ``SIGINT`` / ``SIGTERM`` 后停止接受新 job，等待执行中的 job 收尾
  （Windows 事件循环不支持 ``add_signal_handler`` 时自动退化为 ``signal.signal``）；
- **失败隔离**：每个 job 内部独立 try-except 并记日志，任何一层 / 任何源失败都不会终止调度器。

pipeline 的富化 / 图谱 / 向量层以**独立子进程**执行：单层崩溃或 OOM 不会带走调度器进程，
同时避免 services 层反向 import ``scripts`` 破坏分层。CLI 入口见 ``scripts/run_scheduler.py``。
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from types import FrameType
from typing import Any

from aisec_intel.config import (
    PIPELINE_STAGES,
    SchedulerMode,
    Settings,
    SourcesConfig,
    get_settings,
    load_sources_config,
    normalize_scheduler_mode,
)
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
"""per-source 模式 job id 前缀：``collect:<source>``。"""

PIPELINE_JOB_PREFIX: str = "pipeline"
"""pipeline 模式 job id 前缀：``pipeline:<stage>``。"""

PIPELINE_STAGE_OFFSETS_MINUTES: dict[str, int] = {"collect": 0, "enrich": 10, "graph": 20, "vector": 30}
"""分层流水线首次触发错开（分钟）：采集 0 → 富化 10 → 图谱 20 → 向量 30。"""

PIPELINE_STAGE_TIMEOUT_S: float = 3600.0
"""pipeline 子进程阶段的单次执行上限（秒）；超时按失败处理，不阻断其他层。"""

PIPELINE_OUTPUT_TAIL_LINES: int = 4
"""子进程输出保留的最后若干非空行（进日志 / ``--list`` 摘要，避免刷屏）。"""

REPO_ROOT: Path = Path(__file__).resolve().parents[3]
"""仓库根目录：子进程以它为 cwd，保证 ``python -m scripts.*`` 可解析。"""

DEFAULT_SHUTDOWN_TIMEOUT_S: float = 30.0
"""优雅停机等待执行中 job 的上限（秒）。"""

MISFIRE_GRACE_S: int = 300
"""错过触发点的宽限时间（秒）：进程重启后 5 分钟内的漏跑仍会补跑一次。"""

RETRY_JOB_ID: str = "maintenance:retry-failed"
"""失败重试队列 job id（全局维护任务，两种调度布局下都会注册，见 PROJECT_PLAN.md §12.19）。"""

RETRY_CRON_HOUR: int = 2
"""失败重试队列触发小时（cron ``0 2 * * *`` = 每日凌晨 2 点）。"""

RETRY_CRON_MINUTE: int = 0
"""失败重试队列触发分钟。"""

RETRY_BATCH_SIZE: int = 50
"""单轮重试最多处理条数（与 ``enrich_service.DEFAULT_RETRY_BATCH_SIZE`` 保持一致，单测校验）。"""

RETRY_MAX_ATTEMPTS: int = 3
"""单条富化结论的最大自动重试次数（与 ``enrich_service.MAX_RETRY_ATTEMPTS`` 保持一致，单测校验）。"""


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


@dataclass(slots=True)
class PipelineConfig:
    """分层 pipeline 的运行时参数（``sources.yaml`` 显式声明 > ``Settings`` > 内置默认）。

    Attributes:
        collect_interval_hours: 采集层间隔（小时）。
        enrich_interval_hours: 富化层间隔（小时）。
        graph_interval_hours: 图谱层间隔（小时）。
        vector_interval_hours: 向量层间隔（小时）。
        enrich_batch_size: 富化层每轮条数上限（``run_enrich --limit N``）。
        enrich_only_high_risk: 富化层是否只处理高危条目。
    """

    collect_interval_hours: int = 2
    enrich_interval_hours: int = 6
    graph_interval_hours: int = 12
    vector_interval_hours: int = 12
    enrich_batch_size: int = 50
    enrich_only_high_risk: bool = True

    def interval_hours(self, stage: str) -> int:
        """返回某阶段的调度间隔（小时）。

        Args:
            stage: 阶段名（``collect`` / ``enrich`` / ``graph`` / ``vector``）。

        Returns:
            间隔小时数。

        Raises:
            ValueError: 阶段名不在四层之内。
        """
        mapping = {
            "collect": self.collect_interval_hours,
            "enrich": self.enrich_interval_hours,
            "graph": self.graph_interval_hours,
            "vector": self.vector_interval_hours,
        }
        if stage not in mapping:
            raise ValueError(f"未知 pipeline 阶段：{stage}（可选：{' / '.join(PIPELINE_STAGES)}）")
        return mapping[stage]


@dataclass(slots=True)
class PipelineJobSpec:
    """分层 pipeline 中单个阶段的调度规格。

    Attributes:
        stage: 阶段名（``collect`` / ``enrich`` / ``graph`` / ``vector``）。
        interval_hours: 调度间隔（小时）。
        initial_offset_minutes: 首次触发相对调度器启动时刻的错开分钟数。
        command: 该阶段实际执行的命令（``--list`` 展示与日志留痕）。
        enabled: 是否参与调度（命令行 ``--no-<stage>`` 可关闭）。
    """

    stage: str
    interval_hours: int
    initial_offset_minutes: int = 0
    command: str = ""
    enabled: bool = True

    @property
    def job_id(self) -> str:
        """APScheduler job id，形如 ``pipeline:collect``。"""
        return f"{PIPELINE_JOB_PREFIX}:{self.stage}"

    @property
    def interval_minutes(self) -> int:
        """调度间隔（分钟）。"""
        return self.interval_hours * 60


@dataclass(slots=True)
class PipelineStageStats:
    """单个 pipeline 阶段的执行统计（与 :class:`CollectStats` 区分：本类为「层」粒度）。

    Attributes:
        stage: 阶段名。
        status: ``succeeded`` / ``failed``。
        duration_s: 耗时（秒）。
        detail: 摘要（源数 / 命令 / 退出码等）。
        error: 失败原因；成功时为 ``None``。
    """

    stage: str
    status: str = "succeeded"
    duration_s: float = 0.0
    detail: str = ""
    error: str | None = None


def _declared(model: Any, name: str) -> Any:
    """取出 Pydantic 模型上「显式声明」的字段值（未声明返回 ``None``）。

    Args:
        model: Pydantic 模型实例；``None`` 表示整段缺失。
        name: 字段名。

    Returns:
        显式声明时返回字段值，否则返回 ``None``（调用方回退到下一优先级）。
    """
    if model is None or name not in getattr(model, "model_fields_set", set()):
        return None
    return getattr(model, name)


def resolve_scheduler_mode(
    cli_mode: str | None,
    *,
    settings: Settings,
    config: SourcesConfig | None = None,
) -> SchedulerMode:
    """解析调度模式，优先级：**CLI > 环境变量（显式设置）> ``sources.yaml`` > 内置默认**。

    Args:
        cli_mode: 命令行 ``--mode`` 取值；``None`` 表示未指定。
        settings: 全局配置（``scheduler_mode`` 字段）。
        config: 源配置（``scheduler.mode``）。

    Returns:
        ``"pipeline"`` 或 ``"per_source"``。

    Note:
        某一路取值无法识别时记 ``warning`` 并继续回退（环境变量被误设不应让调度器起不来）。
    """
    candidates: list[tuple[str, str]] = []
    if cli_mode:
        candidates.append(("--mode", cli_mode))
    if "scheduler_mode" in getattr(settings, "model_fields_set", set()):
        candidates.append(("环境变量/Settings", settings.scheduler_mode))
    yaml_mode = config.scheduler.mode if config is not None and config.scheduler is not None else None
    if yaml_mode:
        candidates.append(("sources.yaml", yaml_mode))
    for origin, value in candidates:
        try:
            return normalize_scheduler_mode(value)
        except ValueError as exc:
            logger.warning(f"忽略无法识别的调度模式（{origin}={value!r}）：{exc}")
    return normalize_scheduler_mode(None)


def resolve_pipeline_config(settings: Settings, config: SourcesConfig | None = None) -> PipelineConfig:
    """解析分层 pipeline 参数（``sources.yaml`` 显式声明 > ``Settings`` > 内置默认）。

    Args:
        settings: 全局配置（提供 env / ``.env`` 覆盖与内置默认值）。
        config: 源配置；``None`` 时视为未声明 ``scheduler`` 段。

    Returns:
        :class:`PipelineConfig`。
    """
    pipeline = config.scheduler.pipeline if config is not None and config.scheduler is not None else None
    enrich = pipeline.enrich if pipeline is not None else None
    only_high_risk = _declared(enrich, "only_high_risk")
    return PipelineConfig(
        collect_interval_hours=_declared(pipeline, "collect_interval_hours")
        or settings.pipeline_collect_interval_hours,
        enrich_interval_hours=_declared(pipeline, "enrich_interval_hours") or settings.pipeline_enrich_interval_hours,
        graph_interval_hours=_declared(pipeline, "graph_interval_hours") or settings.pipeline_graph_interval_hours,
        vector_interval_hours=_declared(pipeline, "vector_interval_hours") or settings.pipeline_vector_interval_hours,
        enrich_batch_size=_declared(enrich, "batch_size") or settings.pipeline_enrich_batch_size,
        enrich_only_high_risk=(
            bool(only_high_risk) if only_high_risk is not None else settings.pipeline_enrich_only_high_risk
        ),
    )


def pipeline_stage_argv(stage: str, config: PipelineConfig) -> list[str]:
    """返回子进程阶段的 ``python -m ...`` 参数列表（纯函数）。

    Args:
        stage: 阶段名（``enrich`` / ``graph`` / ``vector``）。
        config: pipeline 参数。

    Returns:
        参数列表（不含解释器本身）。

    Raises:
        ValueError: 阶段不是子进程阶段（``collect`` 在进程内执行）。
    """
    if stage == "enrich":
        argv = ["-m", "scripts.run_enrich", "--limit", str(config.enrich_batch_size), "--only-missing"]
        if config.enrich_only_high_risk:
            argv.append("--only-high-risk")
        return argv
    if stage == "graph":
        return ["-m", "scripts.load_graph", "--all"]
    if stage == "vector":
        return ["-m", "scripts.index_vectors", "--all"]
    raise ValueError(f"阶段 {stage!r} 不是子进程阶段（collect 在进程内执行）")


def pipeline_stage_command(stage: str, config: PipelineConfig) -> str:
    """返回某阶段的可复现命令文本（纯函数，供 ``--list`` 与日志展示）。

    Args:
        stage: 阶段名（四层之一）。
        config: pipeline 参数。

    Returns:
        形如 ``python -m scripts.load_graph --all`` 的命令文本。
    """
    if stage == "collect":
        return "内置 collect_source(--source all) + normalize"
    return "python " + " ".join(pipeline_stage_argv(stage, config))


def make_pipeline_specs(
    settings: Settings,
    config: SourcesConfig | None = None,
    *,
    values: PipelineConfig | None = None,
    stages: Sequence[str] | None = None,
) -> list[PipelineJobSpec]:
    """构建分层 pipeline 的四层调度规格（纯函数，便于单测）。

    Args:
        settings: 全局配置。
        config: 源配置（含 ``scheduler:`` 段）。
        values: 已解析的 pipeline 参数；``None`` 时按 ``settings`` + ``config`` 解析。
        stages: 参与调度的阶段；``None`` 表示四层全开（``--no-<stage>`` 时收窄）。

    Returns:
        :class:`PipelineJobSpec` 列表（顺序固定为 采集 → 富化 → 图谱 → 向量）。
    """
    resolved = values or resolve_pipeline_config(settings, config)
    enabled = set(stages) if stages is not None else set(PIPELINE_STAGES)
    return [
        PipelineJobSpec(
            stage=stage,
            interval_hours=resolved.interval_hours(stage),
            initial_offset_minutes=PIPELINE_STAGE_OFFSETS_MINUTES.get(stage, 0),
            command=pipeline_stage_command(stage, resolved),
            enabled=stage in enabled,
        )
        for stage in PIPELINE_STAGES
    ]


def _tail_lines(text: str, *, limit: int = PIPELINE_OUTPUT_TAIL_LINES, max_chars: int = 240) -> str:
    """取输出的最后若干非空行并做「控制台安全」处理（纯函数，日志留痕用）。

    Args:
        text: 原始输出。
        limit: 保留行数上限。
        max_chars: 结果字符数上限。

    Returns:
        以 `` / `` 连接的单行摘要；无输出时为空串。
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return _console_safe_text(" / ".join(lines[-limit:]) if lines else "", max_chars=max_chars)


def _console_safe_text(text: str, *, encoding: str | None = None, max_chars: int = 240) -> str:
    """把文本裁剪为「可在当前控制台编码下安全打印」的形式（纯函数）。

    Windows 控制台默认 GBK：子进程输出若含 GBK 无法编码的字符（如 ``U+FFFD``、
    部分 Unicode 装饰符），直接 ``print`` / 写日志会抛 ``UnicodeEncodeError`` 并中断汇总输出。
    这里统一做三步：不可打印字符 → 空格、``U+FFFD`` → ``?``、按目标编码做一次可编码性兜底。

    Args:
        text: 原始文本。
        encoding: 目标编码；``None`` 时取 ``sys.stdout.encoding``（再缺省 ``utf-8``）。
        max_chars: 结果字符数上限（超出截断并加省略号）。

    Returns:
        可安全打印的文本。
    """
    target = encoding or sys.stdout.encoding or "utf-8"
    cleaned = "".join(ch if (ch.isprintable() or ch == "\t") else " " for ch in text).replace("\ufffd", "?")
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 1] + "…"
    try:
        cleaned.encode(target)
    except (UnicodeEncodeError, LookupError):
        cleaned = cleaned.encode(target, errors="replace").decode(target, errors="replace")
    return cleaned


async def run_cli_module(
    argv: Sequence[str],
    *,
    timeout: float = PIPELINE_STAGE_TIMEOUT_S,
    cwd: Path | None = None,
    registry: set[Any] | None = None,
) -> tuple[int, str]:
    """以独立子进程执行 ``python -m ...``（pipeline 子进程阶段的默认执行器）。

    子进程显式注入 ``PYTHONIOENCODING=utf-8``，保证管道输出按 UTF-8 编解码（Windows 下
    子进程默认用 locale 编码写管道，父进程按 UTF-8 解码会得到乱码）。

    Args:
        argv: ``python`` 之后的参数，形如 ``["-m", "scripts.run_enrich", "--limit", "50"]``。
        timeout: 超时秒数；超时按「退出码 124 + 提示」返回，不抛异常。
        cwd: 子进程工作目录；``None`` 时使用仓库根目录（保证 ``scripts.*`` 可解析）。
        registry: 子进程登记表；非 ``None`` 时在启动 / 结束时增删，供停机回收残留子进程。

    Returns:
        ``(退出码, 合并后的 stdout+stderr 文本)``；超时返回 ``(124, 提示文本)``。
    """
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        *argv,
        cwd=str(cwd or REPO_ROOT),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    if registry is not None:
        registry.add(process)
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        return 124, f"[超时] {timeout:.0f}s 未完成：python {' '.join(argv)}"
    finally:
        if registry is not None:
            registry.discard(process)
    return int(process.returncode or 0), (stdout or b"").decode("utf-8", errors="replace")


class CollectScheduler:
    """多源周期采集 / 分层 pipeline 调度器。

    Attributes:
        stats_history: 已完成采集 job 的统计（按完成顺序，供测试与运维页查询）。
        pipeline_history: 已完成 pipeline 阶段（层粒度）的统计（按完成顺序）。
        retry_history: 已完成「失败重试队列」轮的摘要（每日 02:00 一轮）。
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
        on_stage: Callable[[PipelineStageStats], None] | None = None,
        scheduler_mode: str | None = None,
        pipeline_stages: Sequence[str] | None = None,
        retry_enabled: bool = True,
        retry_batch_size: int = RETRY_BATCH_SIZE,
        retry_max_attempts: int = RETRY_MAX_ATTEMPTS,
        command_runner: Callable[[Sequence[str]], Awaitable[tuple[int, str]]] | None = None,
        scheduler: Any | None = None,
    ) -> None:
        """初始化调度器（不启动）。

        Args:
            settings: 全局配置；``None`` 时使用 :func:`aisec_intel.config.get_settings`。
            config: 源配置；``None`` 时读取 ``Settings.sources_config_path``。
            mode: 采集模式 ``incremental`` / ``full``（对两种调度布局都生效）。
            limit: 每源每次采集的处理条数上限（0 = 不限）。
            normalize: 是否同步归一化并写入 ``unified_vuln``（pipeline 采集层恒为 ``True``）。
            sources: 参与调度的源；``None`` 时取「YAML 启用 且 已注册」的源。
            run_immediately: ``True`` 时启动即触发一轮（pipeline 下四层同时触发，覆盖错开）。
            shutdown_timeout: 优雅停机等待上限（秒）。
            on_stats: 每次采集 job 完成后的回调（前端运维页 / 测试注入）。
            on_stage: 每次 pipeline 阶段完成后的回调。
            scheduler_mode: ``pipeline`` / ``per_source``；``None`` 时按 CLI > env > YAML 解析。
            pipeline_stages: 参与调度的 pipeline 阶段；``None`` 表示四层全开。
            retry_enabled: 是否注册每日「失败重试队列」job（``0 2 * * *``）。
            retry_batch_size: 单轮重试最多处理条数。
            retry_max_attempts: 单条富化结论的最大自动重试次数。
            command_runner: 子进程阶段执行器（测试注入）；``None`` 时用内置执行器
                :meth:`_spawn_cli`（会登记子进程，停机时统一回收）。
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
        self._on_stage = on_stage
        self._scheduler_mode = resolve_scheduler_mode(scheduler_mode, settings=self._settings, config=self._config)
        self._pipeline_stages = list(pipeline_stages) if pipeline_stages is not None else list(PIPELINE_STAGES)
        self._pipeline_config = resolve_pipeline_config(self._settings, self._config)
        self._retry_enabled = retry_enabled
        self._retry_batch_size = retry_batch_size
        self._retry_max_attempts = retry_max_attempts
        self._command_runner = command_runner
        self._child_processes: set[Any] = set()
        self._scheduler = scheduler
        self._specs: list[ScheduleSpec] = []
        self._pipeline_specs: list[PipelineJobSpec] = []
        self._inflight: set[str] = set()
        self._stop_event = asyncio.Event()
        self._loop_signals: list[int] = []
        self._os_signals: list[int] = []
        self.stats_history: list[CollectStats] = []
        self.pipeline_history: list[PipelineStageStats] = []
        self.retry_history: list[dict[str, Any]] = []

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
        """当前 per-source 调度规格（未构建时为空列表）。"""
        return self._specs

    @property
    def scheduler_mode(self) -> SchedulerMode:
        """当前调度模式（``pipeline`` / ``per_source``）。"""
        return self._scheduler_mode

    @property
    def collect_mode(self) -> str:
        """采集语义（``incremental`` / ``full``）。"""
        return self._mode

    @property
    def is_pipeline(self) -> bool:
        """当前是否为分层 pipeline 模式。"""
        return self._scheduler_mode == "pipeline"

    @property
    def retry_enabled(self) -> bool:
        """是否注册每日「失败重试队列」job（``maintenance:retry-failed``）。"""
        return self._retry_enabled

    @property
    def retry_batch_size(self) -> int:
        """失败重试队列单轮处理条数上限。"""
        return self._retry_batch_size

    @property
    def retry_max_attempts(self) -> int:
        """失败重试队列单条最大重试次数。"""
        return self._retry_max_attempts

    @property
    def pipeline_specs(self) -> list[PipelineJobSpec]:
        """当前分层 pipeline 调度规格（未构建时为空列表）。"""
        return self._pipeline_specs

    @property
    def pipeline_config(self) -> PipelineConfig:
        """当前分层 pipeline 参数（间隔 / 富化批大小等）。"""
        return self._pipeline_config

    def build_pipeline_specs(self) -> list[PipelineJobSpec]:
        """构建四层流水线的调度规格（采集 → 富化 → 图谱 → 向量）。

        Returns:
            :class:`PipelineJobSpec` 列表（``enabled=False`` 表示被 ``--no-<stage>`` 关闭）。
        """
        self._pipeline_specs = make_pipeline_specs(
            self._settings,
            self._config,
            values=self._pipeline_config,
            stages=self._pipeline_stages,
        )
        return self._pipeline_specs

    def build_plan(self) -> None:
        """按当前调度模式装配 job 规格（pipeline 走四层，否则走每源一个 job）。"""
        if self.is_pipeline:
            self.build_pipeline_specs()
        else:
            self.build_specs()

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
        """注册 interval job（幂等：同 id 会被 APScheduler 替换）。

        - ``pipeline`` 模式：注册 4 个分层 job（``pipeline:<stage>``）；
        - ``per_source`` 模式：每个启用源一个 job（``collect:<source>``）；
        - 两种模式**都会**额外注册 1 个每日「失败重试队列」job
          （``maintenance:retry-failed``，cron ``0 2 * * *``，Day23 任务 2）。

        Returns:
            注册的 job 数量（不含被关闭的阶段 / 停用的源；含失败重试 job）。
        """
        if self.is_pipeline:
            pipeline_specs = self._pipeline_specs or self.build_pipeline_specs()
            return self._add_pipeline_jobs(pipeline_specs) + self._add_retry_job()
        source_specs = self._specs or self.build_specs()
        return self._add_source_jobs(source_specs) + self._add_retry_job()

    def _add_source_jobs(self, specs: Sequence[ScheduleSpec]) -> int:
        """per-source 模式：每个启用源一个 interval job。"""
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
            f"调度装配完成（per_source）：{len(specs)} 个源，collect_mode={self._mode}，"
            f"间隔={{{', '.join(f'{spec.source}:{spec.interval_minutes}m' for spec in specs)}}}"
        )
        return len(specs)

    def _add_pipeline_jobs(self, specs: Sequence[PipelineJobSpec]) -> int:
        """pipeline 模式：采集 / 富化 / 图谱 / 向量四层各一个 job。"""
        target = self.scheduler
        registered = 0
        for spec in specs:
            if not spec.enabled:
                continue
            target.add_job(
                self._run_pipeline_job,
                trigger="interval",
                hours=spec.interval_hours,
                args=[spec.stage],
                id=spec.job_id,
                name=f"pipeline {spec.stage}（每 {spec.interval_hours} 小时）",
                max_instances=1,
                coalesce=True,
                misfire_grace_time=MISFIRE_GRACE_S,
                next_run_time=self._first_run_time(spec),
            )
            registered += 1
        logger.info(
            "调度装配完成（pipeline）："
            + ", ".join(f"{spec.stage}:{spec.interval_hours}h" for spec in specs if spec.enabled)
            + f"；collect_mode={self._mode}"
        )
        return registered

    def _first_run_time(self, spec: PipelineJobSpec) -> Any:
        """pipeline 首次触发时刻。

        ``run_immediately``（``--run-now`` / ``--once``）时四层立即各触发一轮（覆盖错开）；
        常规启动时按 ``spec.initial_offset_minutes``（0 / 10 / 20 / 30 分钟）错开。

        Args:
            spec: pipeline 调度规格。

        Returns:
            APScheduler 可接受的 ``datetime``（UTC）。
        """
        now = _now_for_apscheduler()
        if self._run_immediately:
            return now
        return now + timedelta(minutes=spec.initial_offset_minutes)

    def _add_retry_job(self) -> int:
        """注册每日「失败重试队列」job（cron ``0 2 * * *``，Day23 任务 2）。

        与分层 pipeline 无关（不随 ``--no-<stage>`` 关闭），在两种调度布局下都注册：
        每日凌晨 2 点扫描 ``review_status='needs_human'`` 的富化结论并自动重试，
        最多 3 次，用尽则标记 ``permanently_failed``（详见
        :func:`aisec_intel.services.enrich_service.retry_failed`）。

        Returns:
            ``1``（已注册）；``0``（被 ``retry_enabled=False`` 关闭）。
        """
        if not self._retry_enabled:
            logger.info("失败重试队列 job 未注册（retry_enabled=False）")
            return 0
        self.scheduler.add_job(
            self._run_retry_job,
            trigger="cron",
            hour=RETRY_CRON_HOUR,
            minute=RETRY_CRON_MINUTE,
            id=RETRY_JOB_ID,
            name=f"失败重试队列（每天 {RETRY_CRON_HOUR:02d}:{RETRY_CRON_MINUTE:02d}）",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=MISFIRE_GRACE_S,
        )
        logger.info(
            f"调度装配完成（maintenance）：{RETRY_JOB_ID} 每天 "
            f"{RETRY_CRON_HOUR:02d}:{RETRY_CRON_MINUTE:02d}"
            f"（batch={self._retry_batch_size}，max_attempts={self._retry_max_attempts}）"
        )
        return 1

    def scheduled_jobs(self) -> list[dict[str, Any]]:
        """列出已注册 job 的摘要（供 CLI 打印）。

        Returns:
            per-source：``[{"id", "source", "interval_minutes", "next_run_time"}, ...]``；
            pipeline：``[{"id", "stage", "interval_minutes", "next_run_time"}, ...]``。
        """
        if self.is_pipeline:
            return [
                {
                    "id": spec.job_id,
                    "stage": spec.stage,
                    "interval_minutes": spec.interval_minutes,
                    "next_run_time": getattr(self._get_job(spec.job_id), "next_run_time", None),
                }
                for spec in self._pipeline_specs
            ] + [self._retry_job_summary()]
        summary: list[dict[str, Any]] = []
        for spec in self._specs:
            job_id = f"{JOB_ID_PREFIX}:{spec.source}"
            summary.append(
                {
                    "id": job_id,
                    "source": spec.source,
                    "interval_minutes": spec.interval_minutes,
                    "next_run_time": getattr(self._get_job(job_id), "next_run_time", None),
                }
            )
        summary.append(self._retry_job_summary())
        return summary

    def _retry_job_summary(self) -> dict[str, Any]:
        """返回每日失败重试 job 的摘要行（供 ``scheduled_jobs`` 与 ``--list`` 展示）。

        Returns:
            含 ``id`` / ``stage``（固定 ``retry``）/ ``cron`` / ``interval_minutes`` / ``next_run_time``。
        """
        return {
            "id": RETRY_JOB_ID,
            "stage": "retry",
            "cron": f"{RETRY_CRON_MINUTE} {RETRY_CRON_HOUR} * * *",
            "interval_minutes": 24 * 60,
            "next_run_time": getattr(self._get_job(RETRY_JOB_ID), "next_run_time", None),
            "enabled": self._retry_enabled,
        }

    def _get_job(self, job_id: str) -> Any:
        """安全取 APScheduler job（假调度器 / 未启动时返回 ``None``）。"""
        try:
            return self.scheduler.get_job(job_id)
        except Exception:  # noqa: BLE001 - 假调度器 / 未启动时忽略
            return None

    # ---------- job 执行 ----------

    async def run_source(self, source: str, *, normalize: bool | None = None) -> CollectStats:
        """执行一次单源采集（job 的实际业务逻辑）。

        Args:
            source: 源标识。
            normalize: 是否同步归一化；``None`` 时取构造参数 ``normalize``
                （pipeline 采集层固定传 ``True``）。

        Returns:
            :class:`CollectStats` 统计结果。
        """
        effective_normalize = self._normalize if normalize is None else normalize
        since = await resolve_since(source, mode=self._mode, settings=self._settings)
        stats = await collect_source(
            source,
            since=since,
            settings=self._settings,
            limit=self._limit,
            normalize=effective_normalize,
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

    # ---------- pipeline 阶段执行 ----------

    async def run_pipeline_stage(self, stage: str) -> PipelineStageStats:
        """执行单个 pipeline 阶段（内部吞掉异常，返回统计而非抛出）。

        Args:
            stage: 阶段名（``collect`` / ``enrich`` / ``graph`` / ``vector``）。

        Returns:
            :class:`PipelineStageStats`；``status`` 为 ``succeeded`` / ``failed``。
        """
        started = time.perf_counter()
        status = "succeeded"
        detail = ""
        error: str | None = None
        try:
            if stage == "collect":
                detail, failed_count = await self._pipeline_collect()
                if failed_count:
                    status = "failed"
                    error = f"{failed_count} 个源采集失败（详见 stats_history）"
            else:
                detail, code = await self._run_pipeline_command(stage)
                if code != 0:
                    status = "failed"
                    error = f"子进程退出码 {code}"
        except Exception as exc:  # noqa: BLE001 - 单层失败不得中断其他层
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
        stats = PipelineStageStats(
            stage=stage,
            status=status,
            duration_s=time.perf_counter() - started,
            detail=detail,
            error=error,
        )
        self.pipeline_history.append(stats)
        flag = "OK  " if status == "succeeded" else "FAIL"
        logger.info(f"[{flag} pipeline:{stage}] {detail} 耗时={stats.duration_s:.2f}s")
        if error:
            logger.warning(f"[pipeline:{stage}] 失败：{error}")
        if self._on_stage is not None:
            self._on_stage(stats)
        return stats

    async def _pipeline_collect(self) -> tuple[str, int]:
        """采集层：对全部启用源跑一轮 ``collect_source`` 并同步归一化。

        Returns:
            ``(摘要文本, 失败源数量)``。
        """
        sources = list(self._requested)
        ok = 0
        failed: list[str] = []
        for source in sources:
            try:
                stats = await self.run_source(source, normalize=True)
            except Exception as exc:  # noqa: BLE001 - 单源失败不阻断其他源
                logger.error(f"[{source}] pipeline 采集异常：{type(exc).__name__}: {exc}")
                failed.append(source)
                continue
            if stats.status == "succeeded":
                ok += 1
            else:
                failed.append(source)
        detail = f"源={len(sources)} 成功={ok} 失败={len(failed)}"
        if failed:
            detail += f"（{','.join(failed)}）"
        return detail, len(failed)

    async def _run_pipeline_command(self, stage: str) -> tuple[str, int]:
        """子进程执行富化 / 图谱 / 向量层。

        Args:
            stage: 阶段名（非 ``collect``）。

        Returns:
            ``(摘要文本, 退出码)``。
        """
        argv = pipeline_stage_argv(stage, self._pipeline_config)
        command = "python " + " ".join(argv)
        logger.info(f"[pipeline:{stage}] 执行：{command}")
        runner = self._command_runner or self._spawn_cli
        code, output = await runner(argv)
        tail = _tail_lines(output)
        detail = f"cmd={command} | 退出码={code}" + (f" | {tail}" if tail else "")
        return detail, code

    async def _spawn_cli(self, argv: Sequence[str]) -> tuple[int, str]:
        """默认子进程执行器：执行并登记子进程，便于停机时统一回收。

        Args:
            argv: ``python`` 之后的参数。

        Returns:
            ``(退出码, 输出文本)``。
        """
        return await run_cli_module(argv, timeout=PIPELINE_STAGE_TIMEOUT_S, registry=self._child_processes)

    async def terminate_pipeline_children(self) -> int:
        """强制回收仍在运行的 pipeline 子进程（停机兜底）。

        父进程退出不会自动带走 ``python -m scripts.*`` 子进程：若富化层正在调 LLM，它们会变成
        孤儿继续消耗额度 / 写库（Day19 实测到 4 个残留 ``run_enrich``）。故在优雅停机的最后
        一步统一 kill。

        Returns:
            实际被终止的子进程数。
        """
        killed = 0
        for process in list(self._child_processes):
            if getattr(process, "returncode", None) is None:
                try:
                    process.kill()
                    await process.wait()
                    killed += 1
                except ProcessLookupError:  # pragma: no cover - 进程已自行退出
                    pass
            self._child_processes.discard(process)
        if killed:
            logger.warning(f"停机回收 pipeline 子进程：{killed} 个")
        return killed

    async def _run_pipeline_job(self, stage: str) -> PipelineStageStats | None:
        """pipeline job 包装器：保证任何异常都不会杀死调度器。

        Args:
            stage: 阶段名。

        Returns:
            正常完成时返回阶段统计；失败 / 重入跳过时返回 ``None``。
        """
        key = f"{PIPELINE_JOB_PREFIX}:{stage}"
        if key in self._inflight:  # max_instances=1 之外的二次保险
            logger.warning(f"{key} 上一轮仍在执行，跳过本次触发")
            return None
        self._inflight.add(key)
        try:
            return await self.run_pipeline_stage(stage)
        except Exception as exc:  # noqa: BLE001 - 双保险
            logger.error(f"[{key}] job 异常：{type(exc).__name__}: {exc}")
            return None
        finally:
            self._inflight.discard(key)

    # ---------- 生命周期 ----------

    async def _run_retry_job(self) -> dict[str, Any] | None:
        """job 包装器：跑一轮「失败重试队列」（异常隔离，绝不终止调度器）。

        Returns:
            执行摘要字典（供 ``retry_history`` / 汇总打印）；重入或异常时返回 ``None``。
        """
        key = RETRY_JOB_ID
        if key in self._inflight:
            logger.warning(f"[{key}] 上一轮仍在执行，本轮跳过")
            return None
        self._inflight.add(key)
        started = time.perf_counter()
        try:
            from aisec_intel.services.enrich_service import retry_failed

            report = await retry_failed(
                self._settings,
                limit=self._retry_batch_size,
                max_attempts=self._retry_max_attempts,
            )
            summary: dict[str, Any] = {
                "job_id": key,
                "status": "succeeded",
                "scanned": report.scanned,
                "recovered": report.recovered,
                "retry_failed": report.retry_failed,
                "permanently_failed": report.permanently_failed,
                "duration_s": round(time.perf_counter() - started, 3),
                "detail": report.summary(),
            }
            self.retry_history.append(summary)
            logger.info(f"[{key}] OK {report.summary()}")
            return summary
        except Exception as exc:  # noqa: BLE001 - 任何异常都不终止调度器
            logger.error(f"[{key}] job 异常：{type(exc).__name__}: {exc}")
            self.retry_history.append(
                {
                    "job_id": key,
                    "status": "failed",
                    "duration_s": round(time.perf_counter() - started, 3),
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            return None
        finally:
            self._inflight.discard(key)

    async def run_retry_job_now(self) -> dict[str, Any] | None:
        """立即执行一轮「失败重试队列」（等价把每日 02:00 的 job 提前触发，演练 / 验收用）。

        Returns:
            执行摘要字典；异常时返回 ``None``（异常已在 :meth:`_run_retry_job` 内隔离）。
        """
        return await self._run_retry_job()

    def start(self) -> int:
        """装配 job 并启动调度器（不阻塞）。

        Returns:
            注册的 job 数量。
        """
        count = self.add_jobs()
        self.scheduler.start()
        logger.info(
            f"Scheduler started（调度器已启动）：scheduler_mode={self._scheduler_mode}，"
            f"collect_mode={self._mode}，{count} 个 job"
            f"（含每日 {RETRY_CRON_HOUR:02d}:{RETRY_CRON_MINUTE:02d} 失败重试队列）"
        )
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
        """优雅停机：停止调度 → 等待执行中的 job 收尾 → 回收残留子进程 → 恢复信号处理。

        Args:
            timeout: 等待执行中 job 的上限（秒）；``None`` 时取 ``shutdown_timeout``。

        Returns:
            在时限内全部收尾返回 ``True``，否则 ``False``（超时不再等待）。
        """
        self._stop_event.set()
        if self._scheduler is not None and getattr(self._scheduler, "running", False):
            self._scheduler.shutdown(wait=False)
        drained = await self.wait_until_idle(timeout=timeout)
        reaped = await self.terminate_pipeline_children()
        self._restore_signals()
        tail = f"，回收子进程 {reaped} 个" if reaped else ""
        logger.info(f"调度器已停机（进行中 job 收尾：{'完成' if drained else '超时'}{tail}）")
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


