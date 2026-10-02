"""组件健康检查（Day17 任务 3.4：``/healthz`` 升级 + ``/readyz`` 就绪探针）。

四个组件（与 :data:`~aisec_intel.services.metrics_service.M_COMPONENT_UP` 标签一致）：

=========  ==========================================================
``pg``     PostgreSQL：``SELECT 1``（**硬依赖**，失败即未就绪）
``neo4j``  Neo4j：``ping()``；未启用 / 不可用时降级为 PG JSON（``degraded``）
``chroma`` Chroma：客户端 ``heartbeat``；内存后端记为 ``degraded``（符合设计）
``llm``    LLM：仅做**配置检查**（不发起付费调用），未配置 Key 记为 ``degraded``
=========  ==========================================================

结论口径（:func:`overall_status`）：
    - ``error``：硬依赖（PostgreSQL）不可用；
    - ``degraded``：核心可用但存在降级组件；
    - ``ok``：全部组件可用。

Note:
    探针**必须快速且不抛异常**：单项超时（默认 3 秒）只影响该项结论。
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import text

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.services.metrics_service import M_COMPONENT_UP, METRICS
from aisec_intel.storage.database import get_engine, session_scope

logger = get_logger(__name__)

ComponentStatus = Literal["up", "down", "degraded", "unknown"]
"""组件状态。"""
OverallStatus = Literal["ok", "degraded", "error"]
"""聚合状态（``/healthz`` 的 ``status`` 字段）。"""

DEFAULT_PROBE_TIMEOUT_S: float = 3.0
"""单项探针超时（秒）。"""

HARD_DEPENDENCIES: frozenset[str] = frozenset({"pg"})
"""硬依赖组件（不可用时整体判 ``error``）。"""


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    """单个组件的健康状态。

    Attributes:
        name: 组件标识（``pg`` / ``neo4j`` / ``chroma`` / ``llm``）。
        status: 组件状态。
        detail: 人类可读说明（含降级原因）。
        latency_ms: 探针耗时（毫秒）。
    """

    name: str
    status: ComponentStatus
    detail: str
    latency_ms: int = 0

    @property
    def up(self) -> bool:
        """组件是否可用（``degraded`` 视为可用但不健康）。"""
        return self.status in {"up", "degraded"}

    def as_dict(self) -> dict[str, object]:
        """转换为可序列化字典。

        Returns:
            含 ``status`` / ``detail`` / ``latency_ms`` 的字典。
        """
        return {"status": self.status, "detail": self.detail, "latency_ms": self.latency_ms}


async def _timed(
    name: str,
    probe: Callable[[], Awaitable[object]],
    *,
    timeout_s: float,
) -> tuple[object | None, str, int]:
    """执行一个异步探针并计时（异常 / 超时都转成失败原因）。

    Args:
        name: 组件名（日志用）。
        probe: 无参协程工厂。
        timeout_s: 超时（秒）。

    Returns:
        ``(返回值或 None, 失败原因或空串, 耗时毫秒)``。
    """
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(probe(), timeout=timeout_s)
    except TimeoutError:
        return None, f"探针超时（>{timeout_s:g}s）", int((time.perf_counter() - started) * 1000)
    except Exception as exc:  # noqa: BLE001 - 探针需吞掉所有异常
        logger.debug(f"组件探针失败 {name}：{type(exc).__name__}: {exc}")
        return None, f"{type(exc).__name__}: {exc}", int((time.perf_counter() - started) * 1000)
    return result, "", int((time.perf_counter() - started) * 1000)


async def check_postgres(settings: Settings, *, timeout_s: float = DEFAULT_PROBE_TIMEOUT_S) -> ComponentHealth:
    """探针 PostgreSQL（``SELECT 1``）。

    Args:
        settings: 全局配置。
        timeout_s: 超时（秒）。

    Returns:
        组件健康状态。
    """

    async def _probe() -> None:
        async with session_scope(get_engine(settings)) as session:
            await session.execute(text("SELECT 1"))

    _, error, latency = await _timed("pg", _probe, timeout_s=timeout_s)
    if error:
        return ComponentHealth("pg", "down", f"数据库不可用：{error}", latency)
    return ComponentHealth("pg", "up", f"{settings.effective_storage_backend} 连接正常（SELECT 1）", latency)


async def check_neo4j(settings: Settings, *, timeout_s: float = DEFAULT_PROBE_TIMEOUT_S) -> ComponentHealth:
    """探针 Neo4j（``Neo4jClient.ping()``）。

    Args:
        settings: 全局配置。
        timeout_s: 超时（秒）。

    Returns:
        组件健康状态；未启用时记为 ``degraded``（图谱按设计降级为 PG JSON）。
    """
    if not settings.neo4j_enabled:
        return ComponentHealth("neo4j", "degraded", "NEO4J_ENABLED=false，图谱按设计降级为 PG JSON")

    from aisec_intel.storage.neo4j_client import Neo4jClient

    client = Neo4jClient(settings)
    try:
        result, error, latency = await _timed("neo4j", client.ping, timeout_s=timeout_s)
    finally:
        await client.aclose()
    if error or not result:
        return ComponentHealth(
            "neo4j", "down", f"Neo4j 不可用（{error or 'ping 返回 False'}），已降级为 PG JSON", latency
        )
    return ComponentHealth("neo4j", "up", f"bolt 连接正常（{settings.neo4j_uri}）", latency)


async def check_chroma(settings: Settings, *, timeout_s: float = DEFAULT_PROBE_TIMEOUT_S) -> ComponentHealth:
    """探针 Chroma（客户端 ``heartbeat``）。

    Args:
        settings: 全局配置。
        timeout_s: 超时（秒）。

    Returns:
        组件健康状态；内存后端记为 ``degraded``（降级模式下的预期行为）。
    """
    if settings.effective_vector_backend == "chroma_memory":
        return ComponentHealth("chroma", "degraded", "内存向量后端（DEGRADED_MODE），重启即清空")

    def _probe() -> str:
        import chromadb

        client = chromadb.PersistentClient(path=settings.chroma_path)
        return str(client.heartbeat())

    async def _async_probe() -> str:
        return await asyncio.to_thread(_probe)

    result, error, latency = await _timed("chroma", _async_probe, timeout_s=timeout_s)
    if error:
        return ComponentHealth("chroma", "down", f"向量库不可用：{error}（检索退化为全文）", latency)
    return ComponentHealth("chroma", "up", f"heartbeat={result}（path={settings.chroma_path}）", latency)


async def check_llm(settings: Settings, *, timeout_s: float = DEFAULT_PROBE_TIMEOUT_S) -> ComponentHealth:
    """LLM 配置检查（**不发起真实调用**，避免探针扣费）。

    Args:
        settings: 全局配置。
        timeout_s: 预留参数（配置检查本身无 IO）。

    Returns:
        组件健康状态；未配置 Key 时记为 ``degraded``（富化走确定性路径）。
    """
    del timeout_s  # 配置检查无 IO，保留参数以统一探针签名
    if settings.llm_provider == "ollama":
        return ComponentHealth("llm", "up", "provider=ollama（本地离线模型，无需 Key）", 0)
    if not settings.has_llm_api_key or settings.degraded_mode:
        reason = "DEGRADED_MODE=true" if settings.degraded_mode else "未配置 LLM_API_KEY"
        return ComponentHealth("llm", "degraded", f"{reason}，富化/问答走确定性降级路径", 0)
    return ComponentHealth(
        "llm", "up", f"provider={settings.llm_provider} model={settings.effective_llm_model_fast}", 0
    )


async def check_all(
    settings: Settings | None = None,
    *,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> list[ComponentHealth]:
    """并发探针全部组件（互不阻塞）。

    Args:
        settings: 全局配置；``None`` 时取进程单例。
        timeout_s: 单项超时（秒）。

    Returns:
        组件健康状态列表（顺序固定：pg → neo4j → chroma → llm）。
    """
    resolved = settings or get_settings()
    components = list(
        await asyncio.gather(
            check_postgres(resolved, timeout_s=timeout_s),
            check_neo4j(resolved, timeout_s=timeout_s),
            check_chroma(resolved, timeout_s=timeout_s),
            check_llm(resolved, timeout_s=timeout_s),
        )
    )
    record_component_gauges(components)
    return components


def overall_status(components: list[ComponentHealth] | tuple[ComponentHealth, ...]) -> OverallStatus:
    """聚合组件状态（纯函数）。

    Args:
        components: 组件健康状态序列。

    Returns:
        ``error``（硬依赖不可用） / ``degraded``（存在降级组件） / ``ok``。
    """
    if any(component.name in HARD_DEPENDENCIES and not component.up for component in components):
        return "error"
    if any(component.status != "up" for component in components):
        return "degraded"
    return "ok"


def record_component_gauges(components: list[ComponentHealth]) -> None:
    """把组件状态写入 ``aisec_component_up`` 指标。

    Args:
        components: 组件健康状态序列。
    """
    for component in components:
        METRICS.set_gauge(M_COMPONENT_UP, 1.0 if component.up else 0.0, {"component": component.name})

