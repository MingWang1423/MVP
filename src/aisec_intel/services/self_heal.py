"""自愈：重试、降级与镜像切换（Day17 任务 4）。

三条自愈链路（自愈本身**只写日志与指标**，不改变业务结果语义）：

============================  ==========================================================
采集自愈                      ``retry_async`` 指数退避重试 3 次 → 仍失败切 fallback 镜像 URL
富化自愈                      ``retry_async`` + :mod:`aisec_intel.llm.fallback`（reasoner → chat → Ollama）
问答自愈                      检索通路失败 → 自动补 ``fulltext`` 兜底；Neo4j 不可用 → PG JSON
============================  ==========================================================

自愈事件统一写入 ``logs/selfheal.log``（JSON 单行，独立滚动 handler），并累加
``aisec_self_heal_total{component,action}`` 指标，便于运维按 ``trace_id`` 与组件排查。

设计取舍：
    1. 退避**不加随机抖动**（保证单测可断言精确的等待序列）；
    2. ``sleep`` 可注入，单测无需真实等待；
    3. 自愈旁路自身异常一律吞掉，绝不影响主链路。
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypeVar

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import attach_file_handler, get_logger, log_event
from aisec_intel.models.base import iso_z, utc_now
from aisec_intel.services.metrics_service import M_SELF_HEAL, METRICS

if TYPE_CHECKING:
    from aisec_intel.connectors.base import BaseConnector

logger = get_logger(__name__)

T = TypeVar("T")

SELF_HEAL_LOGGER_NAME: str = "aisec_intel.selfheal"
"""自愈专用 logger 名（挂 ``logs/selfheal.log`` 滚动 handler）。"""

DEFAULT_ATTEMPTS: int = 3
"""默认重试次数（含首次尝试）。"""

DEFAULT_BASE_DELAY_S: float = 0.5
"""指数退避基准间隔（秒）。"""

DEFAULT_MAX_DELAY_S: float = 8.0
"""单次退避上限（秒）。"""

COMPONENT_COLLECT: str = "collect"
"""自愈组件名：采集。"""
COMPONENT_ENRICH: str = "enrich"
"""自愈组件名：富化。"""
COMPONENT_QA: str = "qa"
"""自愈组件名：问答。"""
COMPONENT_LLM: str = "llm"
"""自愈组件名：LLM 调用。"""

ACTION_RETRY: str = "retry"
"""自愈动作：重试。"""
ACTION_RECOVERED: str = "recovered"
"""自愈动作：重试后恢复。"""
ACTION_EXHAUSTED: str = "exhausted"
"""自愈动作：重试耗尽。"""
ACTION_FALLBACK: str = "fallback"
"""自愈动作：切换到备用实现 / 镜像地址。"""
ACTION_DEGRADED: str = "degraded"
"""自愈动作：降级（确定性兜底路径）。"""

FALLBACK_URLS: dict[str, tuple[str, ...]] = {
    "kev": ("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",),
}
"""源 → 备用入口地址（主 URL 连续失败后按序切换；KEV 主站故障时用 GitHub 镜像）。"""

CONNECTOR_URL_ATTRS: tuple[str, ...] = ("catalog_url", "api_url", "feed_url", "endpoint_url")
"""采集器上「入口 URL」候选属性名（:func:`apply_fallback_url` 按序探测）。"""


@dataclass(frozen=True, slots=True)
class SelfHealEvent:
    """一次自愈事件（审计与运维检索的最小单元）。

    Attributes:
        component: 组件名（``collect`` / ``enrich`` / ``qa`` / ``llm``）。
        action: 动作（``retry`` / ``recovered`` / ``exhausted`` / ``fallback`` / ``degraded``）。
        reason: 触发原因（异常类型与消息）。
        label: 主体标识（源名 / CVE / 模型名 / 检索通路）。
        attempt: 第几次尝试（从 1 开始；非重试动作填 0）。
        details: 附加结构化上下文。
        occurred_at: 发生时间（UTC）。
    """

    component: str
    action: str
    reason: str
    label: str = ""
    attempt: int = 0
    details: Mapping[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=utc_now)

    def as_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典。

        Returns:
            含 ``kind`` / ``component`` / ``action`` / ``reason`` / ``label`` 等的字典。
        """
        return {
            "kind": "self_heal",
            "component": self.component,
            "action": self.action,
            "reason": self.reason,
            "label": self.label,
            "attempt": self.attempt,
            "details": dict(self.details),
            "occurred_at": iso_z(self.occurred_at),
        }



def configure_self_heal_log(settings: Settings | None = None) -> None:
    """给自愈 logger 挂滚动文件 handler（幂等）。

    Args:
        settings: 全局配置；``None`` 时用 :func:`~aisec_intel.config.get_settings`。
    """
    resolved = settings or get_settings()
    attach_file_handler(
        SELF_HEAL_LOGGER_NAME,
        resolved.self_heal_log_path,
        json_output=True,
        level=resolved.log_level,
        max_bytes=resolved.log_max_bytes,
        backup_count=resolved.log_backup_count,
    )


def log_self_heal(event: SelfHealEvent) -> None:
    """记录一次自愈事件（独立滚动文件 + 控制台 + 指标）。

    落盘为**单行 JSON**，结构：``{"ts","level","logger","trace_id","msg","event",
    "details":{"kind":"self_heal","component","action","reason","label","attempt",
    "occurred_at","context"}}``——即自愈字段全在 ``details`` 里，便于
    ``jq '.details.component'`` 之类检索。

    Args:
        event: 自愈事件。
    """
    name = f"{event.component}.{event.action}"
    title = f"[自愈] {name} {event.label or '-'}：{event.reason}"
    details: dict[str, Any] = {
        "kind": "self_heal",
        "component": event.component,
        "action": event.action,
        "reason": event.reason,
        "label": event.label,
        "attempt": event.attempt,
        "occurred_at": iso_z(event.occurred_at),
        "context": dict(event.details),
    }
    try:
        configure_self_heal_log()
        log_event(get_logger(SELF_HEAL_LOGGER_NAME), name, message=title, **details)
    except Exception as exc:  # noqa: BLE001 - 自愈日志失败不得影响主链路
        logger.warning(f"自愈日志写入失败：{type(exc).__name__}: {exc}")
    METRICS.inc(M_SELF_HEAL, {"component": event.component, "action": event.action})
    log_event(logger, name, message=title, **details)


def backoff_delays(
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    base_delay_s: float = DEFAULT_BASE_DELAY_S,
    max_delay_s: float = DEFAULT_MAX_DELAY_S,
) -> list[float]:
    """计算指数退避等待序列（纯函数，便于单测与文档）。

    Args:
        attempts: 总尝试次数（含首次）；``< 2`` 时返回空列表（无需等待）。
        base_delay_s: 基准间隔（秒）。
        max_delay_s: 单次上限（秒）。

    Returns:
        长度为 ``attempts - 1`` 的等待秒数列表，形如 ``[0.5, 1.0, 2.0]``。
    """
    if attempts <= 1:
        return []
    return [min(max_delay_s, base_delay_s * (2**index)) for index in range(attempts - 1)]



async def retry_async(
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    base_delay_s: float = DEFAULT_BASE_DELAY_S,
    max_delay_s: float = DEFAULT_MAX_DELAY_S,
    component: str = COMPONENT_COLLECT,
    label: str = "",
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """指数退避重试（Day17 任务 4.1）。

    Args:
        operation: 无参异步操作（每次重试都会重新调用）。
        attempts: 总尝试次数（含首次）。
        base_delay_s: 基准间隔（秒）。
        max_delay_s: 单次上限（秒）。
        component: 自愈组件名（写日志 / 指标）。
        label: 主体标识（源名 / CVE / 模型名）。
        sleep: 休眠函数（单测注入，避免真实等待）。

    Returns:
        首次成功的返回值。

    Raises:
        Exception: 全部尝试均失败时抛出**最后一次**异常（原样透传，由调用方决定是否降级）。
    """
    delays = backoff_delays(attempts=attempts, base_delay_s=base_delay_s, max_delay_s=max_delay_s)
    last_exc: Exception | None = None
    for index in range(max(1, attempts)):
        try:
            result = await operation()
        except Exception as exc:  # noqa: BLE001 - 需要捕获全部异常以便重试
            last_exc = exc
            reason = f"{type(exc).__name__}: {exc}"
            if index < len(delays):
                log_self_heal(
                    SelfHealEvent(
                        component=component,
                        action=ACTION_RETRY,
                        reason=reason,
                        label=label,
                        attempt=index + 1,
                        details={"next_delay_s": delays[index]},
                    )
                )
                await sleep(delays[index])
                continue
            log_self_heal(
                SelfHealEvent(
                    component=component,
                    action=ACTION_EXHAUSTED,
                    reason=reason,
                    label=label,
                    attempt=index + 1,
                    details={"attempts": max(1, attempts)},
                )
            )
        else:
            if index > 0:
                log_self_heal(
                    SelfHealEvent(
                        component=component,
                        action=ACTION_RECOVERED,
                        reason="重试后成功",
                        label=label,
                        attempt=index + 1,
                    )
                )
            return result
    raise last_exc if last_exc is not None else RuntimeError("retry_async：无可用异常（不应到达）")


def fallback_urls(source: str) -> tuple[str, ...]:
    """返回某源的备用入口地址列表（大小写不敏感）。

    Args:
        source: 源标识。

    Returns:
        备用地址元组；未登记时返回空元组。
    """
    return FALLBACK_URLS.get(source.strip().lower(), ())


def apply_fallback_url(connector: BaseConnector, url: str) -> bool:
    """把采集器的入口 URL 切到备用地址（**通用机制**，无需改各采集器）。

    实现方式：在连接器实例上覆写「入口 URL 类属性」（见 :data:`CONNECTOR_URL_ATTRS`）。
    仅当该类确实声明过该属性时才生效——既有采集器把入口地址写成类常量
    （如 ``KevConnector.catalog_url``），因此实例属性覆写即可完成镜像切换。

    Args:
        connector: 采集器实例。
        url: 备用入口地址。

    Returns:
        切换成功返回 ``True``；该采集器未声明任何入口 URL 属性时返回 ``False``。
    """
    for attr in CONNECTOR_URL_ATTRS:
        if hasattr(type(connector), attr):
            setattr(connector, attr, url)
            log_self_heal(
                SelfHealEvent(
                    component=COMPONENT_COLLECT,
                    action=ACTION_FALLBACK,
                    reason="主入口连续失败，切换到备用地址",
                    label=connector.source_name,
                    details={"attr": attr, "url": url},
                )
            )
            return True
    log_self_heal(
        SelfHealEvent(
            component=COMPONENT_COLLECT,
            action=ACTION_DEGRADED,
            reason="无可用备用地址，该源本次采集记为失败（不阻断其它源）",
            label=connector.source_name,
        )
    )
    return False


async def fetch_with_self_heal(
    connector: BaseConnector,
    fetch: Callable[[], Awaitable[list[Any]]],
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    base_delay_s: float = DEFAULT_BASE_DELAY_S,
    max_delay_s: float = DEFAULT_MAX_DELAY_S,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> tuple[list[Any], str | None]:
    """带自愈的采集拉取（先重试主地址，再逐个切备用镜像地址）。

    Args:
        connector: 采集器实例（``fetch`` 每次调用都读取其当前入口地址）。
        fetch: 无参异步拉取函数（典型实现：``lambda: connector.fetch_incremental(since)``）。
        attempts: 每个地址的尝试次数（含首次）。
        base_delay_s: 退避基准间隔（秒）。
        max_delay_s: 单次退避上限（秒）。
        sleep: 休眠函数（单测注入）。

    Returns:
        ``(条目列表, 生效的备用地址或 None)``。

    Raises:
        Exception: 主地址与全部备用地址都失败时抛出最后一次异常。
    """
    source = connector.source_name
    last_exc: Exception | None = None
    try:
        items = await retry_async(
            fetch,
            attempts=attempts,
            base_delay_s=base_delay_s,
            max_delay_s=max_delay_s,
            component=COMPONENT_COLLECT,
            label=source,
            sleep=sleep,
        )
        return list(items), None
    except Exception as exc:  # noqa: BLE001 - 主地址耗尽，改试镜像
        last_exc = exc

    for url in fallback_urls(source):
        if not apply_fallback_url(connector, url):
            break
        try:
            items = await retry_async(
                fetch,
                attempts=attempts,
                base_delay_s=base_delay_s,
                max_delay_s=max_delay_s,
                component=COMPONENT_COLLECT,
                label=source,
                sleep=sleep,
            )
            return list(items), url
        except Exception as exc:  # noqa: BLE001 - 继续尝试下一个镜像
            last_exc = exc
    raise last_exc if last_exc is not None else RuntimeError("fetch_with_self_heal：无可用异常（不应到达）")

