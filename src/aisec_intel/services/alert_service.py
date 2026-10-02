"""告警规则与投递（Day17 任务 3.3）。

三条硬性规则（阈值均为常量，便于测试与调参）：

=================================  ============================================================
``collect_failure_rate``           采集失败率 > 20%（:data:`ALERT_COLLECT_FAILURE_RATIO`）
``enrich_failure_rate``            富化失败率 > 20%（:data:`ALERT_ENRICH_FAILURE_RATIO`）
``llm_consecutive_failures``        LLM 连续失败 ≥ 3 次（:data:`ALERT_LLM_CONSECUTIVE_FAILURES`）
=================================  ============================================================

投递方式（两者可同时生效）：
    1. **落盘**：``logs/alerts.log``（JSON 单行，独立滚动 handler，``trace_id`` 随上下文写入）；
    2. **Webhook**（可选）：``ALERT_WEBHOOK_URL`` 非空时 POST 一条 JSON
       （企业微信 / 飞书机器人文本字段兼容：同时给 ``text`` 与 ``content``）。

设计取舍：``emit`` **绝不抛异常**（告警是旁路设施，任何投递失败都不得影响主链路）。
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import attach_file_handler, get_logger, log_event
from aisec_intel.models.base import iso_z, utc_now
from aisec_intel.services.metrics_service import (
    M_ALERTS,
    M_COLLECT_FAILURE_RATIO,
    M_COLLECT_FAILURES,
    M_ENRICH_FAILURE_RATIO,
    M_LLM_CONSECUTIVE_FAILURES,
    METRICS,
    MetricsRegistry,
    collect_failure_ratio,
    enrich_failure_ratio,
)

logger = get_logger(__name__)

ALERT_LOGGER_NAME: str = "aisec_intel.alerts"
"""告警专用 logger 名（挂 ``logs/alerts.log`` 滚动 handler）。"""

ALERT_EVENT: str = "alert.fired"
"""告警事件名（写入日志 ``event`` 字段）。"""

ALERT_COLLECT_FAILURE_RATIO: float = 0.2
"""采集失败率告警阈值（> 20%）。"""

ALERT_ENRICH_FAILURE_RATIO: float = 0.2
"""富化失败率告警阈值（> 20%）。"""

ALERT_LLM_CONSECUTIVE_FAILURES: int = 3
"""LLM 连续失败次数告警阈值（≥ 3 次）。"""

RULE_COLLECT_FAILURE_RATE: str = "collect_failure_rate"
"""规则名：采集失败率过高。"""

RULE_ENRICH_FAILURE_RATE: str = "enrich_failure_rate"
"""规则名：富化失败率过高。"""

RULE_LLM_CONSECUTIVE_FAILURES: str = "llm_consecutive_failures"
"""规则名：LLM 连续失败。"""

Severity = Literal["warning", "critical"]
"""告警级别（失败率类为 ``warning``，LLM 连续失败为 ``critical``）。"""

AlertPoster = Callable[[str, dict[str, Any]], None]
"""Webhook 投递函数签名：``(url, payload) -> None``（异常自行抛出，由 :meth:`AlertService.emit` 吞掉）。"""


def _default_poster(url: str, payload: dict[str, Any]) -> None:
    """默认 Webhook 投递（httpx，3 秒超时）。

    Args:
        url: Webhook 地址。
        payload: JSON 载荷。
    """
    import httpx

    httpx.post(url, json=payload, timeout=3.0).raise_for_status()


@dataclass(frozen=True, slots=True)
class Alert:
    """一条告警。

    Attributes:
        rule: 规则名（见 ``RULE_*`` 常量）。
        severity: 级别。
        message: 面向运维的中文描述。
        details: 结构化上下文（阈值 / 实际值 / 样本）。
        fired_at: 触发时间（UTC）。
    """

    rule: str
    severity: Severity
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    fired_at: datetime = field(default_factory=utc_now)

    def as_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典（落盘 / Webhook 共用）。

        Returns:
            含 ``rule`` / ``severity`` / ``message`` / ``details`` / ``fired_at`` 的字典。
        """
        return {
            "kind": "alert",
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "details": dict(self.details),
            "fired_at": iso_z(self.fired_at),
        }


def evaluate_alerts(
    registry: MetricsRegistry = METRICS,
    *,
    collect_threshold: float = ALERT_COLLECT_FAILURE_RATIO,
    enrich_threshold: float = ALERT_ENRICH_FAILURE_RATIO,
    llm_threshold: int = ALERT_LLM_CONSECUTIVE_FAILURES,
) -> list[Alert]:
    """按三条规则评估当前指标，返回需要触发的告警（纯函数，除读注册表外无副作用）。

    Args:
        registry: 指标注册表。
        collect_threshold: 采集失败率阈值（``>`` 触发）。
        enrich_threshold: 富化失败率阈值（``>`` 触发）。
        llm_threshold: LLM 连续失败阈值（``>=`` 触发）。

    Returns:
        告警列表（规则命中顺序固定，便于测试）。
    """
    alerts: list[Alert] = []
    collect_ratio = collect_failure_ratio(registry)
    registry.set_gauge(M_COLLECT_FAILURE_RATIO, collect_ratio)
    if collect_ratio > collect_threshold:
        alerts.append(
            Alert(
                rule=RULE_COLLECT_FAILURE_RATE,
                severity="warning",
                message=f"采集失败率 {collect_ratio:.0%} 超过阈值 {collect_threshold:.0%}，请检查源可用性",
                details={
                    "failure_ratio": round(collect_ratio, 4),
                    "threshold": collect_threshold,
                    "failures": registry.counter_total(M_COLLECT_FAILURES),
                },
            )
        )
    enrich_ratio = enrich_failure_ratio(registry)
    registry.set_gauge(M_ENRICH_FAILURE_RATIO, enrich_ratio)
    if enrich_ratio > enrich_threshold:
        alerts.append(
            Alert(
                rule=RULE_ENRICH_FAILURE_RATE,
                severity="warning",
                message=f"富化失败率 {enrich_ratio:.0%} 超过阈值 {enrich_threshold:.0%}，请检查 LLM 与检索依赖",
                details={"failure_ratio": round(enrich_ratio, 4), "threshold": enrich_threshold},
            )
        )
    consecutive = int(registry.gauge(M_LLM_CONSECUTIVE_FAILURES))
    if consecutive >= llm_threshold:
        alerts.append(
            Alert(
                rule=RULE_LLM_CONSECUTIVE_FAILURES,
                severity="critical",
                message=f"LLM 连续失败 {consecutive} 次（阈值 {llm_threshold}），已自动降级到备用模型 / 确定性路径",
                details={"consecutive_failures": consecutive, "threshold": llm_threshold},
            )
        )
    return alerts


class AlertService:
    """告警投递器（落盘 + 可选 Webhook）。

    Attributes:
        log_path: 告警日志路径（``None`` 时只用根 logger 输出）。
        webhook_url: Webhook 地址（空串表示不投递）。
    """

    def __init__(
        self,
        *,
        log_path: str | Path | None = None,
        webhook_url: str = "",
        settings: Settings | None = None,
        poster: AlertPoster | None = None,
    ) -> None:
        """初始化投递器。

        Args:
            log_path: 告警日志路径；``None`` 时取 ``Settings.alert_log_path``。
            webhook_url: Webhook 地址；缺省取 ``Settings.alert_webhook_url``。
            settings: 全局配置；``None`` 时用 :func:`~aisec_intel.config.get_settings`。
            poster: 自定义 Webhook 投递函数（测试注入用）。
        """
        resolved = settings or get_settings()
        self.log_path: str | None = str(log_path) if log_path is not None else resolved.alert_log_path
        self.webhook_url: str = webhook_url or resolved.alert_webhook_url
        self._poster: AlertPoster = poster or _default_poster
        self._alert_logger = get_logger(ALERT_LOGGER_NAME)
        if self.log_path:
            attach_file_handler(
                ALERT_LOGGER_NAME,
                self.log_path,
                json_output=True,
                level=resolved.log_level,
                max_bytes=resolved.log_max_bytes,
                backup_count=resolved.log_backup_count,
            )

    def emit(self, alert: Alert) -> bool:
        """投递一条告警（写日志 + 指标 + 可选 Webhook）。

        落盘结构：``details`` 内为 ``{"kind":"alert","rule","severity","fired_at","context"}``，
        与自愈日志同构，便于统一采集 / 检索。

        Args:
            alert: 待投递的告警。

        Returns:
            日志已写出返回 ``True``；投递过程任何异常都被吞掉（返回 ``False``）。
        """
        context = dict(alert.details)
        structured = {
            "kind": "alert",
            "rule": alert.rule,
            "severity": alert.severity,
            "fired_at": iso_z(alert.fired_at),
            "context": context,
        }
        written = False
        try:
            log_event(
                self._alert_logger,
                ALERT_EVENT,
                level=logging.WARNING,
                message=alert.message,
                **structured,
            )
            written = True
        except Exception as exc:  # noqa: BLE001 - 告警投递绝不影响主链路
            logger.warning(f"告警日志写入失败：{type(exc).__name__}: {exc}")
        METRICS.inc(M_ALERTS, {"rule": alert.rule, "severity": alert.severity})
        if self.webhook_url:
            body: dict[str, Any] = {
                "msgtype": "text",
                "text": {"content": f"[{alert.severity}] {alert.message}"},
                "alert": structured,
            }
            try:
                self._poster(self.webhook_url, body)
            except Exception as exc:  # noqa: BLE001 - Webhook 失败只留痕
                logger.warning(f"告警 Webhook 投递失败：{type(exc).__name__}: {exc}")
        return written

    def emit_all(self, alerts: Sequence[Alert]) -> int:
        """批量投递。

        Args:
            alerts: 告警序列。

        Returns:
            成功写出的条数。
        """
        return sum(1 for alert in alerts if self.emit(alert))

    def evaluate_and_emit(self) -> list[Alert]:
        """评估指标并投递命中的告警。

        Returns:
            本次触发的告警列表。
        """
        alerts = evaluate_alerts()
        self.emit_all(alerts)
        return alerts


@lru_cache(maxsize=1)
def get_alert_service() -> AlertService:
    """返回进程级告警投递器（首次调用时按配置挂好 ``logs/alerts.log``）。

    Returns:
        全局唯一的 :class:`AlertService`。
    """
    return AlertService()


def emit_alerts_safely() -> list[Alert]:
    """评估并投递告警（**旁路**：任何异常都只留痕，不抛给主链路）。

    Returns:
        本次触发的告警列表；评估失败时返回空列表。
    """
    try:
        return get_alert_service().evaluate_and_emit()
    except Exception as exc:  # noqa: BLE001 - 告警是旁路设施，绝不影响主流程
        logger.warning(f"告警评估失败（已忽略）：{type(exc).__name__}: {exc}")
        return []

