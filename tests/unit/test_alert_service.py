"""Day17 任务 3.3：告警规则与投递测试（``services/alert_service.py``）。

覆盖点：
    1. 三条规则的阈值判定（采集失败率 > 20% / 富化失败率 > 20% / LLM 连续失败 ≥ 3）；
    2. 落盘：告警 JSON 单行写入 ``alerts.log``（路径可注入，测试用 tmp_path）；
    3. Webhook：投递函数可注入（不触网），失败只留痕不抛出；
    4. 指标累加 ``aisec_alerts_total``。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisec_intel.services.alert_service import (
    ALERT_COLLECT_FAILURE_RATIO,
    RULE_COLLECT_FAILURE_RATE,
    RULE_ENRICH_FAILURE_RATE,
    RULE_LLM_CONSECUTIVE_FAILURES,
    Alert,
    AlertService,
    evaluate_alerts,
)
from aisec_intel.services.metrics_service import (
    M_ALERTS,
    M_COLLECT_FAILURES,
    M_COLLECT_ITEMS,
    M_ENRICH_TOTAL,
    M_LLM_CONSECUTIVE_FAILURES,
    METRICS,
    MetricsRegistry,
)


@pytest.fixture()
def registry() -> MetricsRegistry:
    """干净注册表（规则评估只读传入实例）。"""
    return MetricsRegistry()


class TestRules:
    """三条告警规则的阈值判定。"""

    def test_no_alert_when_healthy(self, registry: MetricsRegistry) -> None:
        """全部正常时不出告警，且失败率快照会写入指标。"""
        registry.inc(M_COLLECT_ITEMS, {"source": "kev"}, value=100)
        registry.inc(M_ENRICH_TOTAL, {"status": "success"}, value=10)
        assert evaluate_alerts(registry) == []

    def test_collect_failure_rate_rule(self, registry: MetricsRegistry) -> None:
        """采集失败率 > 20% 触发采集告警。"""
        registry.inc(M_COLLECT_ITEMS, {"source": "kev"}, value=6)
        registry.inc(M_COLLECT_FAILURES, {"source": "kev"}, value=4)  # 4/10 = 40%
        alerts = evaluate_alerts(registry)
        assert [alert.rule for alert in alerts] == [RULE_COLLECT_FAILURE_RATE]
        assert alerts[0].severity == "warning"
        assert alerts[0].details["failure_ratio"] == pytest.approx(0.4)
        assert registry.gauge("aisec_collect_failure_ratio") == pytest.approx(0.4)

    def test_enrich_failure_rate_rule(self, registry: MetricsRegistry) -> None:
        """富化失败率 > 20% 触发富化告警。"""
        registry.inc(M_ENRICH_TOTAL, {"status": "success"}, value=3)
        registry.inc(M_ENRICH_TOTAL, {"status": "failed"}, value=2)  # 40%
        alerts = evaluate_alerts(registry)
        assert [alert.rule for alert in alerts] == [RULE_ENRICH_FAILURE_RATE]

    def test_llm_consecutive_failures_rule(self, registry: MetricsRegistry) -> None:
        """LLM 连续失败 ≥ 3 次触发 critical 告警。"""
        registry.set_gauge(M_LLM_CONSECUTIVE_FAILURES, 2)
        assert evaluate_alerts(registry) == []
        registry.set_gauge(M_LLM_CONSECUTIVE_FAILURES, 3)
        alerts = evaluate_alerts(registry)
        assert [alert.rule for alert in alerts] == [RULE_LLM_CONSECUTIVE_FAILURES]
        assert alerts[0].severity == "critical"

    def test_thresholds_are_task_spec(self) -> None:
        """阈值与任务书一致（20% / 20% / 3 次）。"""
        assert ALERT_COLLECT_FAILURE_RATIO == 0.2


class TestAlertService:
    """落盘与 Webhook 投递。"""

    def test_emit_writes_json_line_and_counters(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """告警写入 ``alerts.log``（JSON 单行）并累加指标。"""
        import aisec_intel.services.alert_service as module

        fresh = MetricsRegistry()
        monkeypatch.setattr(module, "METRICS", fresh)
        service = AlertService(log_path=tmp_path / "alerts.log", webhook_url="")
        alert = Alert(rule=RULE_COLLECT_FAILURE_RATE, severity="warning", message="采集失败率过高")
        assert service.emit(alert) is True

        lines = [line for line in (tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines() if line]
        payload = json.loads(lines[-1])
        assert payload["event"] == "alert.fired"
        assert payload["details"]["kind"] == "alert"
        assert payload["details"]["rule"] == RULE_COLLECT_FAILURE_RATE
        assert str(payload["details"]["fired_at"]).endswith("Z")
        assert fresh.counter(M_ALERTS, {"rule": RULE_COLLECT_FAILURE_RATE, "severity": "warning"}) == 1

    def test_webhook_failure_is_swallowed(self, tmp_path: Path) -> None:
        """Webhook 抛异常时仍返回 True（旁路不得影响主链路）。"""

        def _boom(url: str, payload: dict[str, object]) -> None:
            raise RuntimeError("webhook down")

        sent: list[dict[str, object]] = []

        def _capture(url: str, payload: dict[str, object]) -> None:
            sent.append(payload)

        service = AlertService(log_path=tmp_path / "alerts.log", webhook_url="https://example.test/hook", poster=_boom)
        assert service.emit(Alert(rule="demo", severity="warning", message="x")) is True
        assert sent == []

        service2 = AlertService(
            log_path=tmp_path / "alerts2.log", webhook_url="https://example.test/hook", poster=_capture
        )
        service2.emit(Alert(rule="demo", severity="critical", message="y"))
        assert sent and "text" in sent[0]

    def test_evaluate_and_emit_end_to_end(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """评估 → 投递：LLM 连续失败达到阈值时写出告警。"""
        import aisec_intel.services.alert_service as module

        monkeypatch.setattr(module, "METRICS", METRICS)
        METRICS.set_gauge(M_LLM_CONSECUTIVE_FAILURES, 3)
        try:
            service = AlertService(log_path=tmp_path / "alerts.log")
            alerts = service.evaluate_and_emit()
        finally:
            METRICS.set_gauge(M_LLM_CONSECUTIVE_FAILURES, 0)
        assert any(alert.rule == RULE_LLM_CONSECUTIVE_FAILURES for alert in alerts)
        last = json.loads((tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines()[-1])
        assert last["details"]["rule"] == RULE_LLM_CONSECUTIVE_FAILURES
        assert last["details"]["severity"] == "critical"
