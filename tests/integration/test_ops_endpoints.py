"""Day17 任务 3：运维端点测试（``/metrics`` / ``/healthz`` / ``/readyz``）。

覆盖点：
    1. ``GET /metrics`` 返回 Prometheus 文本格式（``text/plain`` + ``# HELP`` / ``# TYPE``）；
    2. ``GET /healthz`` 返回 ``status`` + 四组件明细（``pg/neo4j/chroma/llm``）；
    3. ``GET /readyz``：PostgreSQL 可用时 ``ready``（硬依赖），不可用时 503。

Note:
    探针会真实访问当前 ``.env`` 指向的组件；断言只依赖**结构与语义**，
    不假设本地是否启动了 PostgreSQL / Neo4j / Chroma，因此离线可复现。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aisec_intel.api.main import create_app
from aisec_intel.services.metrics_service import METRICS

COMPONENTS = {"pg", "neo4j", "chroma", "llm"}


@pytest.fixture()
def client() -> TestClient:
    """不覆盖任何依赖的测试客户端（走真实配置与探针）。"""
    with TestClient(create_app()) as test_client:
        yield test_client


class TestMetricsEndpoint:
    """Prometheus 指标端点。"""

    def test_metrics_is_prometheus_text(self, client: TestClient) -> None:
        """响应为 Prometheus 文本格式，且包含指标类型声明。"""
        METRICS.inc("aisec_collect_items_total", {"source": "kev"}, value=1)
        response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        body = response.text
        assert "# HELP aisec_collect_items_total" in body
        assert "# TYPE aisec_collect_items_total counter" in body
        assert 'aisec_collect_items_total{source="kev"}' in body

    def test_metrics_exposes_business_metric_families(self, client: TestClient) -> None:
        """四类业务指标家族（采集 / 富化 / 问答 / LLM token / 自愈 / 告警）均可导出。

        Note:
            Prometheus 约定「无样本不导出」，故这里先各记一次业务事件再断言，
            顺便验证服务层记录函数与导出器口径一致。
        """
        from pathlib import Path
        from tempfile import gettempdir

        from aisec_intel.services.alert_service import Alert, AlertService
        from aisec_intel.services.metrics_service import (
            record_collect,
            record_enrich,
            record_llm_usage,
            record_qa,
        )
        from aisec_intel.services.self_heal import SelfHealEvent, log_self_heal

        record_collect("kev", fetched=3, failed=False, duration_s=0.1)
        record_enrich(ok=True, duration_s=0.2)
        record_qa(ok=True, duration_s=0.5)
        record_llm_usage("deepseek-chat", prompt_tokens=10, completion_tokens=5)
        log_self_heal(SelfHealEvent(component="qa", action="degraded", reason="vector down"))
        AlertService(log_path=Path(gettempdir()) / "aisec-test-alerts.log").emit(
            Alert(rule="demo_rule", severity="warning", message="demo")
        )

        body = client.get("/metrics").text
        for family in (
            "aisec_collect_items_total",
            "aisec_enrich_total",
            "aisec_qa_requests_total",
            "aisec_llm_tokens_total",
            "aisec_self_heal_total",
            "aisec_alerts_total",
        ):
            assert f"# TYPE {family}" in body, family


class TestHealthEndpoints:
    """``/healthz`` 与 ``/readyz``。"""

    def test_healthz_reports_components(self, client: TestClient) -> None:
        """``/healthz`` 返回聚合状态 + 四组件明细（含耗时与说明）。"""
        payload = client.get("/healthz").json()
        assert payload["status"] in {"ok", "degraded", "error"}
        assert set(payload["components"]) == COMPONENTS
        assert str(payload["checked_at"]).endswith("Z")
        for name, detail in payload["components"].items():
            assert detail["status"] in {"up", "down", "degraded", "unknown"}, name
            assert isinstance(detail["detail"], str) and detail["detail"]

    def test_readyz_returns_200_or_503(self, client: TestClient) -> None:
        """``/readyz``：就绪 200 / 硬依赖不可用 503，二者语义一一对应。"""
        response = client.get("/readyz")
        payload = response.json()
        if response.status_code == 200:
            assert payload["status"] == "ready"
        else:
            assert response.status_code == 503
            assert payload["status"] == "not_ready"
        assert set(payload["components"]) == COMPONENTS

    def test_component_gauges_exported(self, client: TestClient) -> None:
        """探针结果会同步写入 ``aisec_component_up`` 指标（供 Prometheus 采）。"""
        client.get("/healthz")
        body = client.get("/metrics").text
        assert "# TYPE aisec_component_up gauge" in body
        assert 'aisec_component_up{component="pg"}' in body

    def test_trace_id_header_round_trip(self, client: TestClient) -> None:
        """Day17 任务 3.1：``X-Trace-Id`` 请求头被透传；缺失时自动生成并回写响应头。"""
        provided = "a" * 32
        echoed = client.get("/healthz", headers={"X-Trace-Id": provided})
        assert echoed.headers["X-Trace-Id"] == provided

        generated = client.get("/healthz")
        trace_id = generated.headers["X-Trace-Id"]
        assert len(trace_id) == 32 and trace_id != provided
