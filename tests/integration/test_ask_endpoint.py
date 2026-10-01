"""Day11 任务 5：问答 API 测试（``aisec_intel.api.routers.qa``，PROJECT_PLAN.md §5.8）。

用 ``TestClient`` + ``dependency_overrides`` 注入桩检索服务与降级配置，
**不需要真实 PG / Neo4j / LLM** 即可验证：请求契约、引用可回溯、限流 429、探活字段。
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from aisec_intel.api.deps import RateLimiter, get_rate_limiter, get_retrieval_service, get_settings_dep
from aisec_intel.api.main import create_app
from aisec_intel.config import Settings
from aisec_intel.qa.state import RetrievalResult

QUESTION = "CVE-2024-3400 影响哪些资产"


class _StubRetrieval:
    """检索服务桩：只实现 Supervisor 需要的 ``dispatch``。"""

    def __init__(self, results: list[RetrievalResult]) -> None:
        """初始化桩。

        Args:
            results: ``graph`` 路由返回的结果。
        """
        self._results = results

    async def dispatch(self, route: str, query: str, **_: Any) -> list[RetrievalResult]:
        """按路由返回预置结果。"""
        return list(self._results) if route == "graph" else []

    async def aclose(self) -> None:
        """释放（桩无资源）。"""


def _result() -> RetrievalResult:
    """构造一条图谱检索结果。"""
    return RetrievalResult(
        source="graph",
        doc_id="graph:CVE-2024-3400",
        content="PAN-OS 受影响组件 paloaltonetworks:pan-os",
        score=0.6,
        rank=1,
        metadata={"cve_id": "CVE-2024-3400"},
    )


def _make_client(results: list[RetrievalResult], *, limit: int = 60) -> TestClient:
    """构造注入了桩依赖的测试客户端（全降级配置，不触网）。

    Args:
        results: 桩检索结果。
        limit: 限流额度。

    Returns:
        :class:`TestClient`（已绑定应用）。
    """
    app = create_app()
    settings = Settings(llm_api_key="", degraded_mode=True, embedding_backend="hashing")
    limiter = RateLimiter(limit=limit)
    app.dependency_overrides[get_settings_dep] = lambda: settings
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    app.dependency_overrides[get_retrieval_service] = lambda: _StubRetrieval(results)
    return TestClient(app)


class TestAskEndpoint:
    """``POST /qa/ask``。"""

    def test_ask_returns_cited_answer(self) -> None:
        """正常问答：返回 answer + 可回溯引用（``locator`` 命中检索结果）。"""
        with _make_client([_result()]) as client:
            body = client.post("/api/v1/qa/ask", json={"query": QUESTION, "trace_id": "trace-1"}).json()
        assert body["answer"]
        assert body["citations"][0]["locator"] == "graph:CVE-2024-3400"
        assert body["citations"][0]["cve_id"] == "CVE-2024-3400"
        assert body["degraded"] is True  # 降级配置下需显式标记

    def test_ask_without_evidence_returns_not_found(self) -> None:
        """检索为空：返回「未找到相关信息」而非 500。"""
        with _make_client([]) as client:
            body = client.post("/api/v1/qa/ask", json={"query": "完全无关的问题"}).json()
        assert "未找到相关信息" in body["answer"]
        assert body["citations"] == []

    @pytest.mark.parametrize(
        "payload",
        [
            {"query": ""},
            {"query": QUESTION, "top_k": 0},
            {"query": QUESTION, "max_hops": 9},
            {"query": QUESTION, "unexpected": 1},
        ],
    )
    def test_ask_rejects_invalid_payload(self, payload: dict[str, Any]) -> None:
        """非法请求体统一 422（空问题 / 越界 / 未声明字段）。"""
        with _make_client([_result()]) as client:
            assert client.post("/api/v1/qa/ask", json=payload).status_code == 422

    def test_trace_id_is_generated_when_missing(self) -> None:
        """未传 ``trace_id`` 时请求仍然成功（服务端自动生成）。"""
        with _make_client([_result()]) as client:
            assert client.post("/api/v1/qa/ask", json={"query": QUESTION}).status_code == 200


class TestRateLimit:
    """``POST /qa/ask`` 限流（每分钟 60 次）。"""

    def test_exceeding_quota_returns_429(self) -> None:
        """超过额度返回 429，并给出可读提示。"""
        with _make_client([_result()], limit=2) as client:
            assert client.post("/api/v1/qa/ask", json={"query": QUESTION}).status_code == 200
            assert client.post("/api/v1/qa/ask", json={"query": QUESTION}).status_code == 200
            blocked = client.post("/api/v1/qa/ask", json={"query": QUESTION})
        assert blocked.status_code == 429
        assert "每分钟" in blocked.json()["detail"]

    @pytest.mark.parametrize("limit", [1, 2, 60])
    def test_first_call_always_allowed(self, limit: int) -> None:
        """窗口内首次调用恒放行（不同额度一致）。"""
        assert RateLimiter(limit=limit).allow("1.1.1.1") is True

    def test_rate_limiter_reset(self) -> None:
        """``reset`` 后重新计数。"""
        limiter = RateLimiter(limit=1)
        assert limiter.allow("k") is True and limiter.allow("k") is False
        limiter.reset()
        assert limiter.allow("k") is True


class TestHealthEndpoint:
    """``GET /qa/health`` 与进程探活。"""

    def test_health_reports_degraded_chain(self) -> None:
        """降级配置下：``status=degraded``，并回传主干节点与限流额度。"""
        with _make_client([_result()]) as client:
            body = client.get("/api/v1/qa/health").json()
        assert body["status"] == "degraded"
        assert body["llm_enabled"] is False
        assert body["plan"] == ["query_understander", "supervisor", "reasoner", "synthesizer"]
        assert body["rate_limit_per_minute"] == 60

    def test_healthz_probe(self) -> None:
        """进程探活不依赖任何中间件。"""
        with _make_client([]) as client:
            assert client.get("/healthz").json() == {"status": "ok"}
