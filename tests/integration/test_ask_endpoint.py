"""Day11 任务 5 + Day12 任务 5/6：问答 API 测试（``aisec_intel.api.routers.qa``）。

用 ``TestClient`` + ``dependency_overrides`` 注入桩检索服务与降级配置，
**不需要真实 PG / Neo4j / LLM** 即可验证：请求契约、引用可回溯、限流 429、探活字段，
以及 Day12 的多轮会话（同一 ``session_id`` 复用检查点）不回归。

Note:
    Day12 任务 2 合并：原 14 个用例压到 6 个（同类断言合入同一函数并循环多组输入）。
"""

from __future__ import annotations

from typing import Any

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
    """``POST /qa/ask``（契约、降级、多轮会话）。"""

    def test_ask_returns_cited_answer_and_fallback(self) -> None:
        """有证据时返回可回溯引用；无证据时返回兜底文案而非 500。"""
        with _make_client([_result()]) as client:
            body = client.post("/api/v1/qa/ask", json={"query": QUESTION, "trace_id": "trace-1"}).json()
        assert body["answer"]
        assert body["citations"][0]["locator"] == "graph:CVE-2024-3400"
        assert body["citations"][0]["cve_id"] == "CVE-2024-3400"
        assert body["degraded"] is True  # 降级配置下需显式标记

        with _make_client([]) as client:
            empty = client.post("/api/v1/qa/ask", json={"query": "完全无关的问题"}).json()
        assert "未找到相关信息" in empty["answer"] and empty["citations"] == []

    def test_ask_payload_validation_and_trace_default(self) -> None:
        """非法请求体统一 422；缺 ``trace_id`` 时服务端自动补全（200）。"""
        invalid: list[dict[str, Any]] = [
            {"query": ""},
            {"query": QUESTION, "top_k": 0},
            {"query": QUESTION, "max_hops": 9},
            {"query": QUESTION, "unexpected": 1},
        ]
        with _make_client([_result()]) as client:
            for payload in invalid:
                assert client.post("/api/v1/qa/ask", json=payload).status_code == 422, payload
            assert client.post("/api/v1/qa/ask", json={"query": QUESTION}).status_code == 200

    def test_ask_multi_turn_session(self) -> None:
        """同一 ``session_id`` 的连续两轮问答均成功（Day12 任务 6 回归守卫）。"""
        with _make_client([_result()]) as client:
            first = client.post("/api/v1/qa/ask", json={"query": QUESTION, "session_id": "s-day12"})
            second = client.post(
                "/api/v1/qa/ask",
                json={"query": "那它的修复方案呢？", "session_id": "s-day12"},
            )
            explicit = client.post(
                "/api/v1/qa/ask",
                json={"query": "它影响哪些资产", "session_context": ["上一轮问题：PAN-OS 漏洞"]},
            )
        assert first.status_code == 200 and second.status_code == 200
        assert "未找到相关信息" in second.json()["answer"] or second.json()["answer"]
        assert explicit.status_code == 200


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

    def test_rate_limiter_semantics(self) -> None:
        """窗口内首次调用恒放行；``reset`` 后重新计数。"""
        for limit in (1, 2, 60):
            assert RateLimiter(limit=limit).allow("1.1.1.1") is True
        limiter = RateLimiter(limit=1)
        assert limiter.allow("k") is True and limiter.allow("k") is False
        limiter.reset()
        assert limiter.allow("k") is True


class TestHealthEndpoint:
    """``GET /qa/health`` 与进程探活。"""

    def test_health_and_probe(self) -> None:
        """降级配置下回传链路快照；``/healthz`` 返回组件健康（Day17 任务 3.4）。"""
        with _make_client([_result()]) as client:
            body = client.get("/api/v1/qa/health").json()
            probe = client.get("/healthz").json()
            assert probe["status"] in {"ok", "degraded", "error"}
            assert set(probe["components"]) == {"pg", "neo4j", "chroma", "llm"}
            # LLM 组件仅做配置检查（不发起付费调用）：按本机 .env 可能 up 也可能 degraded
            assert probe["components"]["llm"]["status"] in {"up", "degraded"}
            assert probe["components"]["llm"]["detail"]
            assert str(probe["checked_at"]).endswith("Z")
        assert body["status"] == "degraded"
        assert body["llm_enabled"] is False
        assert body["plan"] == ["query_understander", "supervisor", "reasoner", "synthesizer"]
        assert body["rate_limit_per_minute"] == 60
