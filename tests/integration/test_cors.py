"""Day19 任务 5：CORS 契约测试（前端「本地 / 云端后端切换」的跨域前提）。

覆盖点：
    1. 放行名单包含开发态 Vite dev server（``5173``）与容器前端（``3000``）的
       ``localhost`` / ``127.0.0.1`` 两种写法；
    2. 来自放行源的 **预检请求**（``OPTIONS``）回显 ``Access-Control-Allow-Origin``，
       且暴露 ``X-Trace-Id``（前端凭它把一次点击与后端日志对齐）；
    3. 未放行源不带 ``Access-Control-Allow-Origin``，且预检被拒（400）。

Note:
    预检请求由 CORSMiddleware 直接应答，不进入路由处理，因此无需数据库 / Neo4j 等外部依赖。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from aisec_intel.api.main import CORS_ALLOW_ORIGINS, create_app

ALLOWED_ORIGINS = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}


def _preflight_headers(origin: str) -> dict[str, str]:
    """构造跨域预检请求头（纯函数）。

    Args:
        origin: 发起请求的前端源。

    Returns:
        预检请求头字典。
    """
    return {
        "Origin": origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "content-type",
    }


class TestCorsAllowList:
    """放行名单本身。"""

    def test_covers_dev_and_container_frontends(self) -> None:
        """列表覆盖 5173 / 3000 与 localhost / 127.0.0.1 的组合。"""
        assert set(CORS_ALLOW_ORIGINS) == ALLOWED_ORIGINS


class TestCorsPreflight:
    """预检行为（真实走 CORSMiddleware）。"""

    def test_allowed_origin_preflight_is_echoed(self) -> None:
        """放行源的预检返回 200，并回显 origin 与请求方法。"""
        client = TestClient(create_app())
        response = client.options("/api/v1/stats", headers=_preflight_headers("http://localhost:5173"))
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
        assert "GET" in response.headers["access-control-allow-methods"]

    def test_allowed_origin_simple_response_exposes_trace_header(self) -> None:
        """实际响应暴露 ``X-Trace-Id``（前端凭它把一次点击与后端日志对齐）。

        Note:
            Starlette 的 ``expose_headers`` 只加在**非预检**响应上，故这里用 ``GET /healthz``
            （不依赖数据库，离线可跑）验证。
        """
        client = TestClient(create_app())
        response = client.get("/healthz", headers={"Origin": "http://127.0.0.1:5173"})
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"
        assert "X-Trace-Id" in response.headers["access-control-expose-headers"]

    def test_unknown_origin_preflight_is_rejected(self) -> None:
        """未放行源的预检被拒，且**不**返回 allow-origin（浏览器据此拦截）。"""
        client = TestClient(create_app())
        response = client.options("/api/v1/stats", headers=_preflight_headers("http://evil.example.com"))
        assert response.status_code == 400
        assert "access-control-allow-origin" not in response.headers
