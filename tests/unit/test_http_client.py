"""Day3 HTTP 客户端测试（PROJECT_PLAN.md §5.3）。

全部用例走 ``httpx.MockTransport``，**不产生任何真实网络请求**。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from aisec_intel.connectors.http_client import (
    DEFAULT_USER_AGENT,
    HttpClient,
    HttpStatusError,
    HttpTransportError,
)

if TYPE_CHECKING:  # pragma: no cover - 仅用于类型标注
    from conftest import MockRouter

TARGET = "https://example.test/api/data"
PAYLOAD = {"ok": True, "items": [1, 2, 3]}


class TestBasicRequests:
    """基础请求行为。"""

    async def test_get_json_and_user_agent(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """GET 返回 JSON，并带上统一 User-Agent。"""
        mock_router.always(TARGET, json_body=PAYLOAD)
        data = await mock_http.get_json(TARGET)
        assert data == PAYLOAD
        assert DEFAULT_USER_AGENT in mock_router.calls[-1].headers["user-agent"]

    async def test_get_json_with_params(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """查询参数被正确拼接到 URL。"""
        mock_router.always(TARGET, json_body=PAYLOAD)
        await mock_http.get_json(TARGET, params={"limit": 5, "q": "cve"})
        assert "limit=5" in str(mock_router.calls[-1].url)

    async def test_post_json_sends_body(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """POST 会发送 JSON 请求体。"""
        mock_router.always(TARGET, json_body={"echo": True})
        result = await mock_http.post_json(TARGET, payload={"message": "ping"})
        assert result == {"echo": True}
        assert b"ping" in mock_router.calls[-1].content

    async def test_get_text(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """GET 文本用于 RSS / STIX。"""
        mock_router.always(TARGET, text="<rss></rss>")
        assert await mock_http.get_text(TARGET) == "<rss></rss>"

    async def test_custom_headers_override_default(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """自定义请求头可覆盖默认值（如源方要求的 Accept）。"""
        mock_router.always(TARGET, json_body=PAYLOAD)
        await mock_http.get_json(TARGET, headers={"Accept": "application/vnd.api+json"})
        assert mock_router.calls[-1].headers["accept"] == "application/vnd.api+json"


class TestRetryPolicy:
    """重试行为测试。"""

    async def test_retries_on_5xx_then_succeeds(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """5xx 触发重试，随后成功。"""
        mock_router.add(TARGET, status_code=503)
        mock_router.add(TARGET, json_body=PAYLOAD)
        assert await mock_http.get_json(TARGET) == PAYLOAD
        assert mock_router.call_count(TARGET) == 2

    async def test_retries_exhausted_raises_status_error(
        self, mock_router: MockRouter, mock_http: HttpClient
    ) -> None:
        """连续 5xx 达上限后抛出 ``HttpStatusError``（默认 3 次尝试）。"""
        mock_router.always(TARGET, status_code=500)
        with pytest.raises(HttpStatusError) as excinfo:
            await mock_http.get_json(TARGET)
        assert excinfo.value.status_code == 500
        assert mock_router.call_count(TARGET) == 3

    async def test_client_4xx_is_not_retried(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """普通 4xx 立即失败，不浪费配额。"""
        mock_router.always(TARGET, status_code=404)
        with pytest.raises(HttpStatusError) as excinfo:
            await mock_http.get_json(TARGET)
        assert excinfo.value.status_code == 404
        assert mock_router.call_count(TARGET) == 1

    async def test_transport_error_wrapped(self) -> None:
        """网络层错误被包装为 ``HttpTransportError``。"""

        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("连接被拒绝", request=request)

        client = HttpClient(transport=httpx.MockTransport(boom), max_retries=2, retry_wait_min_s=0.0)
        try:
            with pytest.raises(HttpTransportError):
                await client.get_json(TARGET)
        finally:
            await client.aclose()

    async def test_max_retries_configurable(self, mock_router: MockRouter) -> None:
        """``max_retries`` 可配置（此处为 1 → 只请求一次）。"""
        mock_router.always(TARGET, status_code=502)
        client = HttpClient(transport=httpx.MockTransport(mock_router.handler), max_retries=1)
        try:
            with pytest.raises(HttpStatusError):
                await client.get_json(TARGET)
            assert mock_router.call_count(TARGET) == 1
        finally:
            await client.aclose()


class TestHealthAndConfig:
    """探活与配置属性测试。"""

    async def test_head_status_ok(self, mock_router: MockRouter, mock_http: HttpClient) -> None:
        """HEAD 200 返回状态码。"""
        mock_router.always(TARGET, status_code=200)
        assert await mock_http.head_status(TARGET) == 200

    async def test_head_status_swallows_failure(self, mock_http: HttpClient) -> None:
        """未登记 URL（404）时探活返回 ``None`` 而不抛异常。"""
        assert await mock_http.head_status("https://example.test/missing") is None

    def test_timeout_and_user_agent_properties(self) -> None:
        """超时与 UA 可配置，并暴露只读属性。"""
        client = HttpClient(timeout=12.5, user_agent="custom-ua/1.0", max_retries=5)
        assert client.timeout == 12.5
        assert client.user_agent == "custom-ua/1.0"
        assert client.raw_client is not None

    async def test_client_is_usable_as_context_manager(self, mock_router: MockRouter) -> None:
        """``async with`` 退出时自动关闭连接池。"""
        mock_router.always(TARGET, json_body=PAYLOAD)
        async with HttpClient(transport=httpx.MockTransport(mock_router.handler)) as client:
            assert await client.get_json(TARGET) == PAYLOAD
