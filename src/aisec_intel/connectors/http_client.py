"""统一 HTTP 客户端（PROJECT_PLAN.md §5.3 P2）。

基于 ``httpx.AsyncClient``，为 L1 采集层提供一致的行为：

1. **统一重试**：``tenacity`` 指数退避，默认最多 3 次，仅对网络错误与可重试状态码生效
   （408/425/429/5xx）；其余 4xx 立即失败，避免无意义重试。
2. **统一超时**：默认 30s（可用 ``timeout`` 覆盖）。
3. **统一 User-Agent**：便于源方识别与限流沟通。
4. **支持代理 / 自定义 Header**：企业网络与比赛现场兜底。
5. **便捷方法**：``get_json`` / ``post_json`` / ``get_text`` / ``head_status``。

约束：本模块属 L1 采集层，**禁止调用 LLM**（§0 约束 1）。
"""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

DEFAULT_USER_AGENT: str = "aisec-intel/0.1 (security-intelligence-collector)"
"""默认 User-Agent（不含个人隐私信息）。"""

DEFAULT_TIMEOUT_S: float = 30.0
"""默认请求超时（秒）。"""

DEFAULT_MAX_RETRIES: int = 3
"""默认最大尝试次数（含首次）。"""

RETRYABLE_STATUS: frozenset[int] = frozenset({408, 425, 429, 500, 502, 503, 504})
"""可重试的 HTTP 状态码。"""


class HttpClientError(RuntimeError):
    """HTTP 客户端错误基类。"""


class HttpStatusError(HttpClientError):
    """服务端返回了不可接受的状态码（重试后仍失败）。"""

    def __init__(self, *, status_code: int, url: str, body: str = "") -> None:
        """构造状态码异常。

        Args:
            status_code: HTTP 状态码。
            url: 请求地址。
            body: 响应体片段（截断 200 字符，用于排障）。
        """
        self.status_code = status_code
        self.url = url
        self.body = body[:200]
        super().__init__(f"HTTP {status_code} for {url}: {self.body}")


class HttpTransportError(HttpClientError):
    """网络层错误（连接失败、超时等）。"""


class _RetryableStatusError(HttpClientError):
    """内部信号：状态码可重试，用于驱动 tenacity 重试。"""

    def __init__(self, *, status_code: int, url: str) -> None:
        """构造内部可重试信号。

        Args:
            status_code: HTTP 状态码。
            url: 请求地址。
        """
        self.status_code = status_code
        self.url = url
        super().__init__(f"HTTP {status_code} for {url} (retryable)")


class HttpClient:
    """采集层统一 HTTP 客户端。

    Attributes:
        user_agent: 实际使用的 User-Agent。
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
        user_agent: str = DEFAULT_USER_AGENT,
        headers: dict[str, str] | None = None,
        proxy: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        follow_redirects: bool = True,
        retry_wait_min_s: float = 0.5,
        retry_wait_max_s: float = 8.0,
    ) -> None:
        """初始化客户端（不发起请求）。

        Args:
            base_url: 基础地址；传入后可用相对路径请求。
            timeout: 单次请求超时（秒）。
            max_retries: 最大尝试次数（含首次）。
            user_agent: User-Agent。
            headers: 额外默认请求头（同名时覆盖默认值）。
            proxy: 代理地址，如 ``http://127.0.0.1:7890``。
            transport: 自定义传输层（测试用 ``httpx.MockTransport``）。
            follow_redirects: 是否自动跟随 3xx。
            retry_wait_min_s: 退避等待下限（秒）。
            retry_wait_max_s: 退避等待上限（秒）。
        """
        self.user_agent = user_agent
        self._timeout = timeout
        self._max_retries = max(1, max_retries)
        self._retry_wait_min_s = retry_wait_min_s
        self._retry_wait_max_s = retry_wait_max_s
        default_headers: dict[str, str] = {"User-Agent": user_agent, "Accept": "application/json, */*"}
        if headers:
            default_headers.update(headers)
        self._client = httpx.AsyncClient(
            base_url=base_url or "",
            timeout=timeout,
            headers=default_headers,
            proxy=proxy,
            transport=transport,
            follow_redirects=follow_redirects,
        )

    @property
    def timeout(self) -> float:
        """当前请求超时（秒）。"""
        return self._timeout

    @property
    def raw_client(self) -> httpx.AsyncClient:
        """底层 ``httpx.AsyncClient``（仅供探活/调试等特殊场景使用）。"""
        return self._client

    async def __aenter__(self) -> HttpClient:
        """进入异步上下文。

        Returns:
            自身实例。
        """
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """退出异步上下文并释放连接。

        Args:
            *exc_info: 异常信息（未使用）。
        """
        await self.aclose()

    async def aclose(self) -> None:
        """关闭底层连接池。"""
        await self._client.aclose()

    def _log_retry(self, retry_state: Any) -> None:
        """记录一次重试（不泄露敏感信息）。

        Args:
            retry_state: tenacity 的重试状态对象。
        """
        outcome = getattr(retry_state, "outcome", None)
        exc = outcome.exception() if outcome is not None else None
        logger.warning(f"HTTP 重试 第{retry_state.attempt_number}次 原因={exc!r}")

    async def _attempt(self, method: str, url: str, kwargs: dict[str, Any]) -> httpx.Response:
        """执行单次请求，并把可重试状态码转成内部异常。

        Args:
            method: HTTP 方法。
            url: 请求地址。
            kwargs: 透传给 httpx 的参数。

        Returns:
            成功的响应对象（状态码 < 400）。

        Raises:
            _RetryableStatus: 命中可重试状态码。
            HttpStatusError: 命中不可重试的 4xx/5xx。
            HttpTransportError: 网络层错误。
        """
        try:
            response = await self._client.request(method, url, **kwargs)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            raise HttpTransportError(f"{method} {url} 失败：{exc}") from exc

        if response.status_code in RETRYABLE_STATUS:
            raise _RetryableStatusError(status_code=response.status_code, url=url)
        if response.status_code >= 400:
            raise HttpStatusError(status_code=response.status_code, url=url, body=response.text)
        return response


    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """发送请求（统一重试 + 超时）。

        Args:
            method: HTTP 方法（GET/POST/HEAD/...）。
            url: 绝对或相对地址。
            params: 查询参数。
            json_body: JSON 请求体。
            headers: 本次请求的额外请求头。
            **kwargs: 其它透传给 httpx 的参数。

        Returns:
            ``httpx.Response``（状态码 < 400）。

        Raises:
            HttpClientError: 重试耗尽后仍失败。
        """
        request_kwargs: dict[str, Any] = dict(kwargs)
        if params:
            request_kwargs["params"] = params
        if json_body is not None:
            request_kwargs["json"] = json_body
        if headers:
            request_kwargs["headers"] = headers

        retryer = AsyncRetrying(
            stop=stop_after_attempt(self._max_retries),
            wait=wait_exponential(multiplier=1.0, min=self._retry_wait_min_s, max=self._retry_wait_max_s),
            retry=retry_if_exception_type((_RetryableStatusError, HttpTransportError)),
            reraise=True,
            before_sleep=self._log_retry,
        )
        try:
            async for attempt in retryer:
                with attempt:
                    return await self._attempt(method, url, request_kwargs)
        except _RetryableStatusError as exc:  # 重试耗尽：转为对外异常
            raise HttpStatusError(status_code=exc.status_code, url=exc.url) from exc
        raise HttpClientError(f"{method} {url} 未产生响应")  # pragma: no cover - 逻辑兜底

    async def get_json(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """GET 并解析 JSON。

        Args:
            url: 请求地址。
            params: 查询参数。
            headers: 额外请求头。

        Returns:
            解析后的 JSON 对象（``dict`` / ``list``）。
        """
        response = await self.request("GET", url, params=params, headers=headers)
        return response.json()

    async def post_json(
        self,
        url: str,
        *,
        payload: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """POST JSON 并解析 JSON 响应。

        Args:
            url: 请求地址。
            payload: JSON 请求体。
            params: 查询参数。
            headers: 额外请求头。

        Returns:
            解析后的 JSON 对象。
        """
        response = await self.request("POST", url, params=params, json_body=payload, headers=headers)
        return response.json()

    async def get_text(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        """GET 并返回文本（用于 RSS / HTML / STIX）。

        Args:
            url: 请求地址。
            params: 查询参数。
            headers: 额外请求头。

        Returns:
            响应文本。
        """
        response = await self.request("GET", url, params=params, headers=headers)
        return response.text

    async def head_status(self, url: str, *, headers: dict[str, str] | None = None) -> int | None:
        """探活：返回状态码，失败时返回 ``None``（不抛异常）。

        Args:
            url: 探活地址。
            headers: 额外请求头。

        Returns:
            状态码；网络异常或状态码不可重试失败时返回 ``None``。
        """
        try:
            response = await self.request("HEAD", url, headers=headers)
        except HttpClientError:
            return None
        return response.status_code
