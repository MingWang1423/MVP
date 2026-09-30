"""pytest 共享 fixture（PROJECT_PLAN.md §5.2 P1 / Day3 任务 7）。

提供三类可复用设施：

1. :class:`MockRouter` + ``mock_http``：基于 ``httpx.MockTransport`` 的离线 HTTP 桩，
   支持「同一 URL 依次返回多个响应」（用于重试测试），并记录调用次数；
2. ``memory_engine`` / ``db_session``：SQLite 内存库引擎与会话（不依赖 PostgreSQL）；
3. ``sample_raw_item`` / ``kev_payload``：跨用例复用的样例数据。

Note:
    存储相关 fixture 采用**延迟导入** + ``importorskip``：即使环境缺少 SQLAlchemy，
    其余测试也能正常收集运行。
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem

FIXTURES_DIR: Path = Path(__file__).parent / "fixtures"
"""离线样例数据目录（§2 目录结构）。"""


def _normalize_url(url: str) -> str:
    """把 URL 归一化为「协议+主机+路径」（丢弃查询串），用于路由匹配。

    Args:
        url: 原始 URL。

    Returns:
        不含查询串的 URL。
    """
    return url.split("?", 1)[0]


class MockRouter:
    """把 URL 映射到预置响应，供 ``httpx.MockTransport`` 使用。

    Attributes:
        calls: 按时间顺序记录的请求列表。
    """

    def __init__(self) -> None:
        """初始化空路由表。"""
        self._routes: dict[str, list[httpx.Response]] = {}
        self._default: dict[str, httpx.Response] = {}
        self.calls: list[httpx.Request] = []

    def add(
        self,
        url: str,
        *,
        status_code: int = 200,
        json_body: Any = None,
        text: str | None = None,
        times: int = 1,
        headers: dict[str, str] | None = None,
    ) -> MockRouter:
        """登记一个响应（``times`` 次，按顺序消费）。

        Args:
            url: 完整 URL（**忽略查询串**，与请求地址按路径匹配）。
            status_code: HTTP 状态码。
            json_body: JSON 响应体（与 ``text`` 二选一）。
            text: 文本响应体。
            times: 该响应可被返回的次数。
            headers: 响应头。

        Returns:
            自身实例（支持链式登记）。
        """
        if json_body is not None:
            response = httpx.Response(status_code, json=json_body, headers=headers)
        else:
            response = httpx.Response(status_code, text=text or "", headers=headers)
        bucket = self._routes.setdefault(_normalize_url(url), [])
        bucket.extend([response] * max(1, times))
        return self

    def always(
        self,
        url: str,
        *,
        status_code: int = 200,
        json_body: Any = None,
        text: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> MockRouter:
        """登记一个**始终返回**的响应（不限次数）。

        Args:
            url: 完整 URL（**忽略查询串**）。
            status_code: HTTP 状态码。
            json_body: JSON 响应体。
            text: 文本响应体。
            headers: 响应头。

        Returns:
            自身实例。
        """
        if json_body is not None:
            self._default[_normalize_url(url)] = httpx.Response(status_code, json=json_body, headers=headers)
        else:
            self._default[_normalize_url(url)] = httpx.Response(status_code, text=text or "", headers=headers)
        return self

    def handler(self, request: httpx.Request) -> httpx.Response:
        """``httpx.MockTransport`` 的处理函数。

        Args:
            request: 待处理的请求。

        Returns:
            预置响应；未登记时返回 404。
        """
        self.calls.append(request)
        key = _normalize_url(str(request.url))
        bucket = self._routes.get(key)
        if bucket:
            return bucket.pop(0)
        if key in self._default:
            return self._default[key]
        return httpx.Response(404, text=f"未登记的 URL：{key}")

    def call_count(self, url: str) -> int:
        """返回某 URL 的调用次数（忽略查询串）。

        Args:
            url: 完整 URL。

        Returns:
            调用次数。
        """
        key = _normalize_url(url)
        return sum(1 for request in self.calls if _normalize_url(str(request.url)) == key)

    @property
    def pending(self) -> int:
        """尚未消费的预置响应数量（应保持为 0 才能证明重试次数符合预期）。"""
        return sum(len(bucket) for bucket in self._routes.values())


@pytest.fixture()
def mock_router() -> MockRouter:
    """提供空的 HTTP 路由桩。"""
    return MockRouter()


@pytest.fixture()
def mock_transport(mock_router: MockRouter) -> httpx.MockTransport:
    """提供绑定到 ``mock_router`` 的 httpx 传输层。"""
    return httpx.MockTransport(mock_router.handler)


@pytest.fixture()
async def mock_http(mock_transport: httpx.MockTransport) -> AsyncIterator[HttpClient]:
    """提供离线 ``HttpClient``（禁用退避等待，测试无需真实 sleep）。"""
    client = HttpClient(transport=mock_transport, retry_wait_min_s=0.0, retry_wait_max_s=0.0)
    yield client
    await client.aclose()


@pytest.fixture()
async def memory_engine() -> AsyncIterator[Any]:
    """提供已建表的 SQLite 内存库引擎（不依赖 PostgreSQL）。"""
    pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install 'sqlalchemy[asyncio]' aiosqlite")
    pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")
    from aisec_intel.storage.database import create_engine, init_models

    engine = create_engine("sqlite+aiosqlite:///:memory:")
    await init_models(engine)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def db_session(memory_engine: Any) -> AsyncIterator[Any]:
    """提供绑定到内存库的异步会话。"""
    from aisec_intel.storage.database import create_session_factory

    factory = create_session_factory(memory_engine)
    async with factory() as session:
        yield session


@pytest.fixture()
def sample_raw_item() -> RawItem:
    """提供一条合法的 ``RawItem``（内容与 KEV fixture 中 CVE-2024-3400 对应）。"""
    return RawItem(
        trace_id=new_trace_id(),
        source="kev",
        source_id="CVE-2024-3400",
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        title="Palo Alto Networks PAN-OS Command Injection Vulnerability",
        raw_text='{"cveID":"CVE-2024-3400","dateAdded":"2024-04-12"}',
        lang="en",
        published_at=utc_now(),
        fetched_at=utc_now(),
        sha256="a" * 64,
        meta={"vendorProject": "Palo Alto Networks", "product": "PAN-OS"},
    )


@pytest.fixture()
def kev_payload() -> dict[str, Any]:
    """读取 ``tests/fixtures/kev_sample.json``（真实 KEV 结构，含 5 条记录）。"""
    return json.loads((FIXTURES_DIR / "kev_sample.json").read_text(encoding="utf-8"))


@pytest.fixture()
def sample_json_path() -> Iterator[Path]:
    """提供 fixture 目录路径（便于按文件名加载）。"""
    yield FIXTURES_DIR
