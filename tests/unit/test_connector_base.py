"""Day3 ``BaseConnector`` 与注册表测试（PROJECT_PLAN.md §5.3）。

要点：抽象契约、统一构造（trace_id / fetched_at / sha256）、默认 ``normalize()`` 行为、
时间归一化，以及 ``@register`` 注册表语义。
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest

from aisec_intel.connectors.base import BaseConnector
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.rate_limiter import RateLimiter
from aisec_intel.connectors.registry import (
    UnknownSourceError,
    available_sources,
    create_connector,
    get_connector_class,
    register,
)
from aisec_intel.models.raw_item import RawItem
from aisec_intel.utils.hashing import sha256_text


class DummyConnector(BaseConnector):
    """最小可用采集器（不注册，避免污染全局注册表）。"""

    source_name = "dummy"
    rate_limit = "1000/1"
    timeout = 5.0

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """返回空列表（契约测试不需要真实数据）。"""
        return []

    async def health_check(self) -> bool:
        """始终可用。"""
        return True


def make_limiter() -> RateLimiter:
    """构造高速率限流器（测试无需等待）。"""
    return RateLimiter(rate=1000.0, burst=1000.0)


class TestAbstractContract:
    """抽象基类契约。"""

    def test_base_is_abstract(self) -> None:
        """``BaseConnector`` 不可直接实例化。"""
        with pytest.raises(TypeError):
            BaseConnector()  # type: ignore[abstract]

    def test_missing_source_name_rejected(self) -> None:
        """子类未声明 ``source_name`` 时构造失败。"""

        class NoName(BaseConnector):
            async def fetch_incremental(self, since: datetime) -> list[RawItem]:
                return []

            async def health_check(self) -> bool:
                return True

        with pytest.raises(ValueError, match="source_name"):
            NoName()

    async def test_describe_and_properties(self, mock_http: HttpClient) -> None:
        """``describe()`` 输出运维元信息，属性可读。"""
        async with DummyConnector(http=mock_http, limiter=make_limiter()) as connector:
            info = connector.describe()
            assert info["source"] == "dummy"
            assert info["rate_limit"] == "1000/1"
            assert info["timeout"] == 5.0
            assert info["enabled"] is True
            assert connector.source == "dummy"
            assert connector.settings is not None
            assert "(dummy-collector)" in connector.user_agent

    async def test_injected_client_is_not_closed(self, mock_http: HttpClient) -> None:
        """注入的 HTTP 客户端由调用方管理，``aclose()`` 不应关闭它。"""
        connector = DummyConnector(http=mock_http, limiter=make_limiter())
        await connector.aclose()
        assert mock_http.raw_client is not None


class TestBuildRawItem:
    """统一构造行为。"""

    async def test_auto_generated_fields(self, mock_http: HttpClient) -> None:
        """``trace_id`` / ``fetched_at`` / ``sha256`` / ``url`` 自动生成。"""
        connector = DummyConnector(http=mock_http, limiter=make_limiter())
        item = connector.build_raw_item(source_id="CVE-2024-3400", raw_text="hello")
        assert item.source == "dummy"
        assert item.source_id == "CVE-2024-3400"
        assert len(item.trace_id) == 32
        assert item.sha256 == sha256_text("hello")
        assert item.fetched_at.tzinfo == UTC
        assert item.url == connector.source_url

    async def test_explicit_trace_id_is_preserved(self, mock_http: HttpClient) -> None:
        """显式 ``trace_id`` 优先（链路接续场景）。"""
        connector = DummyConnector(http=mock_http, limiter=make_limiter())
        item = connector.build_raw_item(source_id="X", raw_text="t", trace_id="trace-fixed")
        assert item.trace_id == "trace-fixed"

    async def test_normalize_default_impl(self, mock_http: HttpClient) -> None:
        """默认 ``normalize()`` 透传标准字段，未识别键扁平化写入 ``meta``。"""
        connector = DummyConnector(http=mock_http, limiter=make_limiter())
        item = connector.normalize(
            {
                "source_id": "CVE-2024-3400",
                "raw_text": '{"a":1}',
                "url": "https://example.test/1",
                "title": "示例",
                "published_at": "2024-04-12",
                "lang": "en",
                "vendorProject": "Palo Alto Networks",
                "cwes": ["CWE-77"],
            }
        )
        assert item.source_id == "CVE-2024-3400"
        assert item.published_at == datetime(2024, 4, 12, tzinfo=UTC)
        assert item.meta["vendorProject"] == "Palo Alto Networks"
        assert item.meta["cwes"] == '["CWE-77"]'

    async def test_normalize_missing_required_fields(self, mock_http: HttpClient) -> None:
        """缺少 ``source_id`` / ``raw_text`` 时报错。"""
        connector = DummyConnector(http=mock_http, limiter=make_limiter())
        with pytest.raises(ValueError, match="缺少必需字段"):
            connector.normalize({"source_id": "X"})


class TestTimeUtils:
    """时间归一化工具测试。"""

    def test_date_and_naive_and_iso(self) -> None:
        """``date`` / naive ``datetime`` / ISO 字符串均归一化为 UTC。"""
        assert BaseConnector.to_utc_datetime(date(2024, 4, 12)) == datetime(2024, 4, 12, tzinfo=UTC)
        assert BaseConnector.to_utc_datetime(datetime(2024, 4, 12, 10, 0)) == datetime(2024, 4, 12, 10, 0, tzinfo=UTC)
        assert BaseConnector.to_utc_datetime("2024-04-12T10:00:00Z") == datetime(2024, 4, 12, 10, 0, tzinfo=UTC)

    def test_aware_datetime_converted(self) -> None:
        """带时区的时间被换算到 UTC。"""
        aware = datetime(2024, 4, 12, 20, 0, tzinfo=timezone(timedelta(hours=8)))
        assert BaseConnector.to_utc_datetime(aware) == datetime(2024, 4, 12, 12, 0, tzinfo=UTC)
        assert BaseConnector.to_utc_datetime("2024-04-12T18:00:00+08:00") == datetime(2024, 4, 12, 10, 0, tzinfo=UTC)

    def test_unparsable_returns_none(self) -> None:
        """无法解析时返回 ``None`` 而不是抛异常（采集不得因脏数据中断）。"""
        assert BaseConnector.to_utc_datetime("not-a-date") is None
        assert BaseConnector.to_utc_datetime(None) is None
        assert BaseConnector.to_utc_datetime("") is None

    async def test_raw_text_from_json_is_deterministic(self, mock_http: HttpClient) -> None:
        """同一对象的序列化结果稳定（保证 sha256 可复现）。"""
        connector = DummyConnector(http=mock_http, limiter=make_limiter())
        first = connector.raw_text_from_json({"b": 1, "a": [2, 3]})
        second = connector.raw_text_from_json({"a": [2, 3], "b": 1})
        assert first == second


class TestRegistry:
    """注册表语义。"""

    def test_kev_is_registered(self) -> None:
        """导入 connectors 包即完成 KEV 自注册。"""
        assert "kev" in available_sources()
        assert get_connector_class("kev").source_name == "kev"

    def test_lookup_is_case_insensitive(self) -> None:
        """源标识查询大小写与空白不敏感。"""
        assert get_connector_class(" KEV ").source_name == "kev"

    def test_unknown_source_raises(self) -> None:
        """未注册源抛出 ``UnknownSourceError``。"""
        with pytest.raises(UnknownSourceError, match="未注册的源"):
            get_connector_class("nvd-not-yet")

    def test_duplicate_registration_rejected(self) -> None:
        """同一源标识重复注册会报错（防止静默覆盖）。"""
        with pytest.raises(ValueError, match="禁止重复注册"):

            @register
            class DuplicateKev(BaseConnector):
                source_name = "kev"

                async def fetch_incremental(self, since: datetime) -> list[RawItem]:
                    return []

                async def health_check(self) -> bool:
                    return True

    def test_register_requires_source_name(self) -> None:
        """注册未声明 ``source_name`` 的类会报错。"""
        with pytest.raises(ValueError, match="source_name"):

            @register
            class Nameless(BaseConnector):
                async def fetch_incremental(self, since: datetime) -> list[RawItem]:
                    return []

                async def health_check(self) -> bool:
                    return True

    async def test_create_connector_returns_instance(self) -> None:
        """``create_connector`` 返回可用实例（注入默认限流与 HTTP 客户端）。"""
        connector: Any = create_connector("kev")
        try:
            assert isinstance(connector, BaseConnector)
            assert connector.describe()["source"] == "kev"
        finally:
            await connector.aclose()
