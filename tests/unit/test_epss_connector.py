"""Day4 EPSS 采集器测试（离线 fixture，不访问真实网络）。

覆盖：按日快照增量、按 CVE 精确查询、字段映射、探活与异常结构兜底。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.epss import EPSS_API_URL, EpssConnector
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE_2024 = datetime(2024, 1, 1, tzinfo=UTC)


def make_connector(http: HttpClient, **kwargs: Any) -> EpssConnector:
    """构造注入离线 HTTP 的 EPSS 采集器。"""
    return EpssConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0), **kwargs)


class TestFetchIncremental:
    """增量与字段映射。"""

    async def test_filters_rows_by_model_date(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """只保留 ``date >= since.date()`` 的行（fixture 中 2023 那行被过滤）。"""
        mock_router.always(EPSS_API_URL, json_body=load_fixture("epss_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        assert [item.source_id for item in items] == ["CVE-2021-44228", "CVE-2024-3400"]

    async def test_request_params_include_date_and_limit(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """按日快照模式请求携带 ``date`` 与 ``limit``。"""
        mock_router.always(EPSS_API_URL, json_body=load_fixture("epss_sample.json"))
        await make_connector(mock_http, page_limit=50).fetch_incremental(SINCE_2024)
        url = str(mock_router.calls[-1].url)
        assert "date=2024-01-01" in url
        assert "limit=50" in url

    async def test_cve_mode_uses_cve_param(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """精确查询模式使用 ``cve`` 参数且不带 ``date``。"""
        mock_router.always(EPSS_API_URL, json_body=load_fixture("epss_sample.json"))
        connector = make_connector(mock_http, cve_ids=["cve-2024-3400"])
        await connector.fetch_incremental(SINCE_2024)
        url = str(mock_router.calls[-1].url)
        assert "cve=CVE-2024-3400" in url
        assert "date=" not in url

    async def test_field_mapping(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """``source`` / ``url`` / ``published_at`` / ``meta`` 映射正确。"""
        mock_router.always(EPSS_API_URL, json_body=load_fixture("epss_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        item = next(entry for entry in items if entry.source_id == "CVE-2024-3400")
        assert item.source == "epss"
        assert "CVE-2024-3400" in item.url
        assert item.published_at == datetime(2024, 4, 15, tzinfo=UTC)
        assert item.meta["epss"] == "0.97432"
        assert item.meta["percentile"] == "0.99912"
        assert item.meta["model_date"] == "2024-04-15"

    async def test_missing_cve_raises(self, mock_http: HttpClient) -> None:
        """行内缺少 ``cve`` 时报错。"""
        with pytest.raises(ValueError, match="缺少 cve"):
            make_connector(mock_http).row_to_raw_item({"epss": "0.1"})

    async def test_invalid_response_shape_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """响应不是对象时报错。"""
        mock_router.always(EPSS_API_URL, json_body="not-an-object")
        with pytest.raises(ValueError, match="结构异常"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)

    async def test_data_must_be_list(self, mock_router: Any, mock_http: HttpClient) -> None:
        """``data`` 不是数组时报错。"""
        mock_router.always(EPSS_API_URL, json_body={"data": {"a": 1}})
        with pytest.raises(ValueError, match="不是数组"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(self, mock_router: Any, mock_http: HttpClient) -> None:
        """查询长期存在的 CVE 返回 200 → True。"""
        mock_router.always("https://api.first.org/data/v1/epss?cve=CVE-2021-44228", status_code=200, text="{}")
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源不可用时返回 False 而不抛异常。"""
        mock_router.always("https://api.first.org/data/v1/epss?cve=CVE-2021-44228", status_code=500, text="boom")
        assert await make_connector(mock_http).health_check() is False

    def test_class_defaults(self) -> None:
        """类级默认值符合约定。"""
        assert EpssConnector.source_name == "epss"
        assert EpssConnector.rate_limit == "10/1"
        assert EpssConnector.api_url == EPSS_API_URL
