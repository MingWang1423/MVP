"""Day4 OSV 采集器测试（离线 fixture，不访问真实网络）。

覆盖：按包查询、增量过滤、字段映射、跨包去重、探活、异常结构兜底。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.osv import (
    HEALTH_CHECK_VULN_ID,
    OSV_QUERY_URL,
    OSV_VULN_URL_TEMPLATE,
    OsvConnector,
)
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE_2024 = datetime(2024, 1, 1, tzinfo=UTC)
SINCE_2025 = datetime(2025, 1, 1, tzinfo=UTC)


def make_connector(http: HttpClient, *, packages: tuple[str, ...] = ("langchain", "transformers")) -> OsvConnector:
    """构造注入离线 HTTP 的 OSV 采集器。"""
    return OsvConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0), packages=packages)


class TestQueryPackage:
    """按包查询行为。"""

    async def test_posts_package_payload(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """请求体包含 ``package.name`` 与 ``PyPI`` 生态。"""
        mock_router.always(OSV_QUERY_URL, json_body=load_fixture("osv_sample.json"))
        await make_connector(mock_http).query_package("langchain")
        body = mock_router.calls[-1].content.decode("utf-8").replace(" ", "")
        assert '"name":"langchain"' in body
        assert "PyPI" in body

    async def test_invalid_response_shape_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """响应不是对象时报错（源侧变更需显式暴露）。"""
        mock_router.always(OSV_QUERY_URL, json_body=[1, 2, 3])
        with pytest.raises(ValueError, match="结构异常"):
            await make_connector(mock_http).query_package("langchain")

    async def test_vulns_must_be_list(self, mock_router: Any, mock_http: HttpClient) -> None:
        """``vulns`` 不是数组时报错。"""
        mock_router.always(OSV_QUERY_URL, json_body={"vulns": {"a": 1}})
        with pytest.raises(ValueError, match="不是数组"):
            await make_connector(mock_http).query_package("langchain")


class TestFetchIncremental:
    """增量采集与字段映射。"""

    async def test_filters_by_modified(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """按 ``modified`` 过滤：since=2024 命中 2 条，since=2025 命中 0 条。"""
        mock_router.always(OSV_QUERY_URL, json_body=load_fixture("osv_sample.json"))
        connector = make_connector(mock_http)
        items = await connector.fetch_incremental(SINCE_2024)
        assert {item.source_id for item in items} == {"GHSA-3hjh-jh2g-v3gj", "PYSEC-2024-115"}
        assert await connector.fetch_incremental(SINCE_2025) == []

    async def test_dedupes_and_orders(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """跨包重复条目只保留一条，并按发布时间倒序。"""
        mock_router.always(OSV_QUERY_URL, json_body=load_fixture("osv_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        assert len(items) == 2
        published = [item.published_at for item in items]
        assert published == sorted(published, reverse=True)

    async def test_field_mapping(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """``source`` / ``url`` / ``published_at`` / ``meta`` 映射正确。"""
        mock_router.always(OSV_QUERY_URL, json_body=load_fixture("osv_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        item = next(entry for entry in items if entry.source_id == "GHSA-3hjh-jh2g-v3gj")
        assert item.source == "osv"
        assert item.url.endswith("CVE-2024-28088")  # 有 CVE 别名时指向 NVD
        assert item.published_at == datetime(2024, 3, 15, tzinfo=UTC)
        assert item.meta["ecosystem"] == "PyPI"
        assert "langchain" in item.meta["packages"]
        assert "CVE-2024-28088" in item.meta["aliases"]


    async def test_url_falls_back_to_osv_page(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """无 CVE 别名时使用 OSV 详情页。"""
        mock_router.always(OSV_QUERY_URL, json_body=load_fixture("osv_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        item = next(entry for entry in items if entry.source_id == "PYSEC-2024-115")
        assert item.url.endswith("/vulnerability/PYSEC-2024-115")

    async def test_single_package_failure_does_not_break_run(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """单包失败被吞掉，其余包继续采集。"""
        mock_router.add(OSV_QUERY_URL, status_code=500, text="boom")
        mock_router.always(OSV_QUERY_URL, json_body=load_fixture("osv_sample.json"))
        items = await make_connector(mock_http, packages=("vllm", "langchain")).fetch_incremental(SINCE_2024)
        assert len(items) == 2

    async def test_missing_id_raises(self, mock_http: HttpClient) -> None:
        """条目缺少 ``id`` 时报错。"""
        with pytest.raises(ValueError, match="缺少 id"):
            make_connector(mock_http).vuln_to_raw_item({"summary": "x"})


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(self, mock_router: Any, mock_http: HttpClient) -> None:
        """GET 一条长期存在的漏洞返回 200 → True。"""
        mock_router.always(OSV_VULN_URL_TEMPLATE.format(vuln_id=HEALTH_CHECK_VULN_ID), json_body={"id": "x"})
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源不可用时返回 False 而不抛异常。"""
        mock_router.always(OSV_VULN_URL_TEMPLATE.format(vuln_id=HEALTH_CHECK_VULN_ID), status_code=404, text="no")
        assert await make_connector(mock_http).health_check() is False

    def test_default_packages_from_settings(self) -> None:
        """未显式指定包时使用 ``Settings.watchlist``（默认 5 个 AI/ML 包）。"""
        connector = OsvConnector(packages=None)
        assert connector.packages == ["vllm", "ollama", "transformers", "langchain", "torch"]
