"""Day3 KEV 采集器测试（PROJECT_PLAN.md §5.3）。

全部用例基于 ``tests/fixtures/kev_sample.json`` + ``httpx.MockTransport``，**不访问真实网络**。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.kev import KEV_CATALOG_URL, NVD_DETAIL_URL_TEMPLATE, KevConnector
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE_2024 = datetime(2024, 1, 1, tzinfo=UTC)
SINCE_2020 = datetime(2020, 1, 1, tzinfo=UTC)


def make_connector(http: HttpClient) -> KevConnector:
    """构造注入了离线 HTTP 的 KEV 采集器。"""
    return KevConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0))


class TestFetchIncremental:
    """``fetch_incremental`` 增量过滤与字段映射。"""

    async def test_filters_by_date_added(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """只返回 ``dateAdded >= since`` 的条目（fixture 中 3 条属于 2024 年）。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        assert [item.source_id for item in items] == ["CVE-2024-3400", "CVE-2024-3094", "CVE-2024-1709"]

    async def test_returns_all_when_since_is_old(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``since`` 足够早时返回全部条目，并按 ``dateAdded`` 倒序。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2020)
        assert len(items) == 5
        assert items[0].source_id == "CVE-2024-3400"
        assert items[-1].source_id == "CVE-2021-44228"

    async def test_raw_item_field_mapping(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``RawItem`` 的源标识 / 链接 / 标题 / 时间 / meta 均正确映射。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        first = items[0]
        assert first.source == "kev"
        assert first.source_id == "CVE-2024-3400"
        assert first.url == NVD_DETAIL_URL_TEMPLATE.format(cve_id="CVE-2024-3400")
        assert first.title == "Palo Alto Networks PAN-OS Command Injection Vulnerability"
        assert first.published_at == datetime(2024, 4, 12, tzinfo=UTC)
        assert first.lang == "en"
        assert first.meta["vendorProject"] == "Palo Alto Networks"
        assert first.meta["product"] == "PAN-OS"
        assert first.meta["dateAdded"] == "2024-04-12"
        assert first.meta["cwes"] == "CWE-77"

    async def test_raw_text_keeps_original_entry(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``raw_text`` 保存条目级保真 JSON，便于按条回溯。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        entry = json.loads(items[0].raw_text)
        assert entry["cveID"] == "CVE-2024-3400"
        assert entry["dueDate"] == "2024-04-19"

    async def test_fingerprint_is_stable_across_runs(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """同一数据的指纹稳定 → 重复采集可被去重。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        connector = make_connector(mock_http)
        first = {item.source_id: item.sha256 for item in await connector.fetch_incremental(SINCE_2024)}
        second = {item.source_id: item.sha256 for item in await connector.fetch_incremental(SINCE_2024)}
        assert first == second

    async def test_skips_non_dict_entries(self, mock_router: Any, mock_http: HttpClient) -> None:
        """目录中混入非对象条目时跳过而不是崩溃。"""
        payload = {
            "vulnerabilities": [
                "not-an-object",
                {"cveID": "CVE-2024-9999", "dateAdded": "2024-05-01", "vulnerabilityName": "X"},
            ]
        }
        mock_router.always(KEV_CATALOG_URL, json_body=payload)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        assert [item.source_id for item in items] == ["CVE-2024-9999"]

    async def test_invalid_payload_type_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """目录不是 JSON 对象时报错（源侧结构变更需显式暴露）。"""
        mock_router.always(KEV_CATALOG_URL, json_body=[1, 2, 3])
        with pytest.raises(ValueError, match="结构异常"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)

    async def test_invalid_vulnerabilities_type_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """``vulnerabilities`` 不是数组时报错。"""
        mock_router.always(KEV_CATALOG_URL, json_body={"vulnerabilities": {"a": 1}})
        with pytest.raises(ValueError, match="不是数组"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)


class TestEntryMapping:
    """单条条目映射的边界情况。"""

    async def test_missing_cve_id_raises(self, mock_http: HttpClient) -> None:
        """缺少 ``cveID`` 的条目必须报错（不能写入无主键数据）。"""
        with pytest.raises(ValueError, match="cveID"):
            make_connector(mock_http).entry_to_raw_item({"dateAdded": "2024-04-12"})

    async def test_unparsable_date_yields_none(self, mock_http: HttpClient) -> None:
        """日期不可解析时 ``published_at`` 为 ``None``（不阻断入库）。"""
        item = make_connector(mock_http).entry_to_raw_item({"cveID": "CVE-2024-0001", "dateAdded": "bad-date"})
        assert item.published_at is None

    async def test_entry_without_due_date(self, mock_http: HttpClient) -> None:
        """缺失可选字段时 ``meta`` 只保留存在的键。"""
        item = make_connector(mock_http).entry_to_raw_item({"cveID": "CVE-2024-0002", "dateAdded": "2024-05-01"})
        assert "dueDate" not in item.meta
        assert item.meta["dateAdded"] == "2024-05-01"

    async def test_source_url_is_catalog(self, mock_http: HttpClient) -> None:
        """``source_url`` 指向 KEV 目录（``url`` 缺省回退值）。"""
        assert make_connector(mock_http).source_url == KEV_CATALOG_URL


class TestFetchCves:
    """按 CVE 从目录精确取条目（Day7 前置：``--cve`` 通道）。"""

    async def test_hits_single_cve(self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient) -> None:
        """只返回请求的 CVE（夹具含 5 条，仅 3 条属于 2024 年）。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        items = await make_connector(mock_http).fetch_cves(["CVE-2021-44228"])
        assert [item.source_id for item in items] == ["CVE-2021-44228"]

    async def test_hits_multiple_cves(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """多编号命中多条，且只请求一次目录。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        items = await make_connector(mock_http).fetch_cves(["CVE-2024-3400", "cve-2024-3094"])
        assert sorted(item.source_id for item in items) == ["CVE-2024-3094", "CVE-2024-3400"]
        assert mock_router.call_count(KEV_CATALOG_URL) == 1

    async def test_unknown_cve_returns_empty(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """目录中不存在时返回空列表（不报错）。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        assert await make_connector(mock_http).fetch_cves(["CVE-1999-0001"]) == []

    async def test_empty_input_raises(self, mock_http: HttpClient) -> None:
        """空编号列表显式报错。"""
        with pytest.raises(ValueError, match="至少一个 CVE"):
            await make_connector(mock_http).fetch_cves([])

    async def test_invalid_catalog_structure_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """目录结构异常时报错。"""
        mock_router.always(KEV_CATALOG_URL, json_body={"vulnerabilities": {"a": 1}})
        with pytest.raises(ValueError, match="不是数组"):
            await make_connector(mock_http).fetch_cves(["CVE-2024-3400"])


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(
        self, kev_payload: dict[str, Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """HTTP 200 时返回 ``True``。"""
        mock_router.always(KEV_CATALOG_URL, json_body=kev_payload)
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_is_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源不可用（404）时返回 ``False`` 而不抛异常。"""
        mock_router.always(KEV_CATALOG_URL, status_code=404, text="not found")
        assert await make_connector(mock_http).health_check() is False

    def test_class_defaults(self) -> None:
        """类级默认值符合 §5.3 约定。"""
        assert KevConnector.source_name == "kev"
        assert KevConnector.rate_limit == "10/1"
        assert KevConnector.timeout == 60.0
