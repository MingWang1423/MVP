"""Day5 NVD 采集器单元测试（离线 fixture，不访问真实网络）。

覆盖：120 天窗口切分、分页、``max_records`` 提前止损、字段映射、Key 请求头与探活。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.nvd import NVD_API_URL, NvdConnector
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE = datetime(2024, 1, 1, tzinfo=UTC)
RECENT_SINCE = datetime.now(UTC) - timedelta(days=10)
"""近 10 天起点：只产生 1 个时间窗，便于精确断言请求次数。"""


def make_connector(http: HttpClient, **kwargs: Any) -> NvdConnector:
    """构造注入离线 HTTP 的 NVD 采集器。"""
    kwargs.setdefault("api_key", "unit-test-key")
    return NvdConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0), **kwargs)


class TestWindowAndFormat:
    """时间窗切分与格式化。"""

    def test_format_window(self) -> None:
        """时间统一格式化为 NVD 接受的 RFC3339（``Z`` 结尾）。"""
        assert NvdConnector.format_window(datetime(2024, 1, 1, 12, 30)) == "2024-01-01T12:30:00.000Z"

    def test_split_windows_under_limit(self) -> None:
        """250 天 → 3 个窗口（120 + 120 + 10），且首尾无缝衔接。"""
        since = datetime(2024, 1, 1, tzinfo=UTC)
        windows = NvdConnector(api_key="").split_windows(since, since + timedelta(days=250))
        assert len(windows) == 3
        assert windows[0] == (since, since + timedelta(days=120))
        assert windows[1][0] == windows[0][1]
        assert windows[-1][1] == since + timedelta(days=250)

    def test_split_windows_empty(self) -> None:
        """``since >= until`` 时返回空列表。"""
        moment = datetime(2024, 1, 1, tzinfo=UTC)
        assert NvdConnector(api_key="").split_windows(moment, moment) == []
        assert NvdConnector(api_key="").split_windows(moment, moment - timedelta(days=1)) == []


class TestApiKey:
    """API Key 与限流档位。"""

    async def test_headers_without_key(self, mock_http: HttpClient) -> None:
        """无 Key → 不带 ``apiKey`` 头，且仍可采集（限流档位由 RateLimiter 测试覆盖）。"""
        connector = make_connector(mock_http, api_key="")
        assert connector.has_api_key is False
        assert connector._headers() == {}
        assert connector.enabled is True

    async def test_headers_with_key(self, mock_http: HttpClient) -> None:
        """有 Key → 带 ``apiKey`` 头。"""
        connector = make_connector(mock_http)
        assert connector.has_api_key is True
        assert connector._headers() == {"apiKey": "unit-test-key"}

    async def test_non_ascii_key_is_ignored(self, mock_http: HttpClient) -> None:
        """Key 含非 ASCII（.env 行内注释常见）时不发送，避免请求头编码错误。"""
        connector = make_connector(mock_http, api_key="abc 中文注释")
        assert connector.has_api_key is False
        assert connector._headers() == {}


class TestFetchIncremental:
    """增量采集行为。"""

    async def test_fetches_and_maps(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """单页响应 → 2 条 ``RawItem``，按发布时间倒序。"""
        mock_router.always(NVD_API_URL, json_body=load_fixture("nvd_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(RECENT_SINCE)
        assert [item.source_id for item in items] == ["CVE-2024-3400", "CVE-2021-44228"]

    async def test_period_and_paging_params_sent(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """请求携带 ``lastModStartDate`` / ``lastModEndDate`` 与分页参数。"""
        mock_router.always(NVD_API_URL, json_body=load_fixture("nvd_sample.json"))
        await make_connector(mock_http, page_size=100).fetch_incremental(RECENT_SINCE)
        url = str(mock_router.calls[0].url)
        assert "lastModStartDate=" in url
        assert "lastModEndDate=" in url
        assert "resultsPerPage=100" in url

    async def test_field_mapping(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """``url`` / ``published_at`` / ``meta`` 映射正确（整条记录保真保存）。"""
        mock_router.always(NVD_API_URL, json_body=load_fixture("nvd_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(RECENT_SINCE)
        item = next(entry for entry in items if entry.source_id == "CVE-2024-3400")
        assert item.source == "nvd"
        assert item.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"
        assert item.published_at == datetime(2024, 4, 12, 7, 15, 7, 763000, tzinfo=UTC)
        assert item.meta["severity"] == "CRITICAL"
        assert item.meta["status"] == "Analyzed"
        assert "CVSS:3.1" in item.raw_text  # 供 L2 抽取 CVSS / CWE / CPE

    async def test_pagination_until_total(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """按 ``totalResults`` 翻页并去重（第 2 页重复的 CVE 只保留一条）。"""
        page = load_fixture("nvd_sample.json")
        first = {**page, "resultsPerPage": 2, "startIndex": 0, "totalResults": 3}
        second = {
            **page,
            "resultsPerPage": 2,
            "startIndex": 2,
            "totalResults": 3,
            "vulnerabilities": [page["vulnerabilities"][1]],
        }
        mock_router.add(NVD_API_URL, json_body=first)
        mock_router.add(NVD_API_URL, json_body=second)
        mock_router.always(NVD_API_URL, json_body={**page, "vulnerabilities": [], "totalResults": 3})
        items = await make_connector(mock_http, page_size=2, max_pages=5).fetch_incremental(RECENT_SINCE)
        assert [item.source_id for item in items] == ["CVE-2024-3400", "CVE-2021-44228"]
        assert mock_router.call_count(NVD_API_URL) == 2

    async def test_max_records_stops_early(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """``max_records`` 达到即停止翻页（只请求 1 页）。"""
        mock_router.always(NVD_API_URL, json_body=load_fixture("nvd_sample.json"))
        items = await make_connector(mock_http, max_records=1).fetch_incremental(RECENT_SINCE)
        assert len(items) == 2  # 单页已超上限，本页结果仍保留
        assert mock_router.call_count(NVD_API_URL) == 1

    async def test_invalid_payload_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """``vulnerabilities`` 非数组时报错。"""
        mock_router.always(NVD_API_URL, json_body={"vulnerabilities": {"a": 1}})
        with pytest.raises(ValueError, match="不是数组"):
            await make_connector(mock_http).fetch_incremental(SINCE)

    async def test_missing_cve_id_raises(self, mock_http: HttpClient) -> None:
        """条目缺少 ``cve.id`` 时报错。"""
        with pytest.raises(ValueError, match="cve.id"):
            make_connector(mock_http).vuln_to_raw_item({"cve": {"descriptions": []}})


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """按 ``cveId`` 查询成功 → True。"""
        mock_router.always(NVD_API_URL, json_body=load_fixture("nvd_sample.json"))
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源不可用时返回 False 而不抛异常。"""
        mock_router.always(NVD_API_URL, status_code=503, text="unavailable")
        assert await make_connector(mock_http).health_check() is False

    def test_class_defaults(self) -> None:
        """类级默认值符合约定（窗口 ≤120 天）。"""
        assert NvdConnector.source_name == "nvd"
        assert NvdConnector.api_url == NVD_API_URL
        assert NvdConnector.window_days <= 120
