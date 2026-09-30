"""Day6 arXiv 采集器测试（PROJECT_PLAN.md §5.5 P4 任务 4）。

全部用例基于 ``tests/fixtures/arxiv_sample.xml`` + ``httpx.MockTransport``，**不访问真实网络**。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.arxiv import ARXIV_API_URL, ArxivConnector, split_arxiv_id
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE_2024 = datetime(2024, 1, 1, tzinfo=UTC)
SINCE_2020 = datetime(2020, 1, 1, tzinfo=UTC)

MALFORMED_XML = "<feed><entry><id>http://arxiv.org/abs/2404.99999v1</id>"


def make_connector(http: HttpClient, **kwargs: Any) -> ArxivConnector:
    """构造注入了离线 HTTP 的 arXiv 采集器。"""
    return ArxivConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0), **kwargs)


class TestIdAndQuery:
    """ID 拆分与检索式构造。"""

    def test_split_arxiv_id_strips_version(self) -> None:
        """版本号被剥离，便于跨版本保持同一 ``source_id``。"""
        assert split_arxiv_id("2404.12345v2") == ("2404.12345", "v2")
        assert split_arxiv_id("http://arxiv.org/abs/2404.12345v1") == ("2404.12345", "v1")
        assert split_arxiv_id("2301.00001") == ("2301.00001", None)

    def test_default_query_keywords(self) -> None:
        """默认检索式包含 cs.CR 与 LLM / agent / prompt injection 关键词。"""
        connector = make_connector(HttpClient())
        assert "cat:cs.CR" in connector.query
        assert "LLM" in connector.query
        assert "agent" in connector.query
        assert "prompt injection" in connector.query

    def test_since_is_appended_as_submitted_date(self) -> None:
        """增量条件落地为 ``submittedDate:[YYYYMMDDHHMM TO ...]``。"""
        connector = make_connector(HttpClient())
        query = connector.build_search_query(SINCE_2024)
        assert "submittedDate:[202401010000 TO 999912312359]" in query

    def test_until_bounds_the_window(self) -> None:
        """显式 ``until`` 会写入时间窗上界。"""
        connector = make_connector(HttpClient())
        query = connector.build_search_query(SINCE_2024, until=datetime(2024, 2, 1, tzinfo=UTC))
        assert "submittedDate:[202401010000 TO 202402010000]" in query


class TestFetchIncremental:
    """增量抓取、时间过滤与字段映射。"""

    async def test_filters_by_submitted_date(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """只返回提交时间晚于 ``since`` 的条目（夹具中 1 条属于 2023 年）。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        assert [item.source_id for item in items] == ["2404.12345", "2403.09876"]

    async def test_returns_all_when_since_is_old(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``since`` 足够早时返回全部条目，并按提交时间倒序。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2020)
        assert len(items) == 3
        assert items[0].source_id == "2404.12345"
        assert items[-1].source_id == "2301.00001"

    async def test_request_params_carry_window_and_sort(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """请求参数包含时间窗、排序方式与分页起点。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        await make_connector(mock_http).fetch_incremental(SINCE_2024)
        params = mock_router.calls[0].url.params
        assert "submittedDate:[202401010000" in params["search_query"]
        assert params["sortBy"] == "submittedDate"
        assert params["sortOrder"] == "descending"
        assert params["start"] == "0"

    async def test_raw_item_field_mapping(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``RawItem`` 的源标识 / ID / 链接 / 标题 / 时间 / meta 映射正确。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        first = items[0]
        assert first.source == "arxiv"
        assert first.source_id == "2404.12345"
        assert first.url == "https://arxiv.org/abs/2404.12345v1"
        assert first.title is not None and "\n" not in first.title
        assert first.title.startswith("Prompt Injection Attacks")
        assert first.published_at == datetime(2024, 4, 18, 9, 0, tzinfo=UTC)
        assert first.lang == "en"
        assert first.meta["primary_category"] == "cs.CR"
        assert first.meta["arxiv_version"] == "v1"
        assert first.meta["authors"] == "Alice Zhang, Bob Miller"
        assert first.meta["pdf_url"] == "http://arxiv.org/pdf/2404.12345v1"
        assert "cs.AI" in first.meta["categories"]

    async def test_raw_text_is_faithful_json(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``raw_text`` 保存条目级保真 JSON（标题 / 摘要 / 作者 / 分类）。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        payload = json.loads(items[0].raw_text)
        assert payload["arxiv_id"] == "2404.12345"
        assert "prompt injection" in payload["summary"].lower()
        assert payload["authors"] == ["Alice Zhang", "Bob Miller"]
        assert payload["categories"] == ["cs.CR", "cs.AI"]

    async def test_fingerprint_is_stable(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """同一条目两次采集指纹一致 → 重复采集天然去重。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        connector = make_connector(mock_http)
        first = {item.source_id: item.sha256 for item in await connector.fetch_incremental(SINCE_2024)}
        second = {item.source_id: item.sha256 for item in await connector.fetch_incremental(SINCE_2024)}
        assert first == second

    async def test_pagination_stops_when_page_adds_nothing_new(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """首页满页时继续翻页；下一页无新增即停止（最多 2 次请求，不产生重复）。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        connector = make_connector(mock_http)
        connector.page_size = 3  # type: ignore[misc]
        items = await connector.fetch_incremental(SINCE_2020)
        assert len(items) == 3
        assert mock_router.call_count(ARXIV_API_URL) == 2

    async def test_max_results_stops_pagination(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``max_results`` 达到上限后不再请求下一页。"""
        mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
        connector = make_connector(mock_http, max_results=3)
        connector.page_size = 3  # type: ignore[misc]
        items = await connector.fetch_incremental(SINCE_2020)
        assert len(items) == 3
        assert mock_router.call_count(ARXIV_API_URL) == 1

    async def test_non_xml_response_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源侧返回非 Atom 内容时显式报错（不静默入库）。"""
        mock_router.always(ARXIV_API_URL, text="<html>error</html>")
        with pytest.raises(ValueError, match="Atom XML"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)

    async def test_malformed_xml_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """XML 语法错误时显式报错。"""
        mock_router.always(ARXIV_API_URL, text=MALFORMED_XML)
        with pytest.raises(ValueError, match="解析失败"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)


class TestEntryEdgeCases:
    """条目边界情况。"""

    def test_entry_without_id_is_skipped(self) -> None:
        """缺少 ``atom:id`` 的条目被跳过（不能写入无主键数据）。"""
        connector = make_connector(HttpClient())
        xml = (
            '<feed xmlns="http://www.w3.org/2005/Atom">'
            "<entry><title>no id</title></entry>"
            "<entry><id>http://arxiv.org/abs/2404.00001v1</id><title>ok</title></entry>"
            "</feed>"
        )
        entries = connector.parse_entries(xml)
        assert [entry["arxiv_id"] for entry in entries] == ["2404.00001"]

    def test_missing_arxiv_id_raises(self) -> None:
        """``entry_to_raw_item`` 缺少 ID 时报错。"""
        with pytest.raises(ValueError, match="arxiv_id"):
            make_connector(HttpClient()).entry_to_raw_item({"title": "x"})

    def test_source_url_points_to_listing(self) -> None:
        """``source_url`` 指向 cs.CR 列表页。"""
        assert make_connector(HttpClient()).source_url == "https://arxiv.org/list/cs.CR/recent"

    def test_class_defaults(self) -> None:
        """类级默认值符合约定（``rate_limit`` 遵循 arXiv 官方建议）。"""
        assert ArxivConnector.source_name == "arxiv"
        assert ArxivConnector.rate_limit == "1/3"
        assert ArxivConnector.timeout == 60.0


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(self, mock_router: Any, mock_http: HttpClient) -> None:
        """HTTP 200 时返回 ``True``。"""
        mock_router.always(ARXIV_API_URL, text="<feed/>")
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_is_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源不可用（503）时返回 ``False`` 而不抛异常。"""
        mock_router.always(ARXIV_API_URL, status_code=503, text="unavailable")
        assert await make_connector(mock_http).health_check() is False


