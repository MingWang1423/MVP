"""Day6 OpenAlex 采集器测试（PROJECT_PLAN.md §5.5 P4 任务 4）。

全部用例基于 ``tests/fixtures/openalex_sample.json`` + ``httpx.MockTransport``，**不访问真实网络**。
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.openalex import (
    DEFAULT_SEARCH,
    OPENALEX_WORKS_URL,
    OpenAlexConnector,
    reconstruct_abstract,
)
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE_2024 = datetime(2024, 1, 1, tzinfo=UTC)
SINCE_2020 = datetime(2020, 1, 1, tzinfo=UTC)


def make_connector(http: HttpClient, **kwargs: Any) -> OpenAlexConnector:
    """构造注入了离线 HTTP 的 OpenAlex 采集器。"""
    return OpenAlexConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0), **kwargs)


class TestAbstractReconstruction:
    """倒排摘要还原（确定性纯函数）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_positions_are_sorted()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_positions_are_sorted: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_input_returns_empty_string()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_input_returns_empty_string: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_positions_are_sorted(self) -> None:
        """按位置升序拼接，得到可读摘要。"""
        inverted = {"world": [1], "hello": [0], "again": [2]}
        assert reconstruct_abstract(inverted) == "hello world again"

    def _case_test_empty_input_returns_empty_string(self) -> None:
        """``None`` / 空字典返回空串（不抛异常）。"""
        assert reconstruct_abstract(None) == ""
        assert reconstruct_abstract({}) == ""


class TestFilterAndSearch:
    """检索词与增量过滤条件。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_default_search_is_ai_security()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_default_search_is_ai_security: {type(exc).__name__}: {exc}")
        try:
            self._case_test_filter_uses_from_publication_date()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_filter_uses_from_publication_date: {type(exc).__name__}: {exc}")
        try:
            self._case_test_extra_filter_is_appended()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_extra_filter_is_appended: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_default_search_is_ai_security(self) -> None:
        """默认检索词为 AI security。"""
        assert make_connector(HttpClient()).search == DEFAULT_SEARCH

    def _case_test_filter_uses_from_publication_date(self) -> None:
        """增量条件落地为 ``from_publication_date:YYYY-MM-DD``。"""
        assert make_connector(HttpClient()).build_filter(SINCE_2024) == "from_publication_date:2024-01-01"

    def _case_test_extra_filter_is_appended(self) -> None:
        """追加过滤条件以逗号连接（OpenAlex 语法）。"""
        connector = make_connector(HttpClient(), extra_filter="type:article")
        assert connector.build_filter(SINCE_2024) == "from_publication_date:2024-01-01,type:article"


class TestFetchIncremental:
    """增量抓取、时间过滤与字段映射。"""

    async def test_filters_by_publication_date(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """只返回 ``publication_date >= since`` 的论文（夹具中 1 条属于 2023 年）。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        assert [item.source_id for item in items] == ["W4400000001", "W4400000002"]

    async def test_returns_all_when_since_is_old(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``since`` 足够早时返回全部，并按发布时间倒序。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2020)
        assert len(items) == 3
        assert items[0].source_id == "W4400000001"
        assert items[-1].source_id == "W4390000003"

    async def test_request_params_carry_filter_and_sort(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """请求参数包含检索词、过滤条件与排序方式。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        await make_connector(mock_http).fetch_incremental(SINCE_2024)
        params = mock_router.calls[0].url.params
        assert params["search"] == DEFAULT_SEARCH
        assert params["filter"] == "from_publication_date:2024-01-01"
        assert params["sort"] == "publication_date:desc"
        assert params["page"] == "1"

    async def test_mailto_is_sent_when_configured(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """配置 ``mailto`` 后进入 OpenAlex polite pool。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        await make_connector(mock_http, mailto="team@example.org").fetch_incremental(SINCE_2024)
        assert mock_router.calls[0].url.params["mailto"] == "team@example.org"

    async def test_raw_item_field_mapping(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``RawItem`` 的源标识 / ID / 链接 / 标题 / 时间 / meta 映射正确。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        first = items[0]
        assert first.source == "openalex"
        assert first.source_id == "W4400000001"
        assert first.url == "https://dl.acm.org/doi/10.1145/3610020"
        assert first.title == "Securing LLM Agents: Threat Models and Defenses for Tool Use"
        assert first.published_at == datetime(2024, 5, 10, tzinfo=UTC)
        assert first.lang == "en"
        assert first.meta["doi"] == "https://doi.org/10.1145/3610020"
        assert first.meta["type"] == "article"
        assert first.meta["venue"] == "ACM Computing Surveys"
        assert first.meta["authors"] == "Emily Carter, Wei Li"
        assert first.meta["cited_by_count"] == "27"

    async def test_raw_text_contains_reconstructed_abstract(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """``raw_text`` 中的摘要已由倒排索引还原为纯文本。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024)
        payload = json.loads(items[0].raw_text)
        assert payload["abstract"].startswith("Large language model agents introduce new attack surfaces")
        assert payload["venue"] == "ACM Computing Surveys"

    async def test_pagination_stops_when_page_adds_nothing_new(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """首页满页时继续翻页；下一页无新增即停止（不产生重复）。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
        connector = make_connector(mock_http)
        connector.per_page = 3  # type: ignore[misc]
        items = await connector.fetch_incremental(SINCE_2020)
        assert len(items) == 3
        assert mock_router.call_count(OPENALEX_WORKS_URL) == 2

    async def test_results_not_a_list_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """``results`` 结构异常时显式报错。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body={"results": {"a": 1}})
        with pytest.raises(ValueError, match="results"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)

    async def test_non_object_payload_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """响应不是 JSON 对象时显式报错。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body=[1, 2, 3])
        with pytest.raises(ValueError, match="结构异常"):
            await make_connector(mock_http).fetch_incremental(SINCE_2024)


class TestEntryEdgeCases:
    """条目边界情况。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_missing_id_raises()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_missing_id_raises: {type(exc).__name__}: {exc}")
        try:
            self._case_test_minimal_entry_uses_source_id_as_url_fallback()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_minimal_entry_uses_source_id_as_url_fallback: {type(exc).__name__}: {exc}")
        try:
            self._case_test_class_defaults()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_class_defaults: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_missing_id_raises(self) -> None:
        """缺少 ``id`` 的条目必须报错。"""
        with pytest.raises(ValueError, match="缺少 id"):
            make_connector(HttpClient()).entry_to_raw_item({"title": "x"})

    def _case_test_minimal_entry_uses_source_id_as_url_fallback(self) -> None:
        """缺少落地页与 DOI 时以 OpenAlex ID 作为 ``url`` 兜底。"""
        item = make_connector(HttpClient()).entry_to_raw_item(
            {"id": "https://openalex.org/W1234567890", "title": "Tiny work"}
        )
        assert item.url == "https://openalex.org/W1234567890"
        assert item.published_at is None
        assert item.meta["doi"] == ""

    def _case_test_class_defaults(self) -> None:
        """类级默认值符合约定。"""
        assert OpenAlexConnector.source_name == "openalex"
        assert OpenAlexConnector.rate_limit == "10/1"
        assert OpenAlexConnector.timeout == 60.0


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(self, mock_router: Any, mock_http: HttpClient) -> None:
        """HTTP 200 时返回 ``True``。"""
        mock_router.always(OPENALEX_WORKS_URL, json_body={"results": []})
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_is_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """源不可用（503）时返回 ``False`` 而不抛异常。"""
        mock_router.always(OPENALEX_WORKS_URL, status_code=503, text="unavailable")
        assert await make_connector(mock_http).health_check() is False

