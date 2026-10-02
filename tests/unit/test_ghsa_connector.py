"""Day4 GHSA 采集器测试（mock GraphQL 响应，不访问真实网络）。

覆盖：Token 校验、生态 + AI/ML 关键词过滤、cursor 分页、按 ``updatedAt`` 的增量停止、
字段映射与探活。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.ghsa import (
    GITHUB_GRAPHQL_URL,
    GhsaAuthError,
    GhsaConnector,
    GhsaQueryError,
)
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.rate_limiter import RateLimiter

SINCE_2023 = datetime(2023, 1, 1, tzinfo=UTC)
SINCE_2024_04_25 = datetime(2024, 4, 25, tzinfo=UTC)

EMPTY_PAGE: dict[str, Any] = {
    "data": {"securityAdvisories": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}
}


def make_connector(http: HttpClient, *, token: str = "ghp_unit_test", max_pages: int = 2) -> GhsaConnector:
    """构造注入离线 HTTP 的 GHSA 采集器。"""
    return GhsaConnector(http=http, limiter=RateLimiter(rate=1000.0, burst=1000.0), token=token, max_pages=max_pages)


class TestAuth:
    """Token 校验行为。"""

    def test_disabled_without_token(self) -> None:
        """无 Token 时 ``enabled=False``。"""
        assert GhsaConnector(token="").enabled is False

    async def test_fetch_requires_token(self, mock_http: HttpClient) -> None:
        """无 Token 时采集显式报错（而不是静默返回空）。"""
        with pytest.raises(GhsaAuthError, match="GITHUB_TOKEN"):
            await make_connector(mock_http, token="").fetch_incremental(SINCE_2023)

    async def test_health_check_false_without_token(self, mock_http: HttpClient) -> None:
        """无 Token 时探活直接返回 ``False``。"""
        assert await make_connector(mock_http, token="").health_check() is False

    async def test_non_ascii_token_gives_actionable_error(self, mock_http: HttpClient) -> None:
        """Token 含非 ASCII（如 .env 行内注释粘进值里）时给出可操作报错，而不是 UnicodeEncodeError。"""
        connector = make_connector(mock_http, token="ghp_xxxx  源跳过）")
        with pytest.raises(GhsaAuthError, match="非 ASCII"):
            await connector.fetch_incremental(SINCE_2023)

    async def test_token_is_stripped(self, mock_router: Any, mock_http: HttpClient) -> None:
        """Token 首尾空白被去除（复制粘贴常见问题）。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"data": {"viewer": {"login": "x"}}})
        connector = make_connector(mock_http, token="  ghp_padded  ")
        assert await connector.health_check() is True
        assert mock_router.calls[-1].headers["authorization"] == "Bearer ghp_padded"

    async def test_authorization_header_sent(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """请求头带 Bearer Token。"""
        mock_router.add(GITHUB_GRAPHQL_URL, json_body=load_fixture("ghsa_graphql_sample.json"))
        mock_router.always(GITHUB_GRAPHQL_URL, json_body=EMPTY_PAGE)
        await make_connector(mock_http).fetch_incremental(SINCE_2023)
        assert mock_router.calls[-1].headers["authorization"] == "Bearer ghp_unit_test"


class TestFetchIncremental:
    """过滤、分页与增量行为。"""

    async def test_filters_ecosystem_and_keywords(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """只保留 PIP/NPM 生态且命中 AI/ML 关键词的公告（RUBYGEMS 被过滤）。"""
        mock_router.add(GITHUB_GRAPHQL_URL, json_body=load_fixture("ghsa_graphql_sample.json"))
        mock_router.always(GITHUB_GRAPHQL_URL, json_body=EMPTY_PAGE)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2023)
        assert {item.source_id for item in items} == {"GHSA-2qrp-3j2c-6v3x", "GHSA-9p4w-plgg-j4q7"}
        assert items[0].published_at >= items[-1].published_at

    async def test_pagination_sends_cursor(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """第二页请求携带第一页返回的 ``endCursor``。"""
        first_page = load_fixture("ghsa_graphql_sample.json")
        cursor = first_page["data"]["securityAdvisories"]["pageInfo"]["endCursor"]
        mock_router.add(GITHUB_GRAPHQL_URL, json_body=first_page)
        mock_router.always(GITHUB_GRAPHQL_URL, json_body=EMPTY_PAGE)
        await make_connector(mock_http).fetch_incremental(SINCE_2023)
        assert len(mock_router.calls) >= 2
        assert cursor in mock_router.calls[1].content.decode("utf-8")

    async def test_incremental_stops_at_old_node(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """遇到 ``updatedAt < since`` 的节点即停止（更旧的数据不再取）。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body=load_fixture("ghsa_graphql_sample.json"))
        items = await make_connector(mock_http).fetch_incremental(SINCE_2024_04_25)
        assert [item.source_id for item in items] == ["GHSA-2qrp-3j2c-6v3x"]
        assert len(mock_router.calls) == 1  # 未翻页


    async def test_field_mapping(
        self, mock_router: Any, mock_http: HttpClient, load_fixture: Callable[[str], Any]
    ) -> None:
        """``url`` / ``title`` / ``published_at`` / ``meta`` 映射正确（整节点保真保存）。"""
        mock_router.add(GITHUB_GRAPHQL_URL, json_body=load_fixture("ghsa_graphql_sample.json"))
        mock_router.always(GITHUB_GRAPHQL_URL, json_body=EMPTY_PAGE)
        items = await make_connector(mock_http).fetch_incremental(SINCE_2023)
        item = next(entry for entry in items if entry.source_id == "GHSA-2qrp-3j2c-6v3x")
        assert item.source == "ghsa"
        assert item.url == "https://github.com/advisories/GHSA-2qrp-3j2c-6v3x"
        assert item.published_at == datetime(2024, 3, 15, tzinfo=UTC)
        assert item.meta["severity"] == "HIGH"
        assert item.meta["ecosystems"] == "PIP"
        assert "langchain" in item.meta["packages"]
        assert "CVE-2024-28088" in item.meta["identifiers"]
        assert "CVSS:3.1" in item.raw_text  # 供 L2 抽取 CVSS

    async def test_graphql_errors_raise(self, mock_router: Any, mock_http: HttpClient) -> None:
        """GraphQL ``errors`` 转换为 ``GhsaQueryError``。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"errors": [{"message": "rate limited"}]})
        with pytest.raises(GhsaQueryError, match="rate limited"):
            await make_connector(mock_http).fetch_incremental(SINCE_2023)

    async def test_missing_data_raises(self, mock_router: Any, mock_http: HttpClient) -> None:
        """响应缺少 ``data`` 时报错。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"foo": "bar"})
        with pytest.raises(ValueError, match="缺少 data"):
            await make_connector(mock_http).fetch_incremental(SINCE_2023)

    async def test_missing_ghsa_id_raises(self, mock_http: HttpClient) -> None:
        """节点缺少 ``ghsaId`` 时报错。"""
        with pytest.raises(ValueError, match="ghsaId"):
            make_connector(mock_http).advisory_to_raw_item({"summary": "x"})


class TestHealthCheck:
    """探活行为。"""

    async def test_health_check_ok(self, mock_router: Any, mock_http: HttpClient) -> None:
        """``viewer`` 查询成功 → True。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"data": {"viewer": {"login": "aisec-bot"}}})
        assert await make_connector(mock_http).health_check() is True

    async def test_health_check_failure_swallowed(self, mock_router: Any, mock_http: HttpClient) -> None:
        """GraphQL 报错时返回 False 而不抛异常。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"errors": [{"message": "Bad credentials"}]})
        assert await make_connector(mock_http).health_check() is False


class TestFilters:
    """过滤逻辑单元测试。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_ecosystem_filter_rejects_other_ecosystems()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_ecosystem_filter_rejects_other_ecosystems: {type(exc).__name__}: {exc}")
        try:
            self._case_test_keyword_filter_rejects_irrelevant()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_keyword_filter_rejects_irrelevant: {type(exc).__name__}: {exc}")
        try:
            self._case_test_keywords_can_be_overridden()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_keywords_can_be_overridden: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_ecosystem_filter_rejects_other_ecosystems(self) -> None:
        """非 PIP/NPM 生态被拒绝。"""
        connector = GhsaConnector(token="x")
        node = {
            "summary": "AI model RCE",
            "vulnerabilities": {"nodes": [{"package": {"ecosystem": "GO", "name": "ai"}}]},
        }
        assert connector.matches_filters(node) is False

    def _case_test_keyword_filter_rejects_irrelevant(self) -> None:
        """生态命中但无 AI/ML 关键词时被拒绝。"""
        connector = GhsaConnector(token="x")
        node = {
            "summary": "Open redirect in web framework",
            "description": "An open redirect issue.",
            "vulnerabilities": {"nodes": [{"package": {"ecosystem": "NPM", "name": "left-pad"}}]},
        }
        assert connector.matches_filters(node) is False

    def _case_test_keywords_can_be_overridden(self) -> None:
        """关键词可覆盖（便于后续按需调整关注面）。"""
        connector = GhsaConnector(token="x", keywords=["left-pad"])
        node = {
            "summary": "Anything",
            "vulnerabilities": {"nodes": [{"package": {"ecosystem": "NPM", "name": "left-pad"}}]},
        }
        assert connector.matches_filters(node) is True