"""Day8 新增采集器测试：``vendor_github``（GitHub GraphQL）与 ``rss_blog``（RSS/Atom）。

**全部离线**：HTTP 用 ``httpx.MockTransport``（``mock_http`` fixture），无任何真实网络调用。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.ghsa import GITHUB_GRAPHQL_URL, GhsaAuthError, GhsaQueryError
from aisec_intel.connectors.rss_blog import (
    DEFAULT_FEEDS,
    RSS_BLOG_FEEDS,
    RssBlogConnector,
    parse_feed,
)
from aisec_intel.connectors.vendor_github import (
    ADVISORY_QUERY,
    MONITORED_REPOS,
    VendorGithubConnector,
)

SINCE = datetime(2020, 1, 1, tzinfo=UTC)

RSS_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>Blog</title>
  <item>
    <title>Ollama 0.1.34 fixes path traversal</title>
    <link>https://blog.test/ollama-fix</link>
    <guid>https://blog.test/ollama-fix</guid>
    <pubDate>Tue, 02 Apr 2024 10:00:00 GMT</pubDate>
    <description>Security release fixing CVE-2024-37032.</description>
  </item>
  <item>
    <title>Old post</title>
    <link>https://blog.test/old</link>
    <pubDate>Mon, 01 Jan 2018 00:00:00 GMT</pubDate>
    <description>old</description>
  </item>
</channel></rss>
"""

ATOM_SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Advisories</title>
  <entry>
    <id>urn:uuid:1</id>
    <title>advisory-1</title>
    <link rel="alternate" href="https://atom.test/a1"/>
    <updated>2024-05-01T00:00:00Z</updated>
    <summary>summary text</summary>
  </entry>
</feed>
"""


def graphql_advisory(
    ghsa_id: str, *, updated: str = "2024-05-01T00:00:00Z", package: str = "ollama"
) -> dict[str, Any]:
    """构造一个 GraphQL 公告节点。

    Args:
        ghsa_id: GHSA 编号。
        updated: 更新时间（ISO8601）。
        package: 受影响包名（用于归属匹配测试）。
    """
    return {
        "ghsaId": ghsa_id,
        "summary": f"Vulnerability {ghsa_id}",
        "description": "desc",
        "severity": "HIGH",
        "publishedAt": updated,
        "updatedAt": updated,
        "cvss": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
        "cwes": {"nodes": [{"cweId": "CWE-22"}]},
        "identifiers": [{"type": "GHSA", "value": ghsa_id}],
        "references": [{"url": "https://example.test/adv"}],
        "vulnerabilities": {
            "nodes": [
                {
                    "package": {"ecosystem": "PIP", "name": package},
                    "vulnerableVersionRange": "<0.1.34",
                    "firstPatchedVersion": {"identifier": "0.1.34"},
                }
            ]
        },
    }


class TestVendorGithubConnector:
    """厂商仓库公告采集器。"""

    def test_requires_token(self) -> None:
        """未配置 Token 时不可用。"""
        assert VendorGithubConnector(token="").enabled is False
        assert VendorGithubConnector(token="t").enabled is True

    async def test_missing_token_raises(self) -> None:
        """``fetch_incremental`` 在无 Token 时抛 ``GhsaAuthError``。"""
        with pytest.raises(GhsaAuthError):
            await VendorGithubConnector(token="").fetch_incremental(SINCE)

    def test_monitored_repos_default(self) -> None:
        """默认监控 5 个 AI/ML 厂商仓库。"""
        assert MONITORED_REPOS == (
            "ollama/ollama",
            "vllm-project/vllm",
            "langchain-ai/langchain",
            "huggingface/transformers",
            "pytorch/pytorch",
        )
        connector = VendorGithubConnector(token="t")
        assert connector.repos == MONITORED_REPOS
        assert connector.source_name == "vendor_github"

    def test_query_reuses_ghsa_fields(self) -> None:
        """查询复用 ghsa 的字段选择（ghsaId / vulnerabilities / cvss / cwes）。"""
        for field in ("ghsaId", "vulnerabilities", "cvss { vectorString score }", "cwes(first: 5)"):
            assert field in ADVISORY_QUERY

    def test_match_repo_by_package(self) -> None:
        """按受影响包名归属到受监控仓库（子串匹配，覆盖 langchain-core 等变体）。"""
        connector = VendorGithubConnector(token="t")
        assert connector.match_repo(graphql_advisory("GHSA-x")) == "ollama/ollama"
        assert connector.match_repo({"vulnerabilities": {"nodes": [{"package": {"name": "langchain-core"}}]}}) == (
            "langchain-ai/langchain"
        )
        assert connector.match_repo({"vulnerabilities": {"nodes": [{"package": {"name": "requests"}}]}}) is None
        assert connector.match_repo({}) is None

    async def test_fetch_maps_nodes(self, mock_router: Any, mock_http: Any) -> None:
        """全站公告 → 按包名归属过滤 → 映射为 ``RawItem``（meta 含 repo / packages）。"""
        mock_router.always(
            GITHUB_GRAPHQL_URL,
            json_body={
                "data": {
                    "securityAdvisories": {
                        "nodes": [
                            graphql_advisory("GHSA-aaaa-bbbb-cccc"),
                            graphql_advisory("GHSA-irrelevant", package="requests"),
                        ],
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                    }
                }
            },
        )
        connector = VendorGithubConnector(token="token", repos=["ollama/ollama"], http=mock_http, max_records=5)
        items = await connector.fetch_incremental(SINCE)

        assert [item.source_id for item in items] == ["GHSA-aaaa-bbbb-cccc"]
        item = items[0]
        assert item.source == "vendor_github"
        assert item.url == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
        assert item.meta["repo"] == "ollama/ollama"
        assert item.meta["packages"] == "ollama"
        assert item.published_at == datetime(2024, 5, 1, tzinfo=UTC)
        assert item.source_id == "GHSA-aaaa-bbbb-cccc"

    async def test_since_filters_old_advisories(self, mock_router: Any, mock_http: Any) -> None:
        """``updatedAt < since`` 的公告被过滤。"""
        mock_router.always(
            GITHUB_GRAPHQL_URL,
            json_body={
                "data": {
                    "securityAdvisories": {
                        "nodes": [
                            graphql_advisory("GHSA-new", updated="2024-05-01T00:00:00Z"),
                            graphql_advisory("GHSA-old", updated="2018-01-01T00:00:00Z"),
                        ],
                        "pageInfo": {"hasNextPage": False},
                    }
                }
            },
        )
        connector = VendorGithubConnector(token="t", repos=["ollama/ollama"], http=mock_http)
        items = await connector.fetch_incremental(SINCE)
        assert [item.source_id for item in items] == ["GHSA-new"]

    async def test_page_failure_is_isolated(self, mock_router: Any, mock_http: Any) -> None:
        """单页失败不阻断（返回已收集结果，不抛异常）。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"errors": [{"message": "rate limited"}]})
        connector = VendorGithubConnector(token="t", repos=["ollama/ollama"], http=mock_http)
        assert await connector.fetch_incremental(SINCE) == []

    async def test_graphql_error_is_raised(self, mock_router: Any, mock_http: Any) -> None:
        """GraphQL ``errors`` 在 ``_graphql`` 层显式抛出。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"errors": [{"message": "Bad credentials"}]})
        connector = VendorGithubConnector(token="t", repos=["ollama/ollama"], http=mock_http)
        with pytest.raises(GhsaQueryError, match="Bad credentials"):
            await connector._graphql(ADVISORY_QUERY, {"first": 1, "after": None})

    async def test_health_check(self, mock_router: Any, mock_http: Any) -> None:
        """探活用 ``viewer`` 查询；无 Token 时返回 ``False``。"""
        mock_router.always(GITHUB_GRAPHQL_URL, json_body={"data": {"viewer": {"login": "bot"}}})
        assert await VendorGithubConnector(token="t", repos=["ollama/ollama"], http=mock_http).health_check() is True
        assert await VendorGithubConnector(token="", http=mock_http).health_check() is False


class TestRssBlogConnector:
    """RSS/Atom 博客采集器。"""

    def test_parse_rss_and_atom(self) -> None:
        """RSS 2.0 与 Atom 1.0 均可解析。"""
        rss = parse_feed(RSS_SAMPLE)
        assert len(rss) == 2
        assert rss[0]["title"].startswith("Ollama")
        assert rss[0]["link"] == "https://blog.test/ollama-fix"

        atom = parse_feed(ATOM_SAMPLE)
        assert len(atom) == 1
        assert atom[0]["link"] == "https://atom.test/a1"
        assert atom[0]["published"].startswith("2024-05-01")

    def test_parse_invalid_xml_raises(self) -> None:
        """非法 XML 抛 ``ValueError``。"""
        with pytest.raises(ValueError, match="feed XML 解析失败"):
            parse_feed("<not-xml")

    def test_registry_contains_requested_feeds(self) -> None:
        """注册表含任务指定的三个官方源与实测可达的补充源。"""
        for name in ("cisa_alerts", "apache_security", "pytorch"):
            assert name in RSS_BLOG_FEEDS
        assert {"github_security_blog", "huggingface_blog", "sans_isc"} <= set(RSS_BLOG_FEEDS)
        assert set(DEFAULT_FEEDS) <= set(RSS_BLOG_FEEDS)

    def test_unknown_feed_is_ignored(self) -> None:
        """未注册的 feed 名称被忽略（不抛异常）。"""
        assert RssBlogConnector(feeds=["does-not-exist"]).feeds == []

    def test_custom_feed_urls(self) -> None:
        """可通过 ``feed_urls`` 注入自定义 feed。"""
        connector = RssBlogConnector(feeds=["custom"], feed_urls={"custom": "https://x.test/rss"})
        assert connector.feeds == [("custom", "https://x.test/rss")]

    async def test_fetch_feed_maps_items(self, mock_router: Any, mock_http: Any) -> None:
        """抓取 feed → ``RawItem``（source_id 带 feed 前缀，meta 标记 blog）。"""
        mock_router.always("https://blog.test/rss", text=RSS_SAMPLE)
        connector = RssBlogConnector(feeds=["custom"], feed_urls={"custom": "https://blog.test/rss"}, http=mock_http)
        items = await connector.fetch_feed("custom", "https://blog.test/rss")

        assert len(items) == 2
        assert items[0].source == "rss_blog"
        assert items[0].source_id.startswith("custom:")
        assert items[0].meta["feed"] == "custom"
        assert items[0].meta["source_type"] == "blog"
        assert items[0].published_at == datetime(2024, 4, 2, 10, 0, tzinfo=UTC)

    async def test_fetch_incremental_filters_and_isolates(self, mock_router: Any, mock_http: Any) -> None:
        """按 ``since`` 过滤；单 feed 失败仅记日志（不抛异常）。"""
        mock_router.always("https://ok.test/rss", text=RSS_SAMPLE)
        mock_router.always("https://bad.test/rss", status_code=500, text="boom")
        connector = RssBlogConnector(
            feeds=["ok", "bad"],
            feed_urls={"ok": "https://ok.test/rss", "bad": "https://bad.test/rss"},
            http=mock_http,
        )
        items = await connector.fetch_incremental(datetime(2020, 1, 1, tzinfo=UTC))
        assert [item.title for item in items] == ["Ollama 0.1.34 fixes path traversal"]

    async def test_health_check(self, mock_router: Any, mock_http: Any) -> None:
        """探活：任一 feed 返回 200 且可解析即视为可用；全部失败返回 ``False``。"""
        mock_router.always("https://ok.test/rss", text=RSS_SAMPLE)
        connector = RssBlogConnector(feeds=["ok"], feed_urls={"ok": "https://ok.test/rss"}, http=mock_http)
        assert await connector.health_check() is True

        mock_router.always("https://bad.test/rss", status_code=403, text="denied")
        denied = RssBlogConnector(feeds=["bad"], feed_urls={"bad": "https://bad.test/rss"}, http=mock_http)
        assert await denied.health_check() is False
