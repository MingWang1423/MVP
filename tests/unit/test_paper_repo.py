"""Day7 前置：论文源可检索性测试（PROJECT_PLAN.md §5.5 P4 任务 4）。

覆盖 PaperLinker Agent 的数据通路：**采集件（arxiv / openalex）→ Paper → 只读检索**。

全部用例基于 ``tests/fixtures`` + ``httpx.MockTransport`` + SQLite 内存库，**不访问网络**。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.connectors.arxiv import ArxivConnector
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.connectors.openalex import OpenAlexConnector
from aisec_intel.connectors.rate_limiter import RateLimiter
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.papers import is_paper_source, paper_text, raw_item_to_paper
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.paper_repo import (
    PaperHit,
    PaperRepository,
    normalize_paper_id,
)
from aisec_intel.storage.repositories.raw_repo import RawRepository

SINCE_2020 = datetime(2020, 1, 1, tzinfo=UTC)


def fast_http(http: HttpClient) -> RateLimiter:
    """返回注入的高速限流器（测试无需真实等待）。"""
    return RateLimiter(rate=1000.0, burst=1000.0)


async def collect_arxiv(load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient) -> list[RawItem]:
    """用离线夹具采集 arXiv 论文（3 条）。"""
    from aisec_intel.connectors.arxiv import ARXIV_API_URL

    mock_router.always(ARXIV_API_URL, text=load_fixture("arxiv_sample.xml"))
    connector = ArxivConnector(http=mock_http, limiter=RateLimiter(rate=1000.0, burst=1000.0))
    return await connector.fetch_incremental(SINCE_2020)


async def collect_openalex(
    load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
) -> list[RawItem]:
    """用离线夹具采集 OpenAlex 论文（3 条）。"""
    from aisec_intel.connectors.openalex import OPENALEX_WORKS_URL

    mock_router.always(OPENALEX_WORKS_URL, json_body=load_fixture("openalex_sample.json"))
    connector = OpenAlexConnector(http=mock_http, limiter=RateLimiter(rate=1000.0, burst=1000.0))
    return await connector.fetch_incremental(SINCE_2020)


class TestPaperConversion:
    """``RawItem`` → ``Paper``（纯函数）。"""

    async def test_arxiv_item_becomes_paper(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """arXiv 条目映射：ID / 标题 / 摘要 / 作者 / venue / trace_id 全部就位。"""
        items = await collect_arxiv(load_fixture, mock_router, mock_http)
        paper = raw_item_to_paper(items[0])
        assert paper.paper_id == "2404.12345"
        assert paper.source == "arxiv"
        assert paper.title.startswith("Prompt Injection Attacks")
        assert paper.abstract is not None and "prompt injection" in paper.abstract.lower()
        assert paper.authors == ["Alice Zhang", "Bob Miller"]
        assert paper.venue == "USENIX Security 2024"
        assert paper.published_at == datetime(2024, 4, 18, 9, 0, tzinfo=UTC)
        assert paper.trace_ids == [items[0].trace_id]

    async def test_openalex_item_becomes_paper(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """OpenAlex 条目映射：Work ID / DOI 落地页 / venue / 作者。"""
        items = await collect_openalex(load_fixture, mock_router, mock_http)
        paper = raw_item_to_paper(items[0])
        assert paper.paper_id == "W4400000001"
        assert paper.source == "openalex"
        assert paper.venue == "ACM Computing Surveys"
        assert paper.authors == ["Emily Carter", "Wei Li"]
        assert paper.url == "https://dl.acm.org/doi/10.1145/3610020"
        assert paper.abstract is not None and paper.abstract.startswith("Large language model agents")

    def test_non_paper_source_is_rejected(self) -> None:
        """漏洞源误入论文转换时报错（不静默产出脏数据）。"""
        from aisec_intel.models.base import new_trace_id, utc_now
        from aisec_intel.utils.hashing import sha256_text

        text = '{"cveID": "CVE-2024-3400"}'
        item = RawItem(
            trace_id=new_trace_id(),
            source="kev",
            source_id="CVE-2024-3400",
            url="https://example.org",
            title=None,
            raw_text=text,
            lang="en",
            published_at=utc_now(),
            fetched_at=utc_now(),
            sha256=sha256_text(text),
            meta={},
        )
        with pytest.raises(ValueError, match="不是论文源"):
            raw_item_to_paper(item)

    def test_is_paper_source(self) -> None:
        """论文源识别（大小写不敏感）。"""
        assert is_paper_source("ARXIV") is True
        assert is_paper_source("openalex") is True
        assert is_paper_source("nvd") is False

    async def test_paper_text_combines_title_and_abstract(
        self, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """检索文本 = 标题 + 摘要（供向量化与关键词召回）。"""
        items = await collect_arxiv(load_fixture, mock_router, mock_http)
        text = paper_text(raw_item_to_paper(items[0]))
        assert "Prompt Injection Attacks" in text
        assert "guardrails" in text


class TestNormalizePaperId:
    """论文主键规范化。"""

    def test_strips_version_and_whitespace(self) -> None:
        """容忍 arXiv 版本号后缀与空白。"""
        assert normalize_paper_id(" 2404.12345v2 ") == "2404.12345"
        assert normalize_paper_id("W4400000001") == "W4400000001"


class TestPaperRepository:
    """``PaperRepository`` 只读检索（SQLite 内存库）。"""

    async def seed(
        self,
        engine: Any,
        load_fixture: Callable[[str], Any],
        mock_router: Any,
        mock_http: HttpClient,
    ) -> tuple[list[RawItem], list[RawItem]]:
        """把 arXiv / OpenAlex 夹具条目写入 ``raw_item`` 表。"""
        arxiv_items = await collect_arxiv(load_fixture, mock_router, mock_http)
        openalex_items = await collect_openalex(load_fixture, mock_router, mock_http)
        async with session_scope(engine) as session:
            repo = RawRepository(session)
            for item in [*arxiv_items, *openalex_items]:
                await repo.upsert(item)
        return arxiv_items, openalex_items

    async def test_paperlinker_can_retrieve_papers(
        self, memory_engine: Any, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """PaperLinker 能读到论文：计数、按时间倒序、按 ID 精确取。"""
        await self.seed(memory_engine, load_fixture, mock_router, mock_http)
        async with session_scope(memory_engine) as session:
            repo = PaperRepository(session)
            assert await repo.count() == 6
            recent = await repo.list_recent(limit=10)
            assert len(recent) == 6
            assert recent[0].published_at is not None
            assert recent[0].published_at >= recent[-1].published_at  # 时间倒序
            assert {paper.source for paper in recent} == {"arxiv", "openalex"}

            first = await repo.get("2404.12345")
            assert first is not None and first.title.startswith("Prompt Injection")
            # 版本号后缀容错（Agent 常直接从 RawItem.url 取到带 vN 的 ID）
            assert (await repo.get("2404.12345v2")) is not None
            assert await repo.get("not-exists") is None

    async def test_source_filter(
        self, memory_engine: Any, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """按源过滤只返回该源的论文。"""
        await self.seed(memory_engine, load_fixture, mock_router, mock_http)
        async with session_scope(memory_engine) as session:
            repo = PaperRepository(session)
            assert await repo.count(sources=["arxiv"]) == 3
            assert await repo.count(sources=["openalex"]) == 3
            assert {paper.source for paper in await repo.list_recent(sources=["openalex"])} == {"openalex"}

    async def test_keyword_search_ranks_relevant_paper_first(
        self, memory_engine: Any, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """关键词召回：命中「prompt injection」的论文排第一，并给出 matched 证据。"""
        await self.seed(memory_engine, load_fixture, mock_router, mock_http)
        async with session_scope(memory_engine) as session:
            hits = await PaperRepository(session).search(["prompt injection"], limit=5)

        assert hits, "语料中应至少命中 1 篇（fixture 含 prompt injection 论文）"
        assert isinstance(hits[0], PaperHit)
        assert hits[0].paper.paper_id == "2404.12345"
        assert "prompt injection" in hits[0].matched
        assert hits[0].score >= 1
        # 命中数降序（不允许后项超过前项）
        scores = [hit.score for hit in hits]
        assert scores == sorted(scores, reverse=True)

    async def test_keyword_search_returns_empty_without_hits(
        self, memory_engine: Any, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """无关键词命中时返回空列表（不编造论文）。"""
        await self.seed(memory_engine, load_fixture, mock_router, mock_http)
        async with session_scope(memory_engine) as session:
            assert await PaperRepository(session).search(["quantum-chemistry-nonexistent"]) == []
            assert await PaperRepository(session).search([]) == []

    async def test_search_accepts_multiple_keywords(
        self, memory_engine: Any, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """多关键词召回：CVE 描述里的 AI 安全术语可召回论文。"""
        await self.seed(memory_engine, load_fixture, mock_router, mock_http)
        async with session_scope(memory_engine) as session:
            hits = await PaperRepository(session).search(["llm", "agent"], limit=10)
        assert len(hits) >= 1
        assert all(hit.matched for hit in hits)

    async def test_never_writes_unified_vuln(
        self, memory_engine: Any, load_fixture: Callable[[str], Any], mock_router: Any, mock_http: HttpClient
    ) -> None:
        """论文检索只读：不产生 ``unified_vuln`` 行。"""
        from aisec_intel.storage.repositories.vuln_repo import VulnRepository

        await self.seed(memory_engine, load_fixture, mock_router, mock_http)
        async with session_scope(memory_engine) as session:
            await PaperRepository(session).search(["llm"], limit=5)
            await PaperRepository(session).list_recent(limit=5)
        async with session_scope(memory_engine) as session:
            assert await VulnRepository(session).list_recent(limit=10) == []

