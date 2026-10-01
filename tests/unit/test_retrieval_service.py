"""Day10 混合检索单元测试（``aisec_intel.services.retrieval_service``，PROJECT_PLAN.md §5.8）。

覆盖：纯函数（RRF / 过滤器翻译 / 实体键）、四路检索在 SQLite + 内存向量库下的行为、
单路失败隔离。**不依赖 PostgreSQL / Neo4j / 网络**。
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install 'sqlalchemy[asyncio]' aiosqlite")

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models.enriched_vuln import EnrichedVuln  # noqa: E402
from aisec_intel.models.unified_vuln import UnifiedVuln  # noqa: E402
from aisec_intel.normalize.index_text import render_vuln_text, vuln_index_metadata  # noqa: E402
from aisec_intel.qa.state import QueryFilters, RetrievalResult  # noqa: E402
from aisec_intel.services import retrieval_service as rs  # noqa: E402
from aisec_intel.storage.vector_store import (  # noqa: E402
    COLLECTION_VULN_DESCRIPTIONS,
    VectorDoc,
    VectorStore,
)


def _settings(**overrides: object) -> Settings:
    """测试配置：关闭 Neo4j、使用哈希嵌入（完全离线）。"""
    base: dict[str, object] = {"neo4j_enabled": False, "embedding_backend": "hashing", "embedding_dim": 64}
    base.update(overrides)
    return Settings(**base)


def _store(dim: int = 64) -> VectorStore:
    """内存态向量库（先清空共享内存系统，保证用例隔离）。"""
    store = VectorStore.ephemeral(dim=dim)
    for existing in store.client.list_collections():
        store.client.delete_collection(existing.name)
    return store


def _result(route: str, doc_id: str, *, cve: str | None = None, content: str = "x") -> RetrievalResult:
    """构造单路检索结果（测试夹具）。"""
    metadata: dict[str, Any] = {"cve_id": cve} if cve else {}
    return RetrievalResult(source=route, doc_id=doc_id, content=content, metadata=metadata)


class TestKeywordHelpers:
    """关键词切分与全文打分。"""

    def test_query_keywords_dedupes_and_keeps_cjk_bigrams(self) -> None:
        tokens = rs.query_keywords("PAN-OS 命令注入 PAN-OS")
        assert tokens.count("pan") == 1
        assert "命令" in tokens and "注入" in tokens

    def test_query_keywords_empty(self) -> None:
        assert rs.query_keywords("") == []

    def test_python_fulltext_score_full_and_partial(self) -> None:
        """全部命中得 1.0，部分命中按比例，无命中为 0。"""
        assert rs.python_fulltext_score("PAN-OS command injection", ["pan", "injection"]) == 1.0
        assert rs.python_fulltext_score("PAN-OS command injection", ["pan", "zzz"]) == 0.5
        assert rs.python_fulltext_score("PAN-OS", ["zzz"]) == 0.0
        assert rs.python_fulltext_score("PAN-OS", []) == 0.0

    def test_build_tsquery_is_or_semantics(self) -> None:
        """tsquery 用 OR 拼装（避免 ``plainto_tsquery`` 的 AND 语义导致长查询 0 命中）。"""
        assert rs.build_tsquery(["pan", "os", "注入"]) == "pan | os | 注入"

    def test_build_tsquery_sanitizes_and_dedupes(self) -> None:
        """剔除 tsquery 语法字符与单字词元，并按小写去重。"""
        assert rs.build_tsquery(["CVE-2024-3400", "cve", "a", "!!!"]) == "CVE | 2024 | 3400"

    def test_build_tsquery_empty(self) -> None:
        assert rs.build_tsquery([]) == ""
        assert rs.build_tsquery(["a", "--"]) == ""

    def test_fulltext_snippet_truncates(self, sample_unified_vuln: UnifiedVuln) -> None:
        snippet = rs.fulltext_snippet(sample_unified_vuln, limit=20)
        assert snippet.startswith("CVE-2024-3400")
        assert len(snippet.splitlines()) == 2


class TestCanonicalKey:
    """融合实体键与代表结果选择。"""

    def test_prefers_cve_then_paper_then_doc_id(self) -> None:
        assert rs.canonical_key(_result("vector", "x", cve="cve-2024-3400")) == "cve:CVE-2024-3400"
        paper = RetrievalResult(source="vector", doc_id="paper_abstracts:1", metadata={"paper_id": "2404.1"})
        assert rs.canonical_key(paper) == "paper:2404.1"
        assert rs.canonical_key(_result("graph", "graph:CVE-1")) == "graph:CVE-1"

    def test_prefer_payload_longer_content_wins(self) -> None:
        short = _result("vector", "a", content="short")
        long = _result("fulltext", "b", content="much longer content")
        assert rs.prefer_payload(long, short) is True
        assert rs.prefer_payload(short, long) is False

    def test_prefer_payload_tie_breaks_by_doc_id(self) -> None:
        first = _result("vector", "a", content="same")
        second = _result("fulltext", "b", content="same")
        assert rs.prefer_payload(first, second) is True
        assert rs.prefer_payload(second, first) is False


class TestVectorWhereFromFilters:
    """过滤器 → Chroma ``where`` 翻译。"""

    def test_none_when_no_filters(self) -> None:
        assert rs.vector_where_from_filters(None) is None
        assert rs.vector_where_from_filters(QueryFilters()) is None

    def test_severity_in_clause(self) -> None:
        where = rs.vector_where_from_filters(QueryFilters(severity=["CRITICAL", "HIGH"]))
        assert where == {"severity": {"$in": ["CRITICAL", "HIGH"]}}

    def test_kev_only_clause(self) -> None:
        assert rs.vector_where_from_filters(QueryFilters(kev_only=True)) == {"kev": "true"}

    def test_time_range_clause_uses_iso_cutoff(self) -> None:
        now = datetime(2026, 1, 31, tzinfo=UTC)
        where = rs.vector_where_from_filters(QueryFilters(time_range="recent_30d"), now=now)
        assert where == {"published_at": {"$gte": "2026-01-01T00:00:00Z"}}

    def test_combined_filters_use_and(self) -> None:
        where = rs.vector_where_from_filters({"severity": ["CRITICAL"], "kev_only": True})
        assert where == {"$and": [{"severity": {"$in": ["CRITICAL"]}}, {"kev": "true"}]}

    def test_accepts_plain_dict(self) -> None:
        assert rs.vector_where_from_filters({"kev_only": True}) == {"kev": "true"}


class TestRRF:
    """RRF 融合（纯函数）。"""

    def test_empty_channels(self) -> None:
        assert rs.reciprocal_rank_fusion({}) == []
        assert rs.reciprocal_rank_fusion({"vector": []}) == []

    def test_multi_route_hit_outranks_single_route(self) -> None:
        """多路共同命中的实体得分更高（RRF 的核心收益）。"""
        channels = {
            "vector": [_result("vector", "v1", cve="CVE-1"), _result("vector", "v2", cve="CVE-2")],
            "fulltext": [_result("fulltext", "f1", cve="CVE-2")],
        }
        fused = rs.reciprocal_rank_fusion(channels)
        assert [item.metadata["cve_id"] for item in fused] == ["CVE-2", "CVE-1"]
        assert fused[0].route_scores.keys() == {"vector", "fulltext"}
        assert [item.rank for item in fused] == [1, 2]

    def test_weights_change_order(self) -> None:
        """通路权重可调（评测调参口子）。"""
        channels = {
            "vector": [_result("vector", "v1", cve="CVE-1")],
            "fulltext": [_result("fulltext", "f1", cve="CVE-2")],
        }
        assert rs.reciprocal_rank_fusion(channels, weights={"fulltext": 3.0})[0].metadata["cve_id"] == "CVE-2"

    def test_top_k_and_rank_renumbering(self) -> None:
        channels = {"vector": [_result("vector", f"v{i}", cve=f"CVE-{i}") for i in range(5)]}
        fused = rs.reciprocal_rank_fusion(channels, top_k=2)
        assert len(fused) == 2
        assert [item.rank for item in fused] == [1, 2]

    def test_same_route_same_doc_counts_once(self) -> None:
        """同一路内的重复主键只贡献一次（不重复加词）。"""
        channels = {"vector": [_result("vector", "v1", cve="CVE-1"), _result("vector", "v1b", cve="CVE-1")]}
        assert len(rs.reciprocal_rank_fusion(channels)) == 1

    def test_content_prefers_longer(self) -> None:
        """融合后保留信息量更大的内容。"""
        channels = {
            "vector": [_result("vector", "v1", cve="CVE-1", content="short")],
            "graph": [_result("graph", "g1", cve="CVE-1", content="a much longer structured summary")],
        }
        fused = rs.reciprocal_rank_fusion(channels)
        assert fused[0].content == "a much longer structured summary"


class TestEntityBoost:
    """实体精确匹配加成（融合后确定性重排）。"""

    def test_matching_cve_moves_to_front(self) -> None:
        """查询指向的 CVE 被提到最前，其余顺序不变。"""
        results = [
            _result("vector", "v1", cve="CVE-2024-33331"),
            _result("graph", "g1", cve="CVE-2024-3400"),
            _result("vector", "v2", cve="CVE-2026-19490"),
        ]
        boosted = rs.boost_entity_matches(results, cve_ids=["cve-2024-3400"])
        assert [item.metadata["cve_id"] for item in boosted] == [
            "CVE-2024-3400",
            "CVE-2024-33331",
            "CVE-2026-19490",
        ]
        assert boosted[0].route_scores["entity_match"] == rs.DEFAULT_ENTITY_BONUS
        assert [item.rank for item in boosted] == [1, 2, 3]

    def test_no_entities_is_passthrough(self) -> None:
        results = [_result("vector", "v1", cve="CVE-1")]
        assert rs.boost_entity_matches(results, cve_ids=[]) == results

    def test_results_without_cve_metadata_are_untouched(self) -> None:
        """无 ``cve_id`` 元数据的结果不加成（如论文片段）。"""
        results = [RetrievalResult(source="vector", doc_id="paper_abstracts:1", metadata={"paper_id": "1"})]
        boosted = rs.boost_entity_matches(results, cve_ids=["CVE-1"])
        assert boosted[0].score == 0.0 and "entity_match" not in boosted[0].route_scores


class TestRenderHelpers:
    """结构化渲染与组件匹配。"""

    def test_component_matches_product_vendor_package(self, sample_unified_vuln: UnifiedVuln) -> None:
        assert rs.component_matches(sample_unified_vuln, "pan-os") is True
        assert rs.component_matches(sample_unified_vuln, "paloaltonetworks") is True
        assert rs.component_matches(sample_unified_vuln, "log4j") is False
        assert rs.component_matches(sample_unified_vuln, "") is False

    def test_component_matches_ecosystem_package(self, sample_unified_vuln: UnifiedVuln) -> None:
        vuln = sample_unified_vuln.model_copy(update={"ecosystem_packages": ["PyPI:django"]})
        assert rs.component_matches(vuln, "django") is True

    def test_component_row_text(self) -> None:
        text = rs.component_row_text(
            "pan-os", {"cve_id": "CVE-1", "risk_score": 90.0, "risk_level": "critical", "title": "T"}
        )
        assert text.startswith("CVE-1（组件 pan-os｜risk=90.0 critical）")

    def test_technique_row_text(self) -> None:
        text = rs.technique_row_text(
            "T1190",
            {"cve_id": "CVE-2024-3400", "risk_score": 75.0, "risk_level": "high", "title": "PAN-OS", "kev": True},
        )
        assert text == "CVE-2024-3400（技术 T1190｜risk=75.0 high，KEV）：PAN-OS"

    def test_graph_result_from_neo4j(self) -> None:
        result = rs.graph_result_from_neo4j(
            "CVE-2024-3400",
            [
                {
                    "component": "PAN-OS",
                    "vendor": "paloaltonetworks",
                    "version_range": "<10.2.9-h1",
                    "assets": ["PAN-OS Firewall"],
                }
            ],
            [{"technique_id": "T1190", "tactic": "initial-access", "step_order": 1, "description": "入口利用"}],
            [{"paper_id": "2404.1", "relation": "mentions", "confidence": 0.6}],
        )
        assert result.source == "graph" and result.doc_id == "graph:CVE-2024-3400"
        assert "组件 PAN-OS" in result.content and "T1190" in result.content and "2404.1" in result.content
        assert result.metadata["components"] == 1 and result.metadata["techniques"] == 1

    def test_render_structured_summary_without_enrichment(self, sample_unified_vuln: UnifiedVuln) -> None:
        text = rs.render_structured_summary(sample_unified_vuln, None)
        assert "受影响版本" in text and "风险级别" not in text

    def test_render_structured_summary_with_enrichment(
        self, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        text = rs.render_structured_summary(sample_unified_vuln, sample_enriched_vuln)
        assert "受影响资产" in text and "攻击技术: T1190(initial-access)" in text
        assert "风险级别: critical" in text


async def _seed(session: Any, vuln: UnifiedVuln, enriched: EnrichedVuln | None) -> None:
    """写入事实层（可选富化层）。"""
    from aisec_intel.storage.repositories.vuln_repo import VulnRepository

    repo = VulnRepository(session)
    await repo.upsert(vuln)
    if enriched is not None:
        await repo.upsert_enriched(enriched)
    await session.flush()


def _vector_store_for(vuln: UnifiedVuln) -> VectorStore:
    """构造含一条漏洞描述的向量库。"""
    store = _store()
    store.upsert(
        COLLECTION_VULN_DESCRIPTIONS,
        [
            VectorDoc(
                doc_id=f"{COLLECTION_VULN_DESCRIPTIONS}:{vuln.vuln_id}",
                content=render_vuln_text(vuln),
                metadata=vuln_index_metadata(vuln),
            )
        ],
    )
    return store


class TestServiceRoutes:
    """四路检索的服务层行为（SQLite + 内存向量库）。"""

    async def test_vector_search_returns_ranked_hits(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln
    ) -> None:
        """向量路：命中同主题文档并标注集合名。"""
        store = _vector_store_for(sample_unified_vuln)
        try:
            service = rs.RetrievalService(db_session, settings=_settings(), vector_store=store)
            results = await service.vector_search("PAN-OS 命令注入")
            assert results and results[0].metadata["cve_id"] == "CVE-2024-3400"
            assert results[0].source == "vector" and results[0].rank == 1
            assert results[0].metadata["collection"] == COLLECTION_VULN_DESCRIPTIONS
        finally:
            store.close()

    async def test_vector_search_empty_store(self, db_session: Any) -> None:
        """空向量库返回空列表（不抛异常）。"""
        store = _store()
        try:
            service = rs.RetrievalService(db_session, settings=_settings(), vector_store=store)
            assert await service.vector_search("任意查询") == []
        finally:
            store.close()

    async def test_fulltext_search_python_fallback(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln
    ) -> None:
        """全文路（SQLite 降级）：英文与中文描述都能被对应语言查询命中。"""
        chinese = sample_unified_vuln.model_copy(
            update={
                "vuln_id": "CVE-2024-8888",
                "title": "命令注入漏洞",
                "description": "PAN-OS 存在命令注入漏洞，攻击者可执行任意命令。",
            }
        )
        await _seed(db_session, sample_unified_vuln, None)
        await _seed(db_session, chinese, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        english = await service.fulltext_search("GlobalProtect command injection")
        assert english and english[0].doc_id == "unified_vuln:CVE-2024-3400"
        assert english[0].score > 0
        zh = await service.fulltext_search("命令注入")
        assert zh and zh[0].doc_id == "unified_vuln:CVE-2024-8888"
        assert await service.fulltext_search("完全无关的关键词zzz") == []

    async def test_graph_search_by_cve(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """图谱路：CVE 结构化展平（含攻击技术与资产）。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        results = await service.graph_search("CVE-2024-3400 影响了哪些资产")
        assert len(results) == 1
        assert results[0].doc_id == "graph:CVE-2024-3400"
        assert "T1190" in results[0].content and "PAN-OS Firewall" in results[0].content

    async def test_graph_search_by_component(self, db_session: Any, sample_unified_vuln: UnifiedVuln) -> None:
        """图谱路：无 CVE 时按组件检索相关漏洞。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        results = await service.graph_search("PAN-OS 相关漏洞", components=["pan-os"])
        assert [item.metadata["hit"] for item in results] == ["component-related"]
        assert results[0].metadata["cve_id"] == "CVE-2024-3400"

    async def test_graph_search_without_entities(self, db_session: Any) -> None:
        """无 CVE / 组件实体时返回空列表（不误报）。"""
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        assert await service.graph_search("怎么提升安全性") == []

    async def test_graph_search_unknown_cve(self, db_session: Any) -> None:
        """未知 CVE 返回空列表。"""
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        assert await service.graph_search("CVE-1999-0001 详情") == []

    async def test_multi_hop_search(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """多跳路：返回两条模式结果并标注跳数来源。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        results = await service.multi_hop_search("CVE-2024-3400")
        assert results and all(item.source == "multi_hop" for item in results)
        assert any(item.metadata["hit"] == "CVE->Component->Asset" for item in results)
        assert results[0].metadata["cve_id"] == "CVE-2024-3400"

    async def test_multi_hop_search_without_cve(self, db_session: Any) -> None:
        """无 CVE 时多跳路返回空列表。"""
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        assert await service.multi_hop_search("没有编号的查询") == []

    async def test_graph_search_by_technique(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """图谱路：无 CVE / 无组件时按 ATT&CK 技术（PG 降级扫描）反查漏洞。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        results = await service.graph_search("和 T1190 相关的漏洞", techniques=["t1190"])
        assert [item.metadata["hit"] for item in results] == ["technique-related"]
        assert results[0].metadata["cve_id"] == "CVE-2024-3400"
        assert "技术 T1190" in results[0].content

    async def test_graph_search_by_technique_no_match(self, db_session: Any, sample_unified_vuln: UnifiedVuln) -> None:
        """无有效技术实体 / 库中无该技术时返回空列表。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        assert await service.graph_search("随便问问", techniques=[]) == []
        assert await service.graph_search("随便问问", techniques=["T9999"]) == []

    async def test_dispatch_unknown_route(self, db_session: Any) -> None:
        """未声明的通路名报错（防止拼错通路静默返回空）。"""
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        with pytest.raises(rs.RetrievalError, match="未声明的检索通路"):
            await service.dispatch("sql", "任意")


class TestHybridSearch:
    """混合检索：并发调度 + RRF 融合 + 单路失败隔离。"""

    async def test_hybrid_search_fuses_three_routes(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """三路并发执行并融合；同一 CVE 合并为一条（多路加分）。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        store = _vector_store_for(sample_unified_vuln)
        try:
            service = rs.RetrievalService(db_session, settings=_settings(), vector_store=store)
            outcome = await service.hybrid_search("CVE-2024-3400 GlobalProtect 命令注入")
            assert set(outcome.plan) == {"vector", "fulltext", "graph"}
            assert outcome.route_counts["vector"] >= 1 and outcome.route_counts["fulltext"] >= 1
            assert outcome.results and outcome.results[0].metadata["cve_id"] == "CVE-2024-3400"
            assert len(outcome.results[0].route_scores) >= 2  # 多路共同命中
            assert outcome.elapsed_ms >= 0
        finally:
            store.close()

    async def test_hybrid_search_custom_plan(self, db_session: Any, sample_unified_vuln: UnifiedVuln) -> None:
        """``plan`` 只执行指定通路（白名单去重）。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        outcome = await service.hybrid_search("CVE-2024-3400", plan=["fulltext", "fulltext", "bogus"])
        assert outcome.plan == ["fulltext"]
        assert set(outcome.route_counts) == {"fulltext"}

    async def test_route_failure_is_isolated(self, db_session: Any, sample_unified_vuln: UnifiedVuln) -> None:
        """单路抛异常时其它路仍返回结果，异常记入 ``errors``。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        original = service.dispatch

        async def _flaky(route: str, *args: Any, **kwargs: Any) -> list[RetrievalResult]:
            if route == "graph":
                raise RuntimeError("模拟图谱不可用")
            return await original(route, *args, **kwargs)

        service.dispatch = _flaky  # type: ignore[method-assign]
        outcome = await service.hybrid_search("CVE-2024-3400 GlobalProtect")
        assert outcome.route_counts["graph"] == 0
        assert any(item.startswith("graph: RuntimeError") for item in outcome.errors)
        assert outcome.results  # 其余两路仍产出

    async def test_hybrid_search_reports_empty_routes(self, db_session: Any) -> None:
        """全空数据时留痕说明（便于前端提示「索引未建」）。"""
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        outcome = await service.hybrid_search("毫无匹配的查询 zzz")
        assert outcome.results == []
        assert len(outcome.errors) == len(outcome.plan)
        assert all("0 命中" in item for item in outcome.errors)

    async def test_hybrid_search_passes_keywords(self, db_session: Any, sample_unified_vuln: UnifiedVuln) -> None:
        """``keywords`` 与查询切词结果合并（中文查询 + 英文补词都能命中）。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        outcome = await service.hybrid_search("该漏洞详情", plan=["fulltext"], keywords=["globalprotect"])
        assert outcome.route_counts["fulltext"] == 1
