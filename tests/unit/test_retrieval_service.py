"""Day10/Day11 混合检索测试（``aisec_intel.services.retrieval_service``，PROJECT_PLAN.md §5.8）。

按「测试范围硬约束」合并：仅覆盖**纯函数算法**（RRF / 过滤器翻译 / 实体键 / 词元切分）
与**检索编排行为**（三路 + 多跳 + 单路失败隔离），每条用例覆盖同类行为的多组输入。
不依赖 PostgreSQL / Neo4j / 网络（SQLite 内存库 + 内存向量库 + 哈希嵌入）。
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

CVE = "CVE-2024-3400"


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


def _result(route: str, doc_id: str, *, cve: str | None = None, content: str = "内容") -> RetrievalResult:
    """构造单路检索结果（测试夹具）。"""
    metadata: dict[str, Any] = {"cve_id": cve} if cve else {}
    return RetrievalResult(source=route, doc_id=doc_id, content=content, metadata=metadata)


async def _seed(session: Any, vuln: UnifiedVuln, enriched: EnrichedVuln | None = None) -> None:
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


class TestPureHelpers:
    """纯函数：词元 / 打分 / tsquery / 实体键 / 过滤器 / RRF / 渲染。"""

    def test_keywords_scores_and_tsquery(self, sample_unified_vuln: UnifiedVuln) -> None:
        """覆盖：去重切词 / 空输入 / 中英打分 / OR 语义 tsquery / 片段渲染。"""
        tokens = rs.query_keywords("PAN-OS 命令注入 PAN-OS")
        assert tokens.count("pan") == 1 and "命令" in tokens
        assert rs.query_keywords("") == []
        assert rs.python_fulltext_score("PAN-OS command injection", ["pan", "injection"]) == 1.0
        assert rs.python_fulltext_score("PAN-OS command injection", ["pan", "zzz"]) == 0.5
        assert rs.python_fulltext_score("PAN-OS", []) == 0.0
        assert rs.build_tsquery(["pan", "os", "注入"]) == "pan | os | 注入"
        assert rs.build_tsquery(["CVE-2024-3400", "cve", "a", "!!!"]) == "CVE | 2024 | 3400"
        assert rs.build_tsquery(["a", "--"]) == ""
        snippet = rs.fulltext_snippet(sample_unified_vuln, limit=20)
        assert snippet.startswith(CVE) and len(snippet.splitlines()) == 2

    def test_canonical_key_and_payload_preference(self) -> None:
        """实体键优先 CVE → 论文 → doc_id；代表结果取信息量更大者。"""
        assert rs.canonical_key(_result("vector", "x", cve="cve-2024-3400")) == "cve:CVE-2024-3400"
        assert rs.canonical_key(RetrievalResult(source="vector", doc_id="p", metadata={"paper_id": "1"})) == "paper:1"
        assert rs.canonical_key(_result("graph", "graph:CVE-1")) == "graph:CVE-1"
        short, long = _result("vector", "a", content="s"), _result("fulltext", "b", content="much longer")
        assert rs.prefer_payload(long, short) is True and rs.prefer_payload(short, long) is False
        assert rs.prefer_payload(_result("vector", "a"), _result("fulltext", "b")) is True

    @pytest.mark.parametrize(
        ("filters", "expected"),
        [
            (None, None),
            (QueryFilters(), None),
            (QueryFilters(severity=["CRITICAL", "HIGH"]), {"severity": {"$in": ["CRITICAL", "HIGH"]}}),
            (QueryFilters(kev_only=True), {"kev": "true"}),
            (
                {"severity": ["CRITICAL"], "kev_only": True},
                {"$and": [{"severity": {"$in": ["CRITICAL"]}}, {"kev": "true"}]},
            ),
        ],
    )
    def test_vector_where_from_filters(self, filters: Any, expected: Any) -> None:
        """过滤器 → Chroma ``where``（无过滤为 ``None``，多条件用 ``$and``）。"""
        assert rs.vector_where_from_filters(filters) == expected

    def test_time_range_translates_to_iso_cutoff(self) -> None:
        """时间范围翻译为 ISO8601 下界（字典序即时间序）。"""
        where = rs.vector_where_from_filters(
            QueryFilters(time_range="recent_30d"), now=datetime(2026, 1, 31, tzinfo=UTC)
        )
        assert where == {"published_at": {"$gte": "2026-01-01T00:00:00Z"}}

    def test_rrf_fusion_behavior(self) -> None:
        """RRF：多路共同命中加分、权重可调、``top_k`` 生效、排名重编号、同路重复只计一次。"""
        channels = {
            "vector": [_result("vector", "v1", cve="CVE-1"), _result("vector", "v2", cve="CVE-2")],
            "fulltext": [_result("fulltext", "f1", cve="CVE-2")],
        }
        fused = rs.reciprocal_rank_fusion(channels)
        assert [item.metadata["cve_id"] for item in fused] == ["CVE-2", "CVE-1"]
        assert fused[0].route_scores.keys() == {"vector", "fulltext"} and fused[0].rank == 1
        assert rs.reciprocal_rank_fusion(channels, weights={"fulltext": 3.0})[0].metadata["cve_id"] == "CVE-2"
        assert len(rs.reciprocal_rank_fusion(channels, top_k=1)) == 1
        assert rs.reciprocal_rank_fusion({}) == []
        assert len(rs.reciprocal_rank_fusion({"vector": [_result("vector", "v1", cve="CVE-1")] * 2})) == 1

    def test_entity_boost_moves_exact_match_first(self) -> None:
        """实体加成：查询直指的 CVE 提到最前；无 CVE 元数据的结果不受影响。"""
        results = [
            _result("vector", "v1", cve="CVE-2024-33331"),
            _result("graph", "g1", cve=CVE),
            _result("vector", "v2", cve="CVE-2026-19490"),
        ]
        boosted = rs.boost_entity_matches(results, cve_ids=[CVE.lower()])
        assert [item.metadata["cve_id"] for item in boosted] == [CVE, "CVE-2024-33331", "CVE-2026-19490"]
        assert boosted[0].route_scores["entity_match"] == rs.DEFAULT_ENTITY_BONUS
        assert rs.boost_entity_matches(results, cve_ids=[]) == results
        paper = RetrievalResult(source="vector", doc_id="paper_abstracts:1", metadata={"paper_id": "1"})
        assert "entity_match" not in rs.boost_entity_matches([paper], cve_ids=[CVE])[0].route_scores

    def test_render_helpers(self, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln) -> None:
        """组件匹配 / 行文本渲染 / 图谱结果 / 结构化摘要（含无富化分支）。"""
        assert rs.component_matches(sample_unified_vuln, "pan-os") is True
        assert rs.component_matches(sample_unified_vuln, "log4j") is False
        with_package = sample_unified_vuln.model_copy(update={"ecosystem_packages": ["PyPI:django"]})
        assert rs.component_matches(with_package, "django") is True
        assert rs.component_row_text("pan-os", {"cve_id": "CVE-1", "risk_score": 90.0}).startswith("CVE-1（组件 pan-os")
        assert "技术 T1190" in rs.technique_row_text("T1190", {"cve_id": CVE, "risk_level": "high", "kev": True})
        graph_result = rs.graph_result_from_neo4j(
            CVE,
            [{"component": "PAN-OS", "vendor": "paloaltonetworks", "assets": ["PAN-OS Firewall"]}],
            [{"technique_id": "T1190", "tactic": "initial-access", "step_order": 1, "description": "入口利用"}],
            [{"paper_id": "2404.1", "relation": "mentions", "confidence": 0.6}],
        )
        assert graph_result.doc_id == f"graph:{CVE}" and graph_result.metadata["techniques"] == 1
        assert "风险级别" not in rs.render_structured_summary(sample_unified_vuln, None)
        assert "攻击技术: T1190(initial-access)" in rs.render_structured_summary(
            sample_unified_vuln, sample_enriched_vuln
        )


class TestServiceRoutes:
    """四路检索服务层行为（SQLite + 内存向量库）。"""

    async def test_vector_and_fulltext_routes(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln
    ) -> None:
        """向量路命中同主题文档；全文路英文/中文各自命中且不误报；空库返回空。"""
        store = _vector_store_for(sample_unified_vuln)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=store)
        try:
            vectors = await service.vector_search("PAN-OS 命令注入")
            assert vectors and vectors[0].metadata["cve_id"] == CVE and vectors[0].rank == 1
            assert vectors[0].metadata["collection"] == COLLECTION_VULN_DESCRIPTIONS
            empty = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
            assert await empty.vector_search("任意查询") == []
        finally:
            store.close()

        chinese = sample_unified_vuln.model_copy(
            update={"vuln_id": "CVE-2024-8888", "title": "命令注入漏洞", "description": "PAN-OS 存在命令注入漏洞。"}
        )
        await _seed(db_session, sample_unified_vuln, None)
        await _seed(db_session, chinese, None)
        english = await service.fulltext_search("GlobalProtect command injection")
        assert english[0].doc_id == "unified_vuln:CVE-2024-3400"
        zh = await service.fulltext_search("命令注入")
        assert zh and zh[0].doc_id == "unified_vuln:CVE-2024-8888"
        assert await service.fulltext_search("完全无关的关键词zzz") == []

    async def test_graph_route_by_cve_component_and_technique(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """图谱路三种命中口径（CVE / 组件 / ATT&CK 技术）+ 无实体与未知 CVE 返回空。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        by_cve = await service.graph_search(f"{CVE} 影响了哪些资产")
        assert by_cve[0].doc_id == f"graph:{CVE}" and "T1190" in by_cve[0].content
        by_component = await service.graph_search("PAN-OS 相关漏洞", components=["pan-os"])
        assert by_component[0].metadata["hit"] == "component-related"
        by_technique = await service.graph_search("和 T1190 相关的漏洞", techniques=["t1190"])
        assert by_technique[0].metadata["hit"] == "technique-related" and "技术 T1190" in by_technique[0].content
        assert await service.graph_search("怎么提升安全性") == []
        assert await service.graph_search("CVE-1999-0001 详情") == []
        assert await service.graph_search("随便问问", techniques=["T9999"]) == []

    async def test_multi_hop_route_and_dispatch_guard(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """多跳路返回两条模式结果；未声明的通路名报错（不静默返回空）。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        results = await service.multi_hop_search(CVE)
        assert results and all(item.source == "multi_hop" for item in results)
        assert any(item.metadata["hit"] == "CVE->Component->Asset" for item in results)
        assert await service.multi_hop_search("没有编号的查询") == []
        with pytest.raises(rs.RetrievalError, match="未声明的检索通路"):
            await service.dispatch("sql", "任意")


class TestHybridSearch:
    """混合检索：并发调度 + RRF 融合 + 单路失败隔离。"""

    async def test_fuses_three_routes_and_boosts_exact_cve(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """三路并发执行并融合；同一 CVE 合并为一条且被实体加成提到首位。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        store = _vector_store_for(sample_unified_vuln)
        try:
            service = rs.RetrievalService(db_session, settings=_settings(), vector_store=store)
            outcome = await service.hybrid_search(f"{CVE} GlobalProtect 命令注入")
            assert set(outcome.plan) == {"vector", "fulltext", "graph"}
            assert outcome.route_counts["vector"] >= 1 and outcome.route_counts["fulltext"] >= 1
            assert outcome.results[0].metadata["cve_id"] == CVE
            assert len(outcome.results[0].route_scores) >= 2
        finally:
            store.close()

    async def test_plan_filter_and_keyword_merge(self, db_session: Any, sample_unified_vuln: UnifiedVuln) -> None:
        """``plan`` 白名单去重生效；``keywords`` 与查询切词合并后可命中。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        outcome = await service.hybrid_search(CVE, plan=["fulltext", "fulltext", "bogus"])
        assert outcome.plan == ["fulltext"] and set(outcome.route_counts) == {"fulltext"}
        merged = await service.hybrid_search("该漏洞详情", plan=["fulltext"], keywords=["globalprotect"])
        assert merged.route_counts["fulltext"] == 1

    async def test_route_failure_isolated_and_empty_reported(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln
    ) -> None:
        """单路抛异常时其它路仍产出并留痕；全空数据时每路都给出 0 命中说明。"""
        await _seed(db_session, sample_unified_vuln, None)
        service = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        original = service.dispatch

        async def _flaky(route: str, *args: Any, **kwargs: Any) -> list[RetrievalResult]:
            if route == "graph":
                raise RuntimeError("模拟图谱不可用")
            return await original(route, *args, **kwargs)

        service.dispatch = _flaky  # type: ignore[method-assign]
        outcome = await service.hybrid_search(f"{CVE} GlobalProtect")
        assert outcome.route_counts["graph"] == 0
        assert any(item.startswith("graph: RuntimeError") for item in outcome.errors)
        assert outcome.results

        empty = rs.RetrievalService(db_session, settings=_settings(), vector_store=_store())
        blank = await empty.hybrid_search("毫无匹配的查询 zzz")
        assert blank.results == [] and len(blank.errors) == len(blank.plan)
