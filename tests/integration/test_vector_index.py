"""Day10 向量索引集成测试（``scripts/index_vectors`` + ``storage/vector_store``，§5.7）。

端到端链路：临时 SQLite 文件库（真实写盘）→ 三张表灌数 → 纯函数渲染 → 写入 Chroma
内存向量库 → 检索命中。嵌入走 **hashing** 后端，因此**不需要 PostgreSQL / Neo4j / 网络**。
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install 'sqlalchemy[asyncio]' aiosqlite")
pytest.importorskip("chromadb", reason="需要 chromadb：pip install chromadb")

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models.enriched_vuln import EnrichedVuln  # noqa: E402
from aisec_intel.models.raw_item import RawItem  # noqa: E402
from aisec_intel.models.unified_vuln import UnifiedVuln  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    dispose_engines,
    get_engine,
    init_models,
    session_scope,
)
from aisec_intel.storage.models.raw import RawItemRow  # noqa: E402
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402
from aisec_intel.storage.vector_store import (  # noqa: E402
    COLLECTION_PAPER_ABSTRACTS,
    COLLECTION_REMEDIATION_TEXTS,
    COLLECTION_VULN_DESCRIPTIONS,
    COLLECTIONS,
    VectorStore,
)
from scripts import index_vectors as iv  # noqa: E402


def _settings_for(tmp_path: Path) -> Settings:
    """构造指向临时 SQLite 文件库的配置（真实落盘，验证跨进程可用性）。"""
    dsn = f"sqlite+aiosqlite:///{(tmp_path / 'aisec.db').as_posix()}"
    return Settings(
        database_url=dsn,
        embedding_backend="hashing",
        embedding_dim=64,
        neo4j_enabled=False,
        chroma_path=str(tmp_path / "chroma"),
    )


def _paper_raw_item(sample_paper: Any) -> RawItem:
    """把 ``Paper`` 转成 ``raw_item`` 行所需的采集件（arxiv 条目级 JSON）。"""
    from aisec_intel.models.base import utc_now

    raw_text = (
        '{"arxiv_id": "2404.12345", "title": "Command Injection in Edge Devices: A Survey",'
        ' "summary": "We survey command injection vulnerabilities in edge network devices.",'
        ' "authors": ["A. Researcher"], "abstract_url": "http://arxiv.org/abs/2404.12345"}'
    )
    return RawItem(
        trace_id="t-paper",
        source="arxiv",
        source_id=sample_paper.paper_id,
        url="http://arxiv.org/abs/2404.12345",
        title=sample_paper.title,
        raw_text=raw_text,
        lang="en",
        published_at=utc_now(),
        fetched_at=utc_now(),
        sha256="b" * 64,
        meta={"category": "cs.CR"},
    )


async def _prepare_db(
    settings: Settings,
    vuln: UnifiedVuln,
    enriched: EnrichedVuln,
    paper_item: RawItem | None = None,
) -> None:
    """建表并灌入 unified / enriched（可选注入 raw_item 论文行）。"""
    engine = get_engine(settings)
    await init_models(engine)
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        await repo.upsert(vuln)
        await repo.upsert_enriched(enriched)
        if paper_item is not None:
            session.add(RawItemRow.from_domain(paper_item))


def _store() -> VectorStore:
    """内存态向量库（清空共享内存系统保证隔离）。"""
    store = VectorStore.ephemeral(dim=64)
    for existing in store.client.list_collections():
        store.client.delete_collection(existing.name)
    return store


class TestTargetCollections:
    """命令行集合名展开。"""

    def test_all_expands_to_three(self) -> None:
        assert iv.target_collections("all") == list(COLLECTIONS)

    def test_single_collection(self) -> None:
        assert iv.target_collections(COLLECTION_VULN_DESCRIPTIONS) == [COLLECTION_VULN_DESCRIPTIONS]

    def test_unknown_returns_empty(self) -> None:
        assert iv.target_collections("qa_memory") == []


class TestDocBuilders:
    """三张表 → 向量文档（含元数据）的渲染。"""

    async def test_all_builders(
        self, tmp_path: Path, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln, sample_paper: Any
    ) -> None:
        settings = _settings_for(tmp_path)
        await _prepare_db(settings, sample_unified_vuln, sample_enriched_vuln, _paper_raw_item(sample_paper))
        try:
            vuln_docs = await iv.build_vuln_docs(settings, limit=10)
            assert [doc.doc_id for doc in vuln_docs] == [f"{COLLECTION_VULN_DESCRIPTIONS}:CVE-2024-3400"]
            assert vuln_docs[0].metadata["severity"] == "CRITICAL"
            assert "PAN-OS" in vuln_docs[0].content

            remediation_docs = await iv.build_remediation_docs(settings, limit=10)
            assert remediation_docs[0].doc_id == f"{COLLECTION_REMEDIATION_TEXTS}:CVE-2024-3400"
            assert "处置动作" in remediation_docs[0].content
            assert remediation_docs[0].metadata["risk_level"] == "critical"

            paper_docs = await iv.build_paper_docs(settings, limit=10)
            assert paper_docs[0].doc_id == f"{COLLECTION_PAPER_ABSTRACTS}:2404.12345"
            assert paper_docs[0].metadata["source"] == "arxiv"
            assert "Command Injection" in paper_docs[0].content
        finally:
            await dispose_engines()

    async def test_empty_database_returns_no_docs(self, tmp_path: Path) -> None:
        """空库返回空列表（不抛异常）。"""
        settings = _settings_for(tmp_path)
        await init_models(get_engine(settings))
        try:
            assert await iv.build_vuln_docs(settings, limit=5) == []
            assert await iv.build_remediation_docs(settings, limit=5) == []
            assert await iv.build_paper_docs(settings, limit=5) == []
        finally:
            await dispose_engines()


class TestIndexCollection:
    """单集合索引：写入条数、检索命中、重建幂等。"""

    async def test_index_writes_and_is_searchable(
        self, tmp_path: Path, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln, sample_paper: Any
    ) -> None:
        settings = _settings_for(tmp_path)
        await _prepare_db(settings, sample_unified_vuln, sample_enriched_vuln, _paper_raw_item(sample_paper))
        store = _store()
        try:
            for collection in COLLECTIONS:
                written, elapsed = await iv.index_collection(
                    store, settings, collection, limit=10, rebuild=False, dry_run=False
                )
                assert written == 1 and elapsed >= 0
            assert store.stats() == {
                COLLECTION_VULN_DESCRIPTIONS: 1,
                COLLECTION_PAPER_ABSTRACTS: 1,
                COLLECTION_REMEDIATION_TEXTS: 1,
            }
            hits = store.query(COLLECTION_VULN_DESCRIPTIONS, "PAN-OS 命令注入")
            assert hits and hits[0].metadata["cve_id"] == "CVE-2024-3400"
            remedy = store.query(COLLECTION_REMEDIATION_TEXTS, "升级 处置")
            assert remedy and "处置动作" in remedy[0].content
        finally:
            store.close()
            await dispose_engines()

    async def test_rebuild_is_idempotent(
        self, tmp_path: Path, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``--rebuild`` 后条数不翻倍（先清空再写入）。"""
        settings = _settings_for(tmp_path)
        await _prepare_db(settings, sample_unified_vuln, sample_enriched_vuln)
        store = _store()
        try:
            for _ in range(2):
                written, _ = await iv.index_collection(
                    store, settings, COLLECTION_VULN_DESCRIPTIONS, limit=10, rebuild=True, dry_run=False
                )
                assert written == 1
            assert store.count(COLLECTION_VULN_DESCRIPTIONS) == 1
        finally:
            store.close()
            await dispose_engines()

    async def test_dry_run_writes_nothing(
        self, tmp_path: Path, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``dry_run`` 只读库，不写向量。"""
        settings = _settings_for(tmp_path)
        await _prepare_db(settings, sample_unified_vuln, sample_enriched_vuln)
        store = _store()
        try:
            written, _ = await iv.index_collection(
                store, settings, COLLECTION_VULN_DESCRIPTIONS, limit=10, rebuild=False, dry_run=True
            )
            assert written == 0
            assert store.count(COLLECTION_VULN_DESCRIPTIONS) == 0
        finally:
            store.close()
            await dispose_engines()


class TestCli:
    """命令行入口（``python -m scripts.index_vectors``）。"""

    def test_cli_indexes_all_and_prints_stats(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], sample_unified_vuln: UnifiedVuln,
        sample_enriched_vuln: EnrichedVuln, sample_paper: Any,
    ) -> None:
        """CLI 全量索引：退出码 0、打印各集合统计与合计耗时。"""
        settings = _settings_for(tmp_path)
        asyncio.run(_prepare_db(settings, sample_unified_vuln, sample_enriched_vuln, _paper_raw_item(sample_paper)))
        try:
            code = iv.main(
                [
                    "--dsn",
                    settings.effective_storage_dsn,
                    "--ephemeral",
                    "--embedding-backend",
                    "hashing",
                    "--limit",
                    "10",
                ]
            )
            output = capsys.readouterr().out
            assert code == 0
            for collection in COLLECTIONS:
                assert collection in output
            assert "写入=1" in output
            assert "[向量库统计]" in output and "[合计]" in output
        finally:
            asyncio.run(dispose_engines())

    def test_cli_dry_run(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        sample_unified_vuln: UnifiedVuln,
        sample_enriched_vuln: EnrichedVuln,
    ) -> None:
        """CLI ``--dry-run``：只读不写，输出 dry-run 标记。"""
        settings = _settings_for(tmp_path)
        asyncio.run(_prepare_db(settings, sample_unified_vuln, sample_enriched_vuln))
        try:
            code = iv.main(
                [
                    "--dsn",
                    settings.effective_storage_dsn,
                    "--ephemeral",
                    "--embedding-backend",
                    "hashing",
                    "--dry-run",
                    "--limit",
                    "5",
                ]
            )
            output = capsys.readouterr().out
            assert code == 0
            assert "dry-run" in output
            assert "写入=0" in output
        finally:
            asyncio.run(dispose_engines())
