"""Day25 阶段 2 任务 2.5/2.6：缺口 → 受控外部检索 → 复核 的端到端集成测试。

链路：本地检索（真实 ``RetrievalService`` + SQLite 内存库）→ ``gap_checker`` →
``external_retriever``（4 个权威源用 ``httpx.MockTransport`` 桩，**不触网**）→
``verifier`` → ``reasoner`` → ``synthesizer``，并校验 ``external_evidence`` 隔离表落库。

断言：
    1. 本地证据不足（缺修复版本）→ 触发外部检索，引文含外部源，答案包含外部给出的修复版本；
    2. ``external_evidence`` 表有记录；
    3. 本地证据充足 → **不**触发外部检索，表内不新增记录。

Note:
    本文件属集成测试（需要 sqlalchemy / aiosqlite）；默认 ``-m "not integration"`` 不参与离线快速回归，
    显式运行：``python -m pytest -m integration tests/integration/test_external_retrieval_flow.py``。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.models.unified_vuln import CpeMatch, UnifiedVuln
from aisec_intel.qa.agents import external_retriever as er
from aisec_intel.qa.agents.synthesizer import FIXED_VERSION_PHRASE
from aisec_intel.qa.graph import run_qa
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.external_evidence_repo import ExternalEvidenceRepository
from aisec_intel.storage.vector_store import VectorStore
from tests.unit.test_external_retriever import GHSA_PAYLOAD, KEV_PAYLOAD, NVD_PAYLOAD, OSV_PAYLOAD

pytestmark = pytest.mark.integration

CVE = "CVE-2024-34359"
QUESTION = "CVE-2024-34359 应升级到哪个版本"


def _settings() -> Settings:
    """集成测试配置：离线嵌入 + 关 Neo4j + 开外部检索（HTTP 走 MockTransport）。"""
    return Settings(
        llm_api_key="",
        embedding_backend="hashing",
        embedding_dim=64,
        neo4j_enabled=False,
        qa_external_enabled=True,
        github_token="gh-token",
        nvd_api_key="nvd-key",
    )


def _vuln(*, with_versions: bool) -> UnifiedVuln:
    """构造一条 ``CVE-2024-34359`` 事实（可选带受影响版本，用于对照「本地是否足够」）。"""
    from aisec_intel.models.base import utc_now

    payload: dict[str, Any] = {
        "vuln_id": CVE,
        "title": "llama-cpp-python SSTI",
        "description": f"{CVE} 是 fsspec/llama-cpp-python 的服务器端模板注入漏洞。",
        "severity": "HIGH",
        "published_at": utc_now(),
        "normalized_at": utc_now(),
        "sources": ["nvd"],
    }
    if with_versions:
        payload["affected_versions"] = ["PyPI:llama-cpp-python >=0.2.30, <=0.2.71"]
        payload["cpe_matches"] = [CpeMatch(vendor="pypi", product="llama-cpp-python")]
    return UnifiedVuln(**payload)


async def _seed(session: Any, vuln: UnifiedVuln) -> None:
    """写入事实层（向量库留空，走图谱 / 全文通路）。"""
    from aisec_intel.storage.repositories.vuln_repo import VulnRepository

    await VulnRepository(session).upsert(vuln)
    await session.flush()


def _register_sources(mock_router: Any) -> None:
    """登记 4 个权威源的响应（离线桩）。"""
    mock_router.always(er.NVD_API_URL, json_body=NVD_PAYLOAD)
    mock_router.always(er.GITHUB_GRAPHQL_URL, json_body=GHSA_PAYLOAD)
    mock_router.always(er.OSV_VULN_URL_TEMPLATE.format(vuln_id=CVE), json_body=OSV_PAYLOAD)
    mock_router.always(er.KEV_CATALOG_URL, json_body=KEV_PAYLOAD)


class TestGapDrivenExternalRetrieval:
    """缺口驱动分支与「本地足够」短路的端到端对照。"""

    async def test_missing_fixed_version_triggers_external_and_persists(
        self, memory_engine: Any, mock_router: Any, mock_http: Any
    ) -> None:
        """缺修复版本 → 触发外部检索 → 引文含外部源 → 答案含外部修复版本 → 落隔离表。"""
        from aisec_intel.services.retrieval_service import RetrievalService

        _register_sources(mock_router)
        settings = _settings()
        async with session_scope(memory_engine) as session:
            await _seed(session, _vuln(with_versions=False))
            store = VectorStore.ephemeral(dim=64)
            service = RetrievalService(session, settings=settings, vector_store=store)
            try:
                response, state = await run_qa(
                    service,
                    QUESTION,
                    settings=settings,
                    use_llm=False,
                    session_factory=lambda: session_scope(memory_engine),
                    external_http=mock_http,
                )
            finally:
                await service.aclose()
                store.close()

        assert state["gap_report"] is not None
        assert "fixed_version" in state["gap_report"].missing
        assert mock_router.call_count(er.GITHUB_GRAPHQL_URL) == 1
        assert any(citation.source_type == "external" for citation in response.citations)
        verification = state["external_verification"]
        assert verification is not None and verification.accepted >= 1
        assert "fixed_version" in verification.verified_facts
        assert any("0.2.72" in item.snippet for item in state["external_evidence"])
        assert FIXED_VERSION_PHRASE in response.answer  # 缺口声明（Day25 任务 1.3）

        async with session_scope(memory_engine) as session:
            repo = ExternalEvidenceRepository(session)
            assert await repo.count(cve_id=CVE) >= 1
            rows = await repo.list_by_cve(CVE)
        assert any(row.source_type == "ghsa" and row.verified for row in rows)

    async def test_local_evidence_sufficient_skips_external(
        self, memory_engine: Any, mock_router: Any, mock_http: Any
    ) -> None:
        """本地事实齐备（组件 + 版本）→ 不触发外部检索，隔离表无记录。"""
        from aisec_intel.services.retrieval_service import RetrievalService

        _register_sources(mock_router)
        settings = _settings()
        async with session_scope(memory_engine) as session:
            await _seed(session, _vuln(with_versions=True))
            store = VectorStore.ephemeral(dim=64)
            service = RetrievalService(session, settings=settings, vector_store=store)
            try:
                response, state = await run_qa(
                    service,
                    "CVE-2024-34359 影响哪些资产",
                    settings=settings,
                    use_llm=False,
                    session_factory=lambda: session_scope(memory_engine),
                    external_http=mock_http,
                )
            finally:
                await service.aclose()
                store.close()

        assert state["gap_report"] is not None and state["gap_report"].has_enough is True
        assert mock_router.calls == []  # 完全未发起外部请求
        assert all(citation.source_type != "external" for citation in response.citations)

        async with session_scope(memory_engine) as session:
            assert await ExternalEvidenceRepository(session).count() == 0

