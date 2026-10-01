"""Day10 多跳遍历集成测试（真实 Neo4j，PROJECT_PLAN.md §5.7 / §5.8）。

前置：``docker compose up -d neo4j``（``NEO4J_URI`` 指向该实例）。
未起容器 / 无法连接时**自动跳过**，保证离线环境下 ``python -m pytest`` 仍然全绿。

运行方式::

    python -m pytest -m integration tests/integration/test_multi_hop_graph.py -q
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install 'sqlalchemy[asyncio]' aiosqlite")
pytest.importorskip("neo4j", reason="需要 neo4j 驱动：pip install neo4j")

from aisec_intel.config import get_settings  # noqa: E402
from aisec_intel.graph.extractor import extract_graph  # noqa: E402
from aisec_intel.models.enriched_vuln import EnrichedVuln  # noqa: E402
from aisec_intel.qa.multi_hop import PATTERN_CVE_ASSET, MultiHopTraversal  # noqa: E402
from aisec_intel.storage.neo4j_client import Neo4jClient  # noqa: E402
from aisec_intel.storage.repositories.graph_repo import GraphRepository  # noqa: E402

pytestmark = pytest.mark.integration


@pytest.fixture()
async def neo4j_client() -> Any:
    """提供可用 Neo4j 客户端（不可用时 skip）。"""
    client = Neo4jClient(get_settings())
    if not await client.ping():
        await client.aclose()
        pytest.skip("Neo4j 不可用（请先 docker compose up -d neo4j）")
    yield client
    await client.aclose()


class TestMultiHopAgainstNeo4j:
    """真实图库上的 2 跳查询（幂等写入 + 只读遍历）。"""

    async def test_cve_to_assets_two_hop(
        self, neo4j_client: Any, db_session: Any, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """灌图后 ``CVE → Component → Asset`` 能沿真实边走到资产节点。"""
        repo = GraphRepository(neo4j_client)
        await repo.ensure_schema()
        await repo.upsert_many(extract_graph(sample_enriched_vuln))
        try:
            traversal = MultiHopTraversal(
                db_session, graph_client=neo4j_client, prefer_graph=True
            )
            result = await traversal.cve_to_assets("CVE-2024-3400")
            assert result.source == "neo4j" and result.degraded is False
            assert result.pattern == PATTERN_CVE_ASSET
            assert result.paths, "图中应存在 AFFECTS 边"
            assert any(path.hops == 2 for path in result.paths)
        finally:
            await repo.delete_vulnerability("CVE-2024-3400")
