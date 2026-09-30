"""P6 图谱写入集成测试（PROJECT_PLAN.md §5.7 ``tests/integration/test_graph_write.py``）。

**需要真实 Neo4j**（``docker compose up -d neo4j``）：

    python -m pytest tests/integration/test_graph_write.py -m integration -q -s

未启动 / 未启用（``NEO4J_ENABLED=false``）时**整体 skip**，不阻塞离线测试。
用例使用固定测试编号 ``CVE-2099-0001``，结束时清理自己写入的子图（不污染演示数据）。
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.graph.extractor import extract_graph
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import (
    AffectedAsset,
    AttackChain,
    AttackChainStep,
    EnrichedVuln,
)
from aisec_intel.models.unified_vuln import CpeMatch, CVSSVector
from aisec_intel.storage.neo4j_client import Neo4jClient, Neo4jUnavailableError
from aisec_intel.storage.repositories.graph_repo import GraphRepository

pytestmark = pytest.mark.integration

TEST_CVE = "CVE-2099-0001"
"""测试专用漏洞编号（避免与演示数据冲突）。"""

TEST_VENDOR = "aisec-test"
"""测试专用 CPE 厂商（避免与真实组件键 ``paloaltonetworks:pan-os`` 冲突）。"""

TEST_PRODUCT = "graph-it"
"""测试专用 CPE 产品。"""

TEST_ASSET = "Graph IT Host"
"""测试专用资产名。"""

TEST_TECHNIQUES = ("T9901", "T9902")
"""测试专用 ATT&CK 技术 ID（真实数据不会用到 T99xx 段，避免键冲突）。"""

TEST_KEYS: tuple[tuple[str, str, str], ...] = (
    ("Component", "key", f"{TEST_VENDOR}:{TEST_PRODUCT}"),
    ("Asset", "key", f"device:{TEST_ASSET}"),
    ("AttackTechnique", "technique_id", TEST_TECHNIQUES[0]),
    ("AttackTechnique", "technique_id", TEST_TECHNIQUES[1]),
)
"""测试写入的附属节点（清理时按标签 + 键属性逐个删除，保证不留残留）。"""

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def make_test_enriched(**overrides: Any) -> EnrichedVuln:
    """构造测试用富化实体（自带 CPE / 资产 / 攻击链，覆盖 2 跳查询）。

    Note:
        刻意在本文件中就地构造（不复用单测夹具），保证集成测试**自包含**、
        不依赖 ``tests/unit`` 的导入路径假设。
    """
    payload: dict[str, Any] = {
        "vuln_id": TEST_CVE,
        "title": "Integration Test Vulnerability",
        "description": "Synthetic record for graph integration test.",
        "severity": "CRITICAL",
        "cvss": [CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")],
        "cwe_ids": ["CWE-77"],
        "cpe_matches": [CpeMatch(vendor=TEST_VENDOR, product=TEST_PRODUCT, version_end_excl="10.2.9-h1")],
        "ecosystem_packages": [],
        "references": [],
        "kev": True,
        "sources": ["nvd"],
        "trace_ids": ["trace-graph-it"],
        "normalized_at": utc_now(),
        "affected_assets": [
            AffectedAsset(
                asset_type="device",
                name=TEST_ASSET,
                confidence=0.6,
                evidence_refs=["trace-graph-it"],
            )
        ],
        "related_papers": [],
        "exploits": [],
        "risk_score": 97.0,
        "risk_level": "critical",
        "attack_chain": AttackChain(
            steps=[
                AttackChainStep(
                    order=1,
                    technique_id=TEST_TECHNIQUES[0],
                    tactic="initial-access",
                    stage="Exploitation",
                    description="测试用初始访问",
                ),
                AttackChainStep(
                    order=2,
                    technique_id=TEST_TECHNIQUES[1],
                    tactic="execution",
                    stage="Execution",
                    description="测试用命令执行",
                ),
            ],
            entry_vector="测试入口",
            privileges_required="none",
        ),
        "confidence": 0.9,
        "review_status": "auto_pass",
        "agent_trace": [],
        "model_used": "deepseek-chat",
        "enriched_at": utc_now(),
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


async def cleanup_test_subgraph(repo: GraphRepository) -> None:
    """删除测试写入的全部节点（漏洞 + 附属节点），保证用例可重复运行且不留残留。

    Args:
        repo: 图谱仓储。
    """
    await repo.delete_vulnerability(TEST_CVE)
    for label, prop, value in TEST_KEYS:
        await repo.client.run(f"MATCH (n:{label} {{{prop}: $value}}) DETACH DELETE n", {"value": value})
    await repo.delete_dangling(TEST_CVE)


@pytest.fixture()
async def graph_repo() -> AsyncIterator[GraphRepository]:
    """提供已连接 Neo4j 的仓储；不可用时 skip，前后各清理一次测试子图。"""
    settings = Settings()
    client = Neo4jClient(settings)
    try:
        if not await client.ping():
            pytest.skip(f"Neo4j 不可用：{settings.neo4j_uri}")
    except Neo4jUnavailableError as exc:
        pytest.skip(f"Neo4j 不可用：{exc}")
    repo = GraphRepository(client)
    await repo.ensure_schema()
    await cleanup_test_subgraph(repo)
    try:
        yield repo
    finally:
        await cleanup_test_subgraph(repo)
        await client.aclose()


class TestGraphWrite:
    """写入幂等性与四个查询接口。"""

    async def test_upsert_is_idempotent(self, graph_repo: GraphRepository) -> None:
        """同一抽取结果重复灌图不产生重复节点/边（节点数与边数不变）。"""
        result = extract_graph(make_test_enriched())

        first = await graph_repo.upsert_many(result)
        after_first = await graph_repo.count_nodes()
        await graph_repo.upsert_many(result)
        after_second = await graph_repo.count_nodes()

        assert first["nodes"] == len(result.nodes)
        assert after_first == after_second

    async def test_vulnerability_node_is_queryable(self, graph_repo: GraphRepository) -> None:
        """Neo4j Browser 等价查询：按 ``cve_id`` 取回节点属性。"""
        await graph_repo.upsert_many(extract_graph(make_test_enriched()))

        rows = await graph_repo.client.run(
            "MATCH (v:Vulnerability {cve_id: $cve_id}) RETURN v.cve_id AS cve_id, v.risk_level AS risk_level",
            {"cve_id": TEST_CVE},
        )
        assert rows == [{"cve_id": TEST_CVE, "risk_level": "critical"}]

    async def test_get_affected_assets(self, graph_repo: GraphRepository) -> None:
        """``get_affected_assets`` 返回组件与安装资产（2 跳）。"""
        await graph_repo.upsert_many(extract_graph(make_test_enriched()))

        rows = await graph_repo.get_affected_assets(TEST_CVE)
        assert rows
        assert rows[0]["component"] == TEST_PRODUCT
        assert rows[0]["assets"] == [TEST_ASSET]

    async def test_get_attack_chain(self, graph_repo: GraphRepository) -> None:
        """``get_attack_chain`` 按 ``order`` 升序返回 ATT&CK 技术。"""
        await graph_repo.upsert_many(extract_graph(make_test_enriched()))

        chain = await graph_repo.get_attack_chain(TEST_CVE)
        assert [row["technique_id"] for row in chain] == list(TEST_TECHNIQUES)
        assert [row["step_order"] for row in chain] == [1, 2]

    async def test_get_related_cves_by_component(self, graph_repo: GraphRepository) -> None:
        """``get_related_cves`` 按组件键反查漏洞。"""
        await graph_repo.upsert_many(extract_graph(make_test_enriched()))

        rows = await graph_repo.get_related_cves(f"{TEST_VENDOR}:{TEST_PRODUCT}")
        assert TEST_CVE in {row["cve_id"] for row in rows}

    async def test_get_related_papers_returns_empty_when_none(self, graph_repo: GraphRepository) -> None:
        """无关联论文时返回空列表（不报错）。"""
        await graph_repo.upsert_many(extract_graph(make_test_enriched()))

        assert await graph_repo.get_related_papers(TEST_CVE) == []

    async def test_schema_constraints_exist(self, graph_repo: GraphRepository) -> None:
        """约束已入库（``SHOW CONSTRAINTS`` 可见唯一性约束）。"""
        rows = await graph_repo.client.run("SHOW CONSTRAINTS YIELD name RETURN name")
        names = {str(row["name"]) for row in rows}
        assert "vulnerability_cve_id" in names

    async def test_cleanup_removes_test_subgraph(self, graph_repo: GraphRepository) -> None:
        """清理接口删除漏洞节点后，该 ``cve_id`` 不再可查。"""
        await graph_repo.upsert_many(extract_graph(make_test_enriched()))
        await graph_repo.delete_vulnerability(TEST_CVE)

        rows = await graph_repo.client.run(
            "MATCH (v:Vulnerability {cve_id: $cve_id}) RETURN v", {"cve_id": TEST_CVE}
        )
        assert rows == []
