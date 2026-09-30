"""Day9 图谱仓储单元测试（``storage/repositories/graph_repo.py``，PROJECT_PLAN.md §5.7）。

用 ``FakeClient`` 替代真实 Neo4j：断言 Cypher 形态、白名单校验与参数化查询
（**不连接数据库**；真实连通性由 ``tests/integration/test_graph_write.py`` 覆盖）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.graph import schema
from aisec_intel.graph.extractor import ExtractionResult, GraphEdge, GraphNode
from aisec_intel.storage.repositories.graph_repo import BATCH_SIZE, GraphRepository, _chunk


class FakeClient:
    """记录调用并按需返回预置行的 Neo4j 客户端替身。"""

    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        """初始化替身。

        Args:
            rows: ``run`` 的固定返回值。
        """
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.schema_statements: tuple[str, ...] = ()
        self._rows = rows or []

    async def run(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """记录 Cypher 与参数并返回预置行。"""
        self.calls.append((cypher, params or {}))
        return list(self._rows)

    async def run_statements(self, statements: Any) -> int:
        """记录 schema 语句并返回条数。"""
        self.schema_statements = tuple(statements)
        return len(self.schema_statements)

    @property
    def cypher(self) -> str:
        """最近一次执行的 Cypher。"""
        return self.calls[-1][0]

    @property
    def params(self) -> dict[str, Any]:
        """最近一次执行的参数。"""
        return self.calls[-1][1]


def make_result() -> ExtractionResult:
    """构造含 2 节点 1 边的抽取结果。"""
    return ExtractionResult(
        vuln_id="CVE-2024-3400",
        nodes=[
            GraphNode(label="Vulnerability", key="CVE-2024-3400", properties={"risk_level": "critical"}),
            GraphNode(label="Component", key="paloaltonetworks:pan-os", properties={"name": "pan-os"}),
            GraphNode(label="Component", key="PyPI:ollama", properties={"name": "ollama"}),
        ],
        edges=[
            GraphEdge(
                relation="AFFECTS",
                start_label="Vulnerability",
                start_key="CVE-2024-3400",
                end_label="Component",
                end_key="paloaltonetworks:pan-os",
                properties={"version_range": "<10.2.9-h1"},
            )
        ],
    )


class TestSchemaAndUpsert:
    """schema 初始化与幂等 upsert。"""

    async def test_ensure_schema_applies_all_statements(self) -> None:
        """``ensure_schema`` 执行全部约束与索引语句。"""
        client = FakeClient()
        count = await GraphRepository(client).ensure_schema()
        assert count == len(schema.schema_statements())
        assert client.schema_statements == schema.schema_statements()

    async def test_upsert_node_merges_on_key_property(self) -> None:
        """节点写入使用 ``MERGE`` + 键属性，属性走参数（防注入）。"""
        client = FakeClient()
        await GraphRepository(client).upsert_node(
            GraphNode(label="Component", key="PyPI:ollama", properties={"name": "ollama"})
        )
        assert "MERGE (n:Component {key: $key})" in client.cypher
        assert client.params["key"] == "PyPI:ollama"
        assert client.params["props"] == {"name": "ollama", "key": "PyPI:ollama"}

    async def test_upsert_node_rejects_unknown_label(self) -> None:
        """未声明标签直接拒绝（防止 Cypher 注入 / 建错节点）。"""
        with pytest.raises(ValueError, match="未声明的节点标签"):
            await GraphRepository(FakeClient()).upsert_node(GraphNode(label="Bug", key="x"))

    async def test_upsert_edge_builds_match_merge(self) -> None:
        """关系写入先 ``MATCH`` 两端再 ``MERGE``，端点标签来自 schema。"""
        client = FakeClient()
        edge = make_result().edges[0]
        await GraphRepository(client).upsert_edge(edge)

        assert "MATCH (a:Vulnerability {cve_id: $start_key})" in client.cypher
        assert "MATCH (b:Component {key: $end_key})" in client.cypher
        assert "MERGE (a)-[r:AFFECTS]->(b) SET r += $props" in client.cypher
        assert client.params["props"] == {"version_range": "<10.2.9-h1"}

    async def test_upsert_edge_rejects_unknown_relation(self) -> None:
        """未声明关系类型被拒绝。"""
        edge = GraphEdge(
            relation="DELETES",
            start_label="Vulnerability",
            start_key="C",
            end_label="Component",
            end_key="c",
        )
        with pytest.raises(ValueError, match="未声明的关系类型"):
            await GraphRepository(FakeClient()).upsert_edge(edge)

    async def test_upsert_edge_rejects_wrong_endpoints(self) -> None:
        """端点标签与 ``EDGE_MATRIX`` 不符时报错（防止把关系方向写反）。"""
        edge = GraphEdge(
            relation="AFFECTS",
            start_label="Component",
            start_key="c",
            end_label="Vulnerability",
            end_key="CVE-2024-3400",
        )
        with pytest.raises(ValueError, match="端点应为"):
            await GraphRepository(FakeClient()).upsert_edge(edge)

    async def test_upsert_many_batches_by_label_and_relation(self) -> None:
        """批量写入按标签 / 关系类型各一条 ``UNWIND`` 语句。"""
        client = FakeClient()
        stats = await GraphRepository(client).upsert_many(make_result())

        assert stats == {"nodes": 3, "edges": 1, "node_batches": 2, "edge_batches": 1}
        assert len(client.calls) == 3
        assert all("UNWIND $rows AS row" in cypher for cypher, _ in client.calls)
        assert any("MERGE (n:Vulnerability {cve_id: row.key})" in cypher for cypher, _ in client.calls)
        assert any("MERGE (a)-[r:AFFECTS]->(b)" in cypher for cypher, _ in client.calls)

    async def test_upsert_many_rejects_unknown_label(self) -> None:
        """批量写入同样执行白名单校验。"""
        result = ExtractionResult(vuln_id="CVE-2024-3400", nodes=[GraphNode(label="Bug", key="x")], edges=[])
        with pytest.raises(ValueError, match="未声明的节点标签"):
            await GraphRepository(FakeClient()).upsert_many(result)


class TestQueryInterfaces:
    """四个查询接口：Cypher 形态 + 返回值透传。"""

    async def test_get_affected_assets(self) -> None:
        """受影响资产：2 跳查询（AFFECTS → INSTALLED_ON），带 ``OPTIONAL MATCH``。"""
        client = FakeClient(rows=[{"component": "pan-os", "assets": ["GlobalProtect Gateway"]}])
        rows = await GraphRepository(client).get_affected_assets("cve-2024-3400")

        assert rows == [{"component": "pan-os", "assets": ["GlobalProtect Gateway"]}]
        assert "-[:AFFECTS]->(c:Component)" in client.cypher
        assert "OPTIONAL MATCH (c)-[:INSTALLED_ON]->(a:Asset)" in client.cypher
        assert client.params["cve_id"] == "CVE-2024-3400"  # 主键统一大写

    async def test_get_related_papers(self) -> None:
        """关联论文：按 ``confidence`` 降序返回。"""
        client = FakeClient(rows=[{"paper_id": "2404.12345", "relation": "proposes-attack", "confidence": 0.8}])
        rows = await GraphRepository(client).get_related_papers("CVE-2024-3400")

        assert rows[0]["paper_id"] == "2404.12345"
        assert "-[r:RELATED_TO]->(p:Paper)" in client.cypher
        assert "ORDER BY confidence DESC" in client.cypher

    async def test_get_attack_chain(self) -> None:
        """攻击链：按 ``r.order`` 升序返回技术序列。"""
        client = FakeClient(rows=[{"technique_id": "T1190", "step_order": 1}])
        rows = await GraphRepository(client).get_attack_chain("CVE-2024-3400")

        assert rows[0]["technique_id"] == "T1190"
        assert "-[r:EXPLOITS]->(t:AttackTechnique)" in client.cypher
        assert "ORDER BY step_order, technique_id" in client.cypher

    async def test_get_related_cves(self) -> None:
        """同组件相关 CVE：按组件键或组件名匹配，按风险分降序。"""
        client = FakeClient(rows=[{"cve_id": "CVE-2024-3400", "risk_score": 97.0}])
        rows = await GraphRepository(client).get_related_cves("paloaltonetworks:pan-os")

        assert rows[0]["cve_id"] == "CVE-2024-3400"
        assert "WHERE c.key = $component OR c.name = $component" in client.cypher
        assert "ORDER BY risk_score DESC" in client.cypher
        assert client.params["component"] == "paloaltonetworks:pan-os"

    async def test_count_nodes_fills_missing_labels(self) -> None:
        """节点统计补齐未出现的标签（报告表格不缺口）。"""
        client = FakeClient(rows=[{"label": "Vulnerability", "total": 3}])
        counts = await GraphRepository(client).count_nodes()
        assert counts["Vulnerability"] == 3
        assert counts["Patch"] == 0
        assert "UNWIND labels(n) AS label" in client.cypher

    async def test_count_edges(self) -> None:
        """关系统计按类型返回。"""
        client = FakeClient(rows=[{"relation": "AFFECTS", "total": 2}])
        assert await GraphRepository(client).count_edges() == {"AFFECTS": 2}

    async def test_delete_vulnerability_and_dangling(self) -> None:
        """清理接口：删除漏洞节点（DETACH）与孤立节点。"""
        client = FakeClient()
        repo = GraphRepository(client)
        await repo.delete_vulnerability("cve-2024-3400")
        assert "DETACH DELETE v" in client.cypher and client.params["cve_id"] == "CVE-2024-3400"

        await repo.delete_dangling("CVE-2024-3400")
        assert "NOT (n)--()" in client.cypher


class TestChunking:
    """``_chunk`` 分批纯函数。"""

    def test_chunk_splits_evenly_and_keeps_remainder(self) -> None:
        """偶数批 + 余数批都保留。"""
        rows = [{"i": index} for index in range(5)]
        assert _chunk(rows, 2) == [[{"i": 0}, {"i": 1}], [{"i": 2}, {"i": 3}], [{"i": 4}]]

    def test_chunk_empty_input(self) -> None:
        """空输入返回空列表。"""
        assert _chunk([], 10) == []

    def test_chunk_non_positive_size_uses_default(self) -> None:
        """``size <= 0`` 时回落到 ``BATCH_SIZE``。"""
        rows = [{"i": index} for index in range(BATCH_SIZE + 1)]
        assert len(_chunk(rows, 0)) == 2

