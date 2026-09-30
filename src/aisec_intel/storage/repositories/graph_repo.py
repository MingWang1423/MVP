"""图谱读写仓储（PROJECT_PLAN.md §5.7 P6）：幂等 upsert + 关联查询。

分工：

- 写入：节点用 ``MERGE (n:Label {key: $key}) SET n += $props``、关系用
  ``MATCH (a),(b) MERGE (a)-[r:TYPE]->(b) SET r += $props``，**幂等**（重复灌图不产生重复节点/边）；
- 批量：同标签 / 同关系类型合并为一条 ``UNWIND $rows AS row`` 语句（减少往返）；
- 查询：四个面向演示与问答的接口（受影响资产 / 关联论文 / 攻击链 / 同组件相关 CVE）；
- 安全：标签与关系类型先经 :mod:`aisec_intel.graph.schema` 白名单校验，其余一律参数化，
  杜绝 Cypher 注入。

所有方法均为异步，依赖注入的 :class:`~aisec_intel.storage.neo4j_client.Neo4jClient`。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from aisec_intel.graph.extractor import ExtractionResult, GraphEdge, GraphNode
from aisec_intel.graph.schema import (
    EDGE_MATRIX,
    NODE_ASSET,
    NODE_ATTACK_TECHNIQUE,
    NODE_COMPONENT,
    NODE_PAPER,
    NODE_VULNERABILITY,
    is_known_label,
    is_known_relation,
    key_property_of,
    schema_statements,
)
from aisec_intel.logging_config import get_logger
from aisec_intel.storage.neo4j_client import Neo4jClient

logger = get_logger(__name__)

BATCH_SIZE: int = 200
"""单条 ``UNWIND`` 语句的最大行数（避免超大事务；可按需调大）。"""


class GraphRepository:
    """Neo4j 图谱仓储（节点/边写入 + 关联查询）。

    Attributes:
        client: 底层 Neo4j 客户端。
    """

    def __init__(self, client: Neo4jClient) -> None:
        """绑定客户端。

        Args:
            client: 由调用方创建并负责 ``aclose()`` 的 Neo4j 客户端。
        """
        self.client = client

    async def ensure_schema(self) -> int:
        """创建约束与索引（幂等，重复执行安全）。

        Returns:
            执行的语句条数。

        Raises:
            Neo4jUnavailableError: 图数据库不可用。
        """
        count = await self.client.run_statements(schema_statements())
        logger.info(f"图谱 schema 就绪：约束+索引共 {count} 条")
        return count

    async def upsert_node(self, node: GraphNode) -> None:
        """幂等写入单个节点。

        Args:
            node: 待写入节点。

        Raises:
            ValueError: 标签未在 schema 白名单内。
            Neo4jUnavailableError: 图数据库不可用。
        """
        if not is_known_label(node.label):
            raise ValueError(f"未声明的节点标签：{node.label}（拒绝拼入 Cypher）")
        key_prop = key_property_of(node.label)
        props = {**node.properties, key_prop: node.key}
        await self.client.run(
            f"MERGE (n:{node.label} {{{key_prop}: $key}}) SET n += $props",
            {"key": node.key, "props": props},
        )

    async def upsert_edge(self, edge: GraphEdge) -> None:
        """幂等写入单条关系（两端节点必须已存在）。

        Args:
            edge: 待写入关系。

        Raises:
            ValueError: 关系类型未声明，或两端标签与 ``EDGE_MATRIX`` 不符。
            Neo4jUnavailableError: 图数据库不可用。
        """
        if not is_known_relation(edge.relation):
            raise ValueError(f"未声明的关系类型：{edge.relation}（拒绝拼入 Cypher）")
        expected = EDGE_MATRIX[edge.relation]
        if (edge.start_label, edge.end_label) != expected:
            raise ValueError(
                f"关系 {edge.relation} 的端点应为 {expected}，实际为 {(edge.start_label, edge.end_label)}"
            )
        start_prop = key_property_of(edge.start_label)
        end_prop = key_property_of(edge.end_label)
        cypher = (
            f"MATCH (a:{edge.start_label} {{{start_prop}: $start_key}}) "
            f"MATCH (b:{edge.end_label} {{{end_prop}: $end_key}}) "
            f"MERGE (a)-[r:{edge.relation}]->(b) SET r += $props"
        )
        await self.client.run(
            cypher,
            {"start_key": edge.start_key, "end_key": edge.end_key, "props": dict(edge.properties)},
        )

    async def upsert_many(self, result: ExtractionResult) -> dict[str, int]:
        """批量幂等写入一次抽取的全部节点与边（``UNWIND`` 分批）。

        Args:
            result: 抽取结果（节点已去重排序）。

        Returns:
            ``{"nodes": 写入节点数, "edges": 写入关系数, "node_batches": 语句数, "edge_batches": 语句数}``。
        """
        nodes_by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in result.nodes:
            if not is_known_label(node.label):
                raise ValueError(f"未声明的节点标签：{node.label}（拒绝拼入 Cypher）")
            key_prop = key_property_of(node.label)
            nodes_by_label[node.label].append({"key": node.key, "props": {**node.properties, key_prop: node.key}})

        edges_by_relation: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for edge in result.edges:
            if not is_known_relation(edge.relation):
                raise ValueError(f"未声明的关系类型：{edge.relation}（拒绝拼入 Cypher）")
            expected = EDGE_MATRIX[edge.relation]
            if (edge.start_label, edge.end_label) != expected:
                raise ValueError(f"关系 {edge.relation} 的端点应为 {expected}")
            edges_by_relation[edge.relation].append(
                {"start_key": edge.start_key, "end_key": edge.end_key, "props": dict(edge.properties)}
            )

        node_batches = 0
        edge_batches = 0
        for label, rows in nodes_by_label.items():
            key_prop = key_property_of(label)
            for chunk in _chunk(rows, BATCH_SIZE):
                await self.client.run(
                    f"UNWIND $rows AS row MERGE (n:{label} {{{key_prop}: row.key}}) SET n += row.props",
                    {"rows": chunk},
                )
                node_batches += 1
        for relation, rows in edges_by_relation.items():
            start_label, end_label = EDGE_MATRIX[relation]
            start_prop = key_property_of(start_label)
            end_prop = key_property_of(end_label)
            cypher = (
                f"UNWIND $rows AS row MATCH (a:{start_label} {{{start_prop}: row.start_key}}) "
                f"MATCH (b:{end_label} {{{end_prop}: row.end_key}}) "
                f"MERGE (a)-[r:{relation}]->(b) SET r += row.props"
            )
            for chunk in _chunk(rows, BATCH_SIZE):
                await self.client.run(cypher, {"rows": chunk})
                edge_batches += 1

        summary = {
            "nodes": len(result.nodes),
            "edges": len(result.edges),
            "node_batches": node_batches,
            "edge_batches": edge_batches,
        }
        logger.info(
            f"图谱写入 {result.vuln_id}：节点={summary['nodes']} 边={summary['edges']} "
            f"（语句 {node_batches + edge_batches} 条）"
        )
        return summary

    async def count_nodes(self) -> dict[str, int]:
        """按标签统计节点数（覆盖全部标签，空标签为 0）。

        Returns:
            ``{"Vulnerability": 1, "Component": 3, ...}``（标签字典序）。
        """
        rows = await self.client.run(
            "MATCH (n) UNWIND labels(n) AS label RETURN label AS label, count(*) AS total ORDER BY label"
        )
        counts = {str(row["label"]): int(row["total"]) for row in rows}
        for label in ("Vulnerability", "Component", "Asset", "Paper", "AttackTechnique", "Patch"):
            counts.setdefault(label, 0)
        return dict(sorted(counts.items()))

    async def count_edges(self) -> dict[str, int]:
        """按类型统计关系数。

        Returns:
            ``{"AFFECTS": 2, ...}``（类型字典序）。
        """
        rows = await self.client.run(
            "MATCH ()-[r]->() RETURN type(r) AS relation, count(*) AS total ORDER BY relation"
        )
        return {str(row["relation"]): int(row["total"]) for row in rows}

    async def delete_vulnerability(self, cve_id: str) -> None:
        """删除某漏洞节点及其关系（测试清理 / 重新灌图用）。

        Args:
            cve_id: 漏洞主键（大小写不敏感，内部转大写）。
        """
        await self.client.run(
            f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}}) DETACH DELETE v",
            {"cve_id": cve_id.strip().upper()},
        )
        logger.info(f"已删除漏洞节点及其关系：{cve_id}")

    async def delete_dangling(self, cve_id: str) -> None:
        """删除与指定漏洞相关的孤立节点（清理演示 / 测试数据时避免残留「孤儿」）。

        只删除**没有任何关系**、且带已知唯一键属性（``key`` / ``url`` / ``paper_id`` /
        ``technique_id``）的非 ``Vulnerability`` 节点，不触碰其它漏洞的数据。

        Args:
            cve_id: 刚被删除的漏洞主键（仅用于日志）。
        """
        await self.client.run(
            "MATCH (n) WHERE NOT n:Vulnerability AND NOT (n)--() "
            "AND (n.key IS NOT NULL OR n.url IS NOT NULL "
            "OR n.paper_id IS NOT NULL OR n.technique_id IS NOT NULL) "
            "DELETE n"
        )
        logger.info(f"已清理孤立节点（触发自 {cve_id}）")

    async def get_affected_assets(self, cve_id: str) -> list[dict[str, Any]]:
        """查询「受影响资产」：``CVE → AFFECTS → Component → INSTALLED_ON → Asset``（2 跳）。

        Args:
            cve_id: 漏洞主键（大小写不敏感）。

        Returns:
            每行形如 ``{"component_key", "component", "vendor", "ecosystem", "version_range", "assets"}``。
        """
        cypher = (
            f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[:AFFECTS]->(c:{NODE_COMPONENT}) "
            f"OPTIONAL MATCH (c)-[:INSTALLED_ON]->(a:{NODE_ASSET}) "
            "RETURN c.key AS component_key, c.name AS component, c.vendor AS vendor, "
            "c.ecosystem AS ecosystem, c.version_range AS version_range, "
            "collect(DISTINCT a.name) AS assets "
            "ORDER BY component_key"
        )
        return await self.client.run(cypher, {"cve_id": cve_id.strip().upper()})

    async def get_related_papers(self, cve_id: str) -> list[dict[str, Any]]:
        """查询漏洞关联论文（``Vulnerability -[RELATED_TO]-> Paper``）。

        Args:
            cve_id: 漏洞主键。

        Returns:
            每行形如 ``{"paper_id", "relation", "confidence"}``（按关联置信度降序）。
        """
        cypher = (
            f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[r:RELATED_TO]->(p:{NODE_PAPER}) "
            "RETURN p.paper_id AS paper_id, r.relation AS relation, r.confidence AS confidence "
            "ORDER BY confidence DESC, paper_id"
        )
        return await self.client.run(cypher, {"cve_id": cve_id.strip().upper()})

    async def get_attack_chain(self, cve_id: str) -> list[dict[str, Any]]:
        """查询攻击链（``Vulnerability -[EXPLOITS]-> AttackTechnique``，按 ``order`` 升序）。

        Args:
            cve_id: 漏洞主键。

        Returns:
            每行形如 ``{"technique_id", "tactic", "stage", "step_order", "description"}``。
        """
        cypher = (
            f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[r:EXPLOITS]->(t:{NODE_ATTACK_TECHNIQUE}) "
            "RETURN t.technique_id AS technique_id, t.tactic AS tactic, t.stage AS stage, "
            "r.order AS step_order, t.description AS description "
            "ORDER BY step_order, technique_id"
        )
        return await self.client.run(cypher, {"cve_id": cve_id.strip().upper()})

    async def get_related_cves(self, component: str) -> list[dict[str, Any]]:
        """查询「同组件相关的其它漏洞」（``Component ←[AFFECTS]- Vulnerability``）。

        Args:
            component: 组件键（``vendor:product``）或组件名（``product``）。

        Returns:
            每行形如 ``{"cve_id", "title", "risk_score", "risk_level", "severity", "kev"}``
            （按风险分降序）。
        """
        cypher = (
            f"MATCH (c:{NODE_COMPONENT})<-[:AFFECTS]-(v:{NODE_VULNERABILITY}) "
            "WHERE c.key = $component OR c.name = $component "
            "RETURN DISTINCT v.cve_id AS cve_id, v.title AS title, v.risk_score AS risk_score, "
            "v.risk_level AS risk_level, v.severity AS severity, v.kev AS kev "
            "ORDER BY risk_score DESC, cve_id"
        )
        return await self.client.run(cypher, {"component": component.strip()})


def _chunk(rows: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    """把行列表切成固定大小的批次（纯函数）。

    Args:
        rows: 待分批的行列表。
        size: 单批上限（``<=0`` 时按 :data:`BATCH_SIZE` 处理）。

    Returns:
        批次列表（空输入返回空列表）。
    """
    step = size if size > 0 else BATCH_SIZE
    return [rows[index : index + step] for index in range(0, len(rows), step)]
