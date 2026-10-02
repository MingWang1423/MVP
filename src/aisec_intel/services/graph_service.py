"""知识图谱子图服务（Day15 任务 4；PROJECT_PLAN.md §5.9 图谱页数据源）。

职责：为 ``GET /api/v1/graph/{cve_id}`` 提供 **1 跳子图**，输出前端（React Flow）可直接消费的
``nodes`` / ``edges``：

1. **首选 Neo4j**：``Vulnerability {cve_id} -[r]- (邻居)``，节点/关系类型受
   :mod:`aisec_intel.graph.schema` 白名单约束（杜绝 Cypher 注入）；
2. **降级 PostgreSQL**（``NEO4J_ENABLED=false`` / 驱动不可用 / 图中无该节点）：
   由冻结契约现场推导子图，口径与 :func:`aisec_intel.graph.extractor.extract_graph` 一致
   （组件限流、补丁按 ``references`` 标签识别），保证离线演示同样可看；
3. **纯函数负责映射**：方向还原、类型归一、显示名、去重与排序全部是纯函数，可单测。

节点类型（前端按此着色）：``vulnerability`` / ``component`` / ``asset`` / ``paper`` /
``technique`` / ``patch``。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.config import Settings
from aisec_intel.graph.extractor import (
    DEFAULT_COMPONENT_MAX_PER_VULN,
    PATCH_TAGS,
    ExtractionResult,
    extract_graph,
)
from aisec_intel.graph.schema import (
    EDGE_MATRIX,
    NODE_ASSET,
    NODE_ATTACK_TECHNIQUE,
    NODE_COMPONENT,
    NODE_PAPER,
    NODE_PATCH,
    NODE_VULNERABILITY,
    RELATION_AFFECTS,
    RELATION_FIXED_BY,
    key_property_of,
)
from aisec_intel.logging_config import get_logger
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.neo4j_client import Neo4jClient, Neo4jUnavailableError
from aisec_intel.storage.repositories.graph_repo import GraphRepository
from aisec_intel.storage.repositories.vuln_repo import VulnRepository

logger = get_logger(__name__)

SubgraphBackend = Literal["neo4j", "postgres"]
"""子图数据来源：``neo4j``（图数据库） / ``postgres``（冻结契约现场推导的降级路径）。"""

NODE_TYPE_BY_LABEL: dict[str, str] = {
    NODE_VULNERABILITY: "vulnerability",
    NODE_COMPONENT: "component",
    NODE_ASSET: "asset",
    NODE_PAPER: "paper",
    NODE_ATTACK_TECHNIQUE: "technique",
    NODE_PATCH: "patch",
}
"""Neo4j 节点标签 → 前端节点类型（前端按类型取设计 token 着色）。"""

DEFAULT_SUBGRAPH_LIMIT: int = 80
"""单次返回的邻居行数上限（超出即 ``truncated=True``，前端提示「已截断」）。"""


@dataclass(frozen=True, slots=True)
class SubgraphNode:
    """子图节点（前端 ``Node`` 的原始形态）。

    Attributes:
        id: 全局唯一 ID（``标签:键``，跨类型不冲突）。
        type: 节点类型（见 :data:`NODE_TYPE_BY_LABEL` 的取值）。
        label: 展示名（如 ``CVE-2024-3400`` / ``T1190``）。
        properties: 原始属性（前端做 tooltip / 详情用）。
    """

    id: str
    type: str
    label: str
    properties: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SubgraphEdge:
    """子图边（前端 ``Edge`` 的原始形态）。

    Attributes:
        id: 边 ID（``源-关系->目标``，去重键）。
        source: 起点节点 ID。
        target: 终点节点 ID。
        relation: 关系类型（``AFFECTS`` / ``INSTALLED_ON`` / ...）。
    """

    id: str
    source: str
    target: str
    relation: str


@dataclass(frozen=True, slots=True)
class Subgraph:
    """一次子图查询的结果。

    Attributes:
        cve_id: 中心漏洞主键。
        backend: 数据来源（``neo4j`` / ``postgres``）。
        nodes: 节点列表（含中心节点，按类型+ID 排序）。
        edges: 边列表（按关系+源+目标排序）。
        truncated: 是否因 ``limit`` 截断。
    """

    cve_id: str
    backend: SubgraphBackend
    nodes: list[SubgraphNode]
    edges: list[SubgraphEdge]
    truncated: bool = False


def node_identifier(label: str, key: str) -> str:
    """拼装节点唯一 ID（纯函数）。

    Args:
        label: 节点标签（如 ``Vulnerability``）。
        key: 节点唯一键（如 ``CVE-2024-3400``）。

    Returns:
        形如 ``Vulnerability:CVE-2024-3400`` 的 ID。
    """
    return f"{label}:{key}"


def display_label(label: str, properties: dict[str, Any]) -> str:
    """按节点类型取展示名（纯函数）。

    Args:
        label: 节点标签。
        properties: 节点属性。

    Returns:
        展示用短文本（缺失时回退到唯一键）。
    """
    if label == NODE_VULNERABILITY:
        return str(properties.get("cve_id") or properties.get("key") or "")
    if label == NODE_PAPER:
        return str(properties.get("title") or properties.get("paper_id") or "")[:60]
    if label == NODE_ATTACK_TECHNIQUE:
        name = properties.get("name") or properties.get("description") or ""
        return f"{properties.get('technique_id', '')} {name}".strip()[:60]
    if label == NODE_PATCH:
        url = str(properties.get("url") or "")
        return str(properties.get("title") or url.rsplit("/", 1)[-1][:32] or url)
    return str(properties.get("name") or properties.get("key") or "")


def orient_edge(relation: str, center_id: str, neighbor_id: str, neighbor_label: str) -> tuple[str, str]:
    """还原边的方向（纯函数，依据 :data:`~aisec_intel.graph.schema.EDGE_MATRIX`）。

    无向查询（``(v)-[r]-(n)``）拿不到方向，这里按 schema 声明的端点约束还原：
    邻居为起点 → ``邻居 → 中心``，否则 ``中心 → 邻居``。

    Args:
        relation: 关系类型。
        center_id: 中心漏洞节点 ID。
        neighbor_id: 邻居节点 ID。
        neighbor_label: 邻居节点标签。

    Returns:
        ``(source_id, target_id)``。
    """
    expected = EDGE_MATRIX.get(relation)
    if expected is not None and expected[0] == neighbor_label:
        return neighbor_id, center_id
    return center_id, neighbor_id


def _sorted_nodes(nodes: dict[str, SubgraphNode]) -> list[SubgraphNode]:
    """按 ``(类型, ID)`` 稳定排序（纯函数，便于断言与前端布局复现）。"""
    return sorted(nodes.values(), key=lambda item: (item.type, item.id))


def _sorted_edges(edges: dict[str, SubgraphEdge]) -> list[SubgraphEdge]:
    """按 ``(关系, 源, 目标)`` 稳定排序（纯函数）。"""
    return sorted(edges.values(), key=lambda item: (item.relation, item.source, item.target))


def map_subgraph_rows(
    rows: list[dict[str, Any]],
    *,
    limit: int = DEFAULT_SUBGRAPH_LIMIT,
) -> tuple[list[SubgraphNode], list[SubgraphEdge], bool]:
    """把 Neo4j 原始行映射为 ``(nodes, edges, truncated)``（纯函数）。

    Args:
        rows: :meth:`~aisec_intel.storage.repositories.graph_repo.GraphRepository.subgraph` 的返回行。
        limit: 本次查询的行数上限（用于判断是否截断）。

    Returns:
        ``(节点列表, 边列表, 是否截断)``；孤立漏洞（无邻居）返回「仅中心节点 + 空边」。
    """
    nodes: dict[str, SubgraphNode] = {}
    edges: dict[str, SubgraphEdge] = {}
    neighbor_rows = 0

    for row in rows:
        key = str(row.get("center_key") or "").strip()
        if not key:
            continue
        center_id = node_identifier(NODE_VULNERABILITY, key)
        nodes.setdefault(
            center_id,
            SubgraphNode(
                id=center_id,
                type=NODE_TYPE_BY_LABEL[NODE_VULNERABILITY],
                label=key,
                properties={
                    "title": row.get("center_title"),
                    "severity": row.get("center_severity"),
                },
            ),
        )

        relation = str(row.get("relation") or "")
        labels = [item for item in (row.get("node_labels") or []) if item in NODE_TYPE_BY_LABEL]
        properties = dict(row.get("node_props") or {})
        if not relation or not labels:
            continue

        neighbor_rows += 1
        label = labels[0]
        neighbor_key = str(properties.get(key_property_of(label)) or "").strip()
        if not neighbor_key:
            continue
        neighbor_id = node_identifier(label, neighbor_key)
        nodes.setdefault(
            neighbor_id,
            SubgraphNode(
                id=neighbor_id,
                type=NODE_TYPE_BY_LABEL[label],
                label=display_label(label, {**properties, key_property_of(label): neighbor_key}),
                properties=properties,
            ),
        )
        source, target = orient_edge(relation, center_id, neighbor_id, label)
        edge_id = f"{source}-{relation}->{target}"
        edges.setdefault(
            edge_id, SubgraphEdge(id=edge_id, source=source, target=target, relation=relation)
        )

    return _sorted_nodes(nodes), _sorted_edges(edges), neighbor_rows >= limit


def map_extraction(result: ExtractionResult) -> tuple[list[SubgraphNode], list[SubgraphEdge]]:
    """把图谱抽取结果映射为子图节点 / 边（纯函数）。

    复用 :func:`~aisec_intel.graph.extractor.extract_graph` 的产出，确保「PG 降级路径」
    与「写入 Neo4j 的子图」口径完全一致（同一份抽取规则，不会出现两套图）。

    Args:
        result: 抽取结果（节点 + 边，已去重排序）。

    Returns:
        ``(节点列表, 边列表)``。
    """
    nodes: dict[str, SubgraphNode] = {}
    edges: dict[str, SubgraphEdge] = {}
    for node in result.nodes:
        props = dict(node.properties)
        props.setdefault(key_property_of(node.label), node.key)
        node_id = node_identifier(node.label, node.key)
        nodes[node_id] = SubgraphNode(
            id=node_id,
            type=NODE_TYPE_BY_LABEL.get(node.label, "unknown"),
            label=display_label(node.label, props),
            properties=props,
        )
    for edge in result.edges:
        source = node_identifier(edge.start_label, edge.start_key)
        target = node_identifier(edge.end_label, edge.end_key)
        edge_id = f"{source}-{edge.relation}->{target}"
        edges[edge_id] = SubgraphEdge(
            id=edge_id, source=source, target=target, relation=edge.relation
        )
    return _sorted_nodes(nodes), _sorted_edges(edges)


PATCH_REFERENCE_LIMIT: int = 5
"""未富化时从 ``references`` 中最多取出的补丁 / 公告链接数（与 Streamlit 版口径一致）。"""


def facts_only_subgraph(unified: UnifiedVuln) -> tuple[list[SubgraphNode], list[SubgraphEdge]]:
    """未富化时的兜底子图（纯函数）：中心漏洞 + 组件 + 补丁。

    规则与 :func:`~aisec_intel.graph.extractor.extract_graph` 保持一致：
    组件来自 ``cpe_matches``（厂商一致、按 ``vendor:product`` 归一）与 ``ecosystem_packages``，
    补丁来自 ``references`` 中带 patch / advisory 标签者。

    Args:
        unified: 漏洞事实层实体。

    Returns:
        ``(节点列表, 边列表)``。
    """
    center_id = node_identifier(NODE_VULNERABILITY, unified.vuln_id)
    nodes: dict[str, SubgraphNode] = {
        center_id: SubgraphNode(
            id=center_id,
            type=NODE_TYPE_BY_LABEL[NODE_VULNERABILITY],
            label=unified.vuln_id,
            properties={
                "title": unified.title,
                "severity": unified.severity,
                "kev": unified.kev,
                "risk_score": None,
            },
        )
    }
    edges: dict[str, SubgraphEdge] = {}

    def link(label: str, key: str, properties: dict[str, Any], relation: str) -> None:
        """登记邻居节点与一条以中心为起点的边。"""
        node_id = node_identifier(label, key)
        nodes.setdefault(
            node_id,
            SubgraphNode(
                id=node_id,
                type=NODE_TYPE_BY_LABEL[label],
                label=display_label(label, {**properties, key_property_of(label): key}),
                properties=properties,
            ),
        )
        edge_id = f"{center_id}-{relation}->{node_id}"
        edges.setdefault(
            edge_id, SubgraphEdge(id=edge_id, source=center_id, target=node_id, relation=relation)
        )

    for cpe in list(unified.cpe_matches)[:DEFAULT_COMPONENT_MAX_PER_VULN]:
        key = f"{cpe.vendor}:{cpe.product}"
        link(
            NODE_COMPONENT,
            key,
            {"key": key, "name": cpe.product, "vendor": cpe.vendor, "vulnerable": cpe.vulnerable},
            RELATION_AFFECTS,
        )
    for package in list(unified.ecosystem_packages)[:DEFAULT_COMPONENT_MAX_PER_VULN]:
        name = str(package)
        link(NODE_COMPONENT, name, {"key": name, "name": name}, RELATION_AFFECTS)
    for reference in list(unified.references)[:PATCH_REFERENCE_LIMIT]:
        tags = {str(tag).lower() for tag in reference.tags}
        if reference.url and (tags & PATCH_TAGS):
            link(
                NODE_PATCH,
                reference.url,
                {"url": reference.url, "name": reference.url.rsplit("/", 1)[-1][:32]},
                RELATION_FIXED_BY,
            )
    return _sorted_nodes(nodes), _sorted_edges(edges)


def build_entity_subgraph(
    unified: UnifiedVuln,
    enriched: EnrichedVuln | None,
) -> tuple[list[SubgraphNode], list[SubgraphEdge]]:
    """由冻结契约现场推导子图（纯函数，Neo4j 降级路径）。

    Args:
        unified: 事实层实体。
        enriched: 富化层实体；``None`` 时退化为「组件 + 补丁」两跳。

    Returns:
        ``(节点列表, 边列表)``。
    """
    if enriched is None:
        return facts_only_subgraph(unified)
    return map_extraction(extract_graph(enriched))


class GraphService:
    """图谱子图服务：Neo4j 优先，不可用时降级为冻结契约推导。"""

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings,
        client: Neo4jClient | None = None,
        limit: int = DEFAULT_SUBGRAPH_LIMIT,
    ) -> None:
        """绑定会话与配置。

        Args:
            session: 请求级 PG 会话（用于读取事实层 / 富化层实体）。
            settings: 全局配置（``NEO4J_ENABLED`` 决定是否走图数据库）。
            client: 复用的 Neo4j 客户端；``None`` 时按需创建并在本次调用后关闭。
            limit: 子图邻居行数上限。
        """
        self._session = session
        self._settings = settings
        self._client = client
        self._limit = max(1, limit)

    async def subgraph(self, cve_id: str, *, limit: int | None = None) -> Subgraph | None:
        """返回指定 CVE 的 1 跳子图。

        Args:
            cve_id: 漏洞主键（大小写不敏感）。
            limit: 覆盖默认行数上限。

        Returns:
            :class:`Subgraph`；库中不存在该 CVE 时返回 ``None``。
        """
        repo = VulnRepository(self._session)
        unified = await repo.get_by_cve(cve_id)
        if unified is None:
            return None

        effective_limit = max(1, limit or self._limit)
        if self._settings.neo4j_enabled:
            nodes, edges, truncated = await self._try_neo4j(unified.vuln_id, effective_limit)
            if nodes:
                return Subgraph(
                    cve_id=unified.vuln_id,
                    backend="neo4j",
                    nodes=nodes,
                    edges=edges,
                    truncated=truncated,
                )

        enriched = await repo.get_enriched(unified.vuln_id)
        nodes, edges = build_entity_subgraph(unified, enriched)
        return Subgraph(cve_id=unified.vuln_id, backend="postgres", nodes=nodes, edges=edges)

    async def _try_neo4j(
        self, vuln_id: str, limit: int
    ) -> tuple[list[SubgraphNode], list[SubgraphEdge], bool]:
        """尝试从 Neo4j 取子图；不可用 / 无节点时返回空结果（由调用方降级）。

        Args:
            vuln_id: 规范化后的漏洞主键。
            limit: 行数上限。

        Returns:
            ``(节点列表, 边列表, 是否截断)``；失败时全为「空 / False」。
        """
        owns_client = self._client is None
        client = self._client or Neo4jClient(self._settings)
        try:
            rows = await GraphRepository(client).subgraph(vuln_id, limit=limit)
        except Neo4jUnavailableError as exc:
            logger.warning(f"图谱子图降级为 PG 推导（{vuln_id}）：{exc}")
            return [], [], False
        finally:
            if owns_client:
                await client.aclose()

        nodes, edges, truncated = map_subgraph_rows(rows, limit=limit)
        if not nodes:
            logger.info(f"图谱中暂无该漏洞节点（{vuln_id}），降级为 PG 推导")
        return nodes, edges, truncated

