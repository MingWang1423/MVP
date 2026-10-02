"""Day15 任务 4：图谱子图纯函数单测（``services/graph_service.py``）。

覆盖三条确定性逻辑（前端 React Flow 图的形状与配色分类依赖它们）：

1. :func:`~aisec_intel.services.graph_service.map_subgraph_rows`（Neo4j 行 → 节点/边）；
2. :func:`~aisec_intel.services.graph_service.map_extraction`（抽取结果 → 节点/边）；
3. :func:`~aisec_intel.services.graph_service.facts_only_subgraph`（未富化兜底）。

以及三个小工具：``node_identifier`` / ``orient_edge`` / ``display_label``。
"""

from __future__ import annotations

from aisec_intel.graph.extractor import extract_graph
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import (
    AffectedAsset,
    AttackChain,
    AttackChainStep,
    EnrichedVuln,
    ExploitRecord,
)
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import CpeMatch, Reference, UnifiedVuln
from aisec_intel.services.graph_service import (
    build_entity_subgraph,
    display_label,
    facts_only_subgraph,
    map_extraction,
    map_subgraph_rows,
    node_identifier,
    orient_edge,
)

CENTER_ROW = {
    "center_key": "CVE-2024-3400",
    "center_title": "PAN-OS command injection",
    "center_severity": "CRITICAL",
}

COMPONENT_ROW = {
    **CENTER_ROW,
    "relation": "AFFECTS",
    "node_labels": ["Component"],
    "node_props": {"key": "paloaltonetworks:pan-os", "name": "PAN-OS"},
}

PATCH_ROW = {
    **CENTER_ROW,
    "relation": "FIXED_BY",
    "node_labels": ["Patch"],
    "node_props": {"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "title": "公告"},
}

EMPTY_ROW = {**CENTER_ROW, "relation": None, "node_labels": None, "node_props": None}

UNKNOWN_LABEL_ROW = {
    **CENTER_ROW,
    "relation": "AFFECTS",
    "node_labels": ["NotDeclared"],
    "node_props": {"key": "x"},
}

TECHNIQUE_ROW = {
    **CENTER_ROW,
    "relation": "EXPLOITS",
    "node_labels": ["AttackTechnique"],
    "node_props": {"technique_id": "T1190", "description": "Exploit Public-Facing Application"},
}

ASSET_ROW = {
    **CENTER_ROW,
    "relation": "INSTALLED_ON",
    "node_labels": ["Asset"],
    "node_props": {"key": "device:edge-fw", "name": "edge-fw"},
}


def make_unified(**overrides: object) -> UnifiedVuln:
    """构造一条事实层实体（测试辅助）。"""
    payload: dict[str, object] = {
        "vuln_id": "CVE-2024-3400",
        "title": "PAN-OS command injection",
        "description": "test",
        "severity": "CRITICAL",
        "sources": ["nvd"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)  # type: ignore[arg-type]


def make_enriched() -> EnrichedVuln:
    """构造一条带五维结论的富化实体（测试辅助）。"""
    base = make_unified(
        cpe_matches=[CpeMatch(vendor="paloaltonetworks", product="pan-os")],
        references=[
            Reference(
                url="https://security.paloaltonetworks.com/CVE-2024-3400",
                source="vendor",
                tags=["patch"],
            )
        ],
    )
    return EnrichedVuln(
        **base.model_dump(),
        affected_assets=[AffectedAsset(asset_type="device", name="edge-fw", confidence=0.9)],
        related_papers=[
            PaperVulnLink(paper_id="2403.01234", vuln_id="CVE-2024-3400", relation="proposes-attack")
        ],
        exploits=[ExploitRecord(source="github", url="https://example.test/poc", maturity="poc")],
        risk_score=96.0,
        risk_level="critical",
        confidence=0.85,
        model_used="deepseek-chat",
        enriched_at=base.normalized_at,
        attack_chain=AttackChain(
            steps=[
                AttackChainStep(
                    order=1,
                    technique_id="T1190",
                    tactic="initial-access",
                    stage="Delivery",
                    description="利用暴露面漏洞",
                )
            ]
        ),
    )


class TestSmallHelpers:
    """``node_identifier`` / ``orient_edge`` / ``display_label``。"""

    def test_node_identifier_is_namespaced(self) -> None:
        assert node_identifier("Vulnerability", "CVE-2024-3400") == "Vulnerability:CVE-2024-3400"

    def test_orient_edge_follows_schema_matrix(self) -> None:
        """邻居是关系终点 → 中心在前（``中心 → 邻居``）。"""
        center = "Vulnerability:CVE-2024-3400"
        assert orient_edge("AFFECTS", center, "Component:pan-os", "Component") == (
            center,
            "Component:pan-os",
        )
        assert orient_edge("FIXED_BY", center, "Patch:https://x", "Patch") == (
            center,
            "Patch:https://x",
        )

    def test_orient_edge_swaps_when_neighbor_is_start(self) -> None:
        """邻居是关系起点时（如 ``Component -INSTALLED_ON-> ...``）交换方向。"""
        center = "Vulnerability:CVE-2024-3400"
        assert orient_edge("INSTALLED_ON", center, "Component:pan-os", "Component") == (
            "Component:pan-os",
            center,
        )
        # 未声明关系（防御性）：保持 中心 → 邻居
        assert orient_edge("MYSTERY", center, "Asset:a", "Asset") == (center, "Asset:a")

    def test_display_label_by_type(self) -> None:
        assert display_label("Vulnerability", {"cve_id": "CVE-1"}) == "CVE-1"
        assert display_label("Component", {"name": "PAN-OS"}) == "PAN-OS"
        assert display_label("Paper", {"title": "A study"}) == "A study"
        assert (
            display_label("AttackTechnique", {"technique_id": "T1190", "description": "X"})
            == "T1190 X"
        )
        assert display_label("Patch", {"url": "https://a.test/bulletin"}) == "bulletin"


class TestMapSubgraphRows:
    """Neo4j 行 → React Flow 节点 / 边。"""

    def test_maps_nodes_edges_and_skips_noise(self) -> None:
        rows = [COMPONENT_ROW, PATCH_ROW, TECHNIQUE_ROW, ASSET_ROW, EMPTY_ROW, UNKNOWN_LABEL_ROW]
        nodes, edges, truncated = map_subgraph_rows(rows, limit=80)

        assert truncated is False
        by_id = {node.id: node for node in nodes}
        assert set(by_id) == {
            "Vulnerability:CVE-2024-3400",
            "Component:paloaltonetworks:pan-os",
            "Patch:https://security.paloaltonetworks.com/CVE-2024-3400",
            "AttackTechnique:T1190",
            "Asset:device:edge-fw",
        }
        assert by_id["Vulnerability:CVE-2024-3400"].type == "vulnerability"
        assert by_id["Component:paloaltonetworks:pan-os"].label == "PAN-OS"
        assert by_id["Asset:device:edge-fw"].label == "edge-fw"
        assert by_id["AttackTechnique:T1190"].label == "T1190 Exploit Public-Facing Application"

        assert {edge.relation for edge in edges} == {"AFFECTS", "FIXED_BY", "EXPLOITS", "INSTALLED_ON"}
        affects = next(edge for edge in edges if edge.relation == "AFFECTS")
        assert affects.source == "Vulnerability:CVE-2024-3400"
        assert affects.target == "Component:paloaltonetworks:pan-os"
        # 边 ID 形如 ``源-关系->目标``，前端可直接当 key 用
        assert affects.id == "Vulnerability:CVE-2024-3400-AFFECTS->Component:paloaltonetworks:pan-os"

    def test_isolated_vulnerability_returns_center_only(self) -> None:
        """孤立漏洞（OPTIONAL MATCH 空行）→ 仅中心节点、无边。"""
        nodes, edges, truncated = map_subgraph_rows([EMPTY_ROW], limit=80)
        assert [node.id for node in nodes] == ["Vulnerability:CVE-2024-3400"]
        assert edges == [] and truncated is False

    def test_truncated_flag(self) -> None:
        rows = [COMPONENT_ROW, PATCH_ROW]
        _, _, truncated = map_subgraph_rows(rows, limit=2)
        assert truncated is True

    def test_empty_input(self) -> None:
        assert map_subgraph_rows([], limit=10) == ([], [], False)

    def test_nodes_sorted_by_type_then_id(self) -> None:
        nodes, _, _ = map_subgraph_rows([PATCH_ROW, COMPONENT_ROW, TECHNIQUE_ROW], limit=80)
        assert [node.type for node in nodes] == ["component", "patch", "technique", "vulnerability"]


class TestEntitySubgraph:
    """抽取结果映射与未富化兜底（Neo4j 降级路径）。"""

    def test_map_extraction_covers_all_node_types(self) -> None:
        nodes, edges = map_extraction(extract_graph(make_enriched()))
        types = {node.type for node in nodes}
        assert {"vulnerability", "component", "asset", "paper", "technique", "patch"} <= types
        assert any(edge.relation == "FIXED_BY" for edge in edges)
        assert all(node.id.count(":") >= 1 for node in nodes)

    def test_build_entity_subgraph_without_enrichment_uses_facts(self) -> None:
        unified = make_unified(
            cpe_matches=[CpeMatch(vendor="acme", product="proxy")],
            ecosystem_packages=["PyPI:acme-proxy"],
            references=[
                Reference(
                    url="https://acme.test/advisories/1", source="vendor", tags=["vendor-advisory"]
                ),
                Reference(url="https://acme.test/blog/1", source="vendor", tags=["mailing-list"]),
            ],
        )
        nodes, edges = build_entity_subgraph(unified, None)
        ids = {node.id for node in nodes}
        assert "Vulnerability:CVE-2024-3400" in ids
        assert "Component:acme:proxy" in ids and "Component:PyPI:acme-proxy" in ids
        # 只有带 patch / advisory 标签的引用成为 Patch 节点
        assert "Patch:https://acme.test/advisories/1" in ids
        assert "Patch:https://acme.test/blog/1" not in ids
        assert len(edges) == len(nodes) - 1

    def test_facts_only_subgraph_respects_component_limit(self) -> None:
        unified = make_unified(
            cpe_matches=[CpeMatch(vendor="v", product=f"p{index}") for index in range(9)]
        )
        nodes, _ = facts_only_subgraph(unified)
        assert len([node for node in nodes if node.type == "component"]) == 5

