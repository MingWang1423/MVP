"""Day16 任务 1.4：图谱全图概览的**纯函数**单测（``services/graph_service.py``）。

覆盖 :func:`~aisec_intel.services.graph_service.merge_subgraphs` 的四条规则：

1. 节点按 ``id`` 去重（跨 CVE 复用的组件 / 技术 / 补丁只出现一次，天然成为「枢纽」）；
2. 边按 ``id`` 去重；
3. 裁剪时两端不全在保留集合内的边必须被丢弃（React Flow 渲染前置约束）；
4. 节点超限时**优先保留 vulnerability 节点**并置 ``truncated=True``。

不依赖 Neo4j / 数据库，纯内存构造。
"""

from __future__ import annotations

from aisec_intel.services.graph_service import (
    SubgraphEdge,
    SubgraphNode,
    merge_subgraphs,
)


def node(node_id: str, node_type: str) -> SubgraphNode:
    """构造节点。

    Args:
        node_id: 节点 ID。
        node_type: 节点类型（``vulnerability`` / ``component`` / ...）。

    Returns:
        :class:`SubgraphNode`。
    """
    return SubgraphNode(id=node_id, type=node_type, label=node_id.split(":")[-1], properties={})


def edge(source: str, target: str, relation: str = "AFFECTS") -> SubgraphEdge:
    """构造边（ID 与生产口径一致：``源-关系->目标``）。

    Args:
        source: 起点节点 ID。
        target: 终点节点 ID。
        relation: 关系类型。

    Returns:
        :class:`SubgraphEdge`。
    """
    return SubgraphEdge(
        id=f"{source}-{relation}->{target}", source=source, target=target, relation=relation
    )


class TestMergeSubgraphs:
    """多张子图合并为概览图。"""

    def test_shared_neighbour_is_deduplicated(self) -> None:
        """两个 CVE 共用同一组件时，组件节点只出现一次（概览图的「枢纽」）。"""
        vuln_a = node("Vulnerability:CVE-A", "vulnerability")
        vuln_b = node("Vulnerability:CVE-B", "vulnerability")
        shared = node("Component:vendor:product", "component")
        parts = [
            ([vuln_a, shared], [edge(vuln_a.id, shared.id)]),
            ([vuln_b, shared], [edge(vuln_b.id, shared.id)]),
        ]
        nodes, edges, truncated = merge_subgraphs(parts, max_nodes=100)
        assert truncated is False
        ids = [item.id for item in nodes]
        assert ids == ["Component:vendor:product", "Vulnerability:CVE-A", "Vulnerability:CVE-B"]
        assert len(edges) == 2

    def test_duplicate_edges_are_deduplicated(self) -> None:
        """同一对节点间的同关系边只保留一条。"""
        vuln = node("Vulnerability:CVE-A", "vulnerability")
        component = node("Component:vendor:product", "component")
        parts = [
            ([vuln, component], [edge(vuln.id, component.id)]),
            ([vuln, component], [edge(vuln.id, component.id)]),
        ]
        _, edges, _ = merge_subgraphs(parts, max_nodes=100)
        assert len(edges) == 1

    def test_truncation_keeps_vulnerabilities_first(self) -> None:
        """节点超限时先保 vulnerability 节点，且丢弃悬空边。"""
        vuln = node("Vulnerability:CVE-A", "vulnerability")
        leaves = [node(f"Patch:p{index}", "patch") for index in range(5)]
        parts = [([vuln, *leaves], [edge(vuln.id, leaf.id, "FIXED_BY") for leaf in leaves])]
        nodes, edges, truncated = merge_subgraphs(parts, max_nodes=3)
        ids = {item.id for item in nodes}
        assert truncated is True
        assert len(nodes) == 3
        # 中心漏洞必须保留（否则概览图失去意义）；输出顺序遵循 (类型, ID) 稳定排序
        assert "Vulnerability:CVE-A" in ids
        assert ids == {"Vulnerability:CVE-A", "Patch:p0", "Patch:p1"}
        for item in edges:
            assert item.source in ids
            assert item.target in ids

    def test_zero_max_nodes_means_unlimited(self) -> None:
        """``max_nodes<=0`` 视为不限容量（不裁剪、不置 truncated）。"""
        parts = [([node("Patch:p1", "patch"), node("Patch:p2", "patch")], [])]
        nodes, edges, truncated = merge_subgraphs(parts, max_nodes=0)
        assert len(nodes) == 2
        assert edges == []
        assert truncated is False

    def test_empty_input(self) -> None:
        """无任何子图时返回空结果（前端渲染空态）。"""
        nodes, edges, truncated = merge_subgraphs([], max_nodes=10)
        assert nodes == []
        assert edges == []
        assert truncated is False
