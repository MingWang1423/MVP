"""图谱可视化组件（PROJECT_PLAN.md §5.9 ``frontend/components/graph_view.py``）。

用 ``pyvis`` 把「富化实体 → 子图」渲染为可交互力导向图（答辩演示用）：

    Vulnerability ──AFFECTS──> Component ──INSTALLED_ON──> Asset
                  ├─RELATED_TO─> Paper
                  ├─EXPLOITS───> AttackTechnique
                  └─FIXED_BY───> Patch

Note:
    前端**不直连 Neo4j**（§2.1 分层约束）：节点/边由 ``GET /vulnerabilities/{cve_id}``
    返回的冻结契约现场推导，口径与 ``graph/extractor`` 一致（组件限流 5 个）。
"""

from __future__ import annotations

from typing import Any

import streamlit as st
import streamlit.components.v1 as components

NODE_COLORS: dict[str, str] = {
    "Vulnerability": "#b71c1c",
    "Component": "#1565c0",
    "Asset": "#2e7d32",
    "Paper": "#6a1b9a",
    "AttackTechnique": "#e65100",
    "Patch": "#455a64",
}
"""节点类型 → 颜色（与 ``graph/schema`` 的 6 类标签一致）。"""

MAX_COMPONENTS: int = 5
"""前端侧组件上限（与 ``COMPONENT_MAX_PER_VULN`` 默认值一致，避免渲染爆炸）。"""


def build_subgraph(payload: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """把详情响应推导成 ``(nodes, edges)``（纯函数，便于测试）。

    Args:
        payload: ``GET /vulnerabilities/{cve_id}`` 的响应体（含 ``unified`` / ``enriched``）。

    Returns:
        ``(nodes, edges)``：节点形如 ``{"id", "label", "group"}``，
        边形如 ``{"source", "target", "label"}``。
    """
    unified = payload.get("unified") or {}
    enriched = payload.get("enriched") or {}
    cve_id = str(unified.get("vuln_id") or enriched.get("vuln_id") or "UNKNOWN")
    nodes: list[dict[str, str]] = [
        {"id": cve_id, "label": cve_id, "group": "Vulnerability"}
    ]
    edges: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(node_id: str, label: str, group: str, relation: str) -> None:
        """登记节点（去重）与边。"""
        if node_id not in seen:
            seen.add(node_id)
            nodes.append({"id": node_id, "label": label, "group": group})
        edges.append({"source": cve_id, "target": node_id, "label": relation})

    for cpe in list(unified.get("cpe_matches") or [])[:MAX_COMPONENTS]:
        comp = f"{cpe.get('vendor')}:{cpe.get('product')}"
        add(comp, comp, "Component", "AFFECTS")
    for package in list(unified.get("ecosystem_packages") or [])[:MAX_COMPONENTS]:
        add(str(package), str(package), "Component", "AFFECTS")
    for asset in enriched.get("affected_assets") or []:
        key = f"{asset.get('asset_type')}:{asset.get('name')}"
        add(key, str(asset.get("name")), "Asset", "INSTALLED_ON")
    for link in enriched.get("related_papers") or []:
        add(str(link.get("paper_id")), str(link.get("paper_id")), "Paper", "RELATED_TO")
    chain = enriched.get("attack_chain") or {}
    for step in chain.get("steps") or []:
        technique = str(step.get("technique_id") or "").upper()
        if technique:
            add(technique, technique, "AttackTechnique", "EXPLOITS")
    for reference in (unified.get("references") or [])[:5]:
        tags = {str(tag).lower() for tag in reference.get("tags") or []}
        if tags & {"patch", "advisory", "vendor-advisory", "fix", "mitigation"}:
            url = str(reference.get("url") or "")
            if url:
                add(url, url.rsplit("/", 1)[-1][:24] or "patch", "Patch", "FIXED_BY")
    return nodes, edges


def render_graph(payload: dict[str, Any], *, height: int = 520) -> None:
    """渲染富化实体的知识子图（pyvis → 内嵌 HTML）。

    Args:
        payload: 漏洞详情响应体。
        height: 画布高度（像素）。
    """
    from pyvis.network import Network

    nodes, edges = build_subgraph(payload)
    if len(nodes) <= 1:
        st.info("该漏洞暂无图谱关系（可能未富化或缺少 CPE / 资产数据）")
        return
    network = Network(height=f"{height}px", width="100%", directed=True, notebook=False)
    network.barnes_hut()
    for node in nodes:
        group = node["group"]
        network.add_node(
            node["id"],
            label=node["label"],
            color=NODE_COLORS.get(group, "#616161"),
            title=group,
            shape="dot" if group != "Vulnerability" else "star",
            size=26 if group == "Vulnerability" else 14,
        )
    for edge in edges:
        network.add_edge(edge["source"], edge["target"], title=edge["label"], label=edge["label"])
    components.html(network.generate_html(), height=height + 40, scrolling=True)
    st.caption(f"子图：{len(nodes)} 节点 / {len(edges)} 边（组件上限 {MAX_COMPONENTS}，与后端抽取口径一致）")
