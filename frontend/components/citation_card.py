"""引用卡片组件（PROJECT_PLAN.md §5.9 ``frontend/components/citation_card.py``）。

问答页展示的 ``Citation``（冻结契约字段：``source_type`` / ``locator`` / ``cve_id`` /
``trace_id`` / ``url`` / ``quote``）逐条渲染为「定位 + 原文片段 + 可回溯链接」，
用于演示验收指标「引用可回溯率 100%」。
"""

from __future__ import annotations

from typing import Any

import streamlit as st

SOURCE_LABELS: dict[str, str] = {
    "vector": "向量语义检索（Chroma）",
    "graph": "图谱结构化检索（Neo4j）",
    "fulltext": "PostgreSQL 全文检索",
    "multi_hop": "图谱多跳遍历",
}
"""检索通路 → 中文标签（与 ``qa/state.ROUTE_LABELS`` 同口径，前端不 import 后端包）。"""


def render_citations(citations: list[dict[str, Any]] | None) -> None:
    """渲染引用卡片列表。

    Args:
        citations: ``QAResponse.citations`` 序列化后的字典列表；为空时给出降级提示。
    """
    items = list(citations or [])
    if not items:
        st.warning("本次回答没有可回溯引用（降级回答）")
        return
    st.markdown(f"**引用（{len(items)} 条，全部可回溯）**")
    for index, citation in enumerate(items, start=1):
        locator = str(citation.get("locator") or "-")
        source = SOURCE_LABELS.get(
            str(citation.get("source_type") or ""), str(citation.get("source_type") or "-")
        )
        cve_id = str(citation.get("cve_id") or "-")
        with st.expander(f"{index}. {locator}", expanded=index == 1):
            st.caption(f"来源：{source} ｜ CVE：{cve_id} ｜ trace：{citation.get('trace_id') or '-'}")
            quote = str(citation.get("quote") or "").strip()
            if quote:
                st.markdown(f"> {quote}")
            url = citation.get("url")
            if url:
                st.markdown(f"[查看原文]({url})")

