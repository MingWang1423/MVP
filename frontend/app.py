"""Streamlit 前端入口 · 首页概览（PROJECT_PLAN.md §5.9 P8，Day13 任务 5 拆分后）。

启动::

    streamlit run frontend/app.py            # 默认 http://localhost:8501

多页面结构（Streamlit 原生机制，侧边栏自动生成导航）::

    frontend/app.py              首页：链路探活 + 规模概览 + 快速入口（本文件）
    frontend/ui.py               共享 UI 层（bootstrap / 四个页面主体 / 7 维渲染）
    frontend/pages/1_漏洞列表.py  ① 列表：严重度 / 来源 / 时间筛选，点击行进入详情
    frontend/pages/2_漏洞详情.py  ② 详情：7 维富化 Tabs + pyvis 子图
    frontend/pages/3_智能问答.py  ③ 问答：答案 + 引用卡片 + 推理链（多轮会话）
    frontend/pages/4_数据质量.py  ④ 质量：reports/*.md

前端只消费 API（§2.1：不 import ``aisec_intel``、不直连数据库）。
"""

from __future__ import annotations

import sys
from pathlib import Path

_FRONTEND_DIR = Path(__file__).resolve().parent
if str(_FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(_FRONTEND_DIR))

import streamlit as st  # noqa: E402
from api_client import ApiError, health, list_vulnerabilities  # noqa: E402
from ui import PAGE_DETAIL, PAGE_LIST, PAGE_QA, bootstrap  # noqa: E402


def overview() -> None:
    """渲染首页：链路探活快照 + 数据规模指标 + 三个快速入口按钮。"""
    st.title("🛡️ AI 安全知识情报系统")
    st.caption("L1 采集 → L2 归一化 → L3 富化（LangGraph 多 Agent）→ L4 问答 → L5 API → L6 前端")

    try:
        snapshot = health()
        first_page = list_vulnerabilities(limit=5)
        kev_page = list_vulnerabilities(kev_only=True, limit=5)
    except ApiError as exc:
        st.error(str(exc))
        st.code("docker compose up -d && python -m scripts.init_db && python -m scripts.seed_sources", "powershell")
        return

    col_status, col_total, col_kev = st.columns(3)
    col_status.metric("问答链路", str(snapshot.get("status")))
    col_total.metric("漏洞总量", first_page.get("total", 0))
    col_kev.metric("CISA KEV 条目", kev_page.get("total", 0))
    st.caption(
        f"LLM={'on' if snapshot.get('llm_enabled') else 'off'} ｜ "
        f"向量={snapshot.get('vector_backend')} ｜ "
        f"Neo4j={'on' if snapshot.get('neo4j_enabled') else 'off'} ｜ 主干："
        + " → ".join(snapshot.get("plan") or [])
    )

    col_a, col_b, col_c = st.columns(3)
    if col_a.button("① 漏洞列表", type="primary"):
        st.switch_page(PAGE_LIST)
    if col_b.button("② 漏洞详情"):
        st.switch_page(PAGE_DETAIL)
    if col_c.button("③ 智能问答"):
        st.switch_page(PAGE_QA)

    st.divider()
    st.markdown("#### 最新漏洞（按发布时间倒序）")
    items = first_page.get("items") or []
    if items:
        st.dataframe(
            [
                {
                    "CVE": item.get("vuln_id"),
                    "严重度": item.get("severity") or "-",
                    "风险分": item.get("risk_score"),
                    "KEV": "是" if item.get("kev") else "",
                    "发布": str(item.get("published_at") or "")[:19],
                }
                for item in items
            ],
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("库中暂无漏洞：先跑 `python -m scripts.run_collect --source kev --normalize`。")


bootstrap("首页")
overview()
