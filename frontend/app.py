"""Streamlit 前端入口（PROJECT_PLAN.md §5.9 P8，Day12 任务 4）。

启动::

    streamlit run frontend/app.py            # 默认 http://localhost:8501

四个页面（侧边栏切换，只消费 API，不含任何 LLM / 数据库直连）：

======  ====================  =============================================
页面    数据来源               关键内容
======  ====================  =============================================
①列表   ``GET /vulnerabilities``      严重度 / 来源 / 时间筛选，点击行进入详情
②详情   ``GET /vulnerabilities/{id}`` 7 维富化展示 + pyvis 子图
③问答   ``POST /qa/ask``              答案 + 引用卡片 + 推理链（支持多轮）
④质量   本地 ``reports/data_quality.md`` 采集数据质量报告
======  ====================  =============================================

Note:
    Streamlit 以脚本所在目录作为工作目录，因此这里把 ``frontend/`` 加入 ``sys.path``
    （基于 ``__file__`` 计算，非硬编码），保证 ``api_client`` / ``components`` 可导入。
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import streamlit as st

FRONTEND_DIR = Path(__file__).resolve().parent
if str(FRONTEND_DIR) not in sys.path:
    sys.path.insert(0, str(FRONTEND_DIR))

from api_client import ApiError, ask, base_url, get_vulnerability, health, list_vulnerabilities  # noqa: E402
from components.citation_card import render_citations  # noqa: E402
from components.graph_view import render_graph  # noqa: E402
from components.risk_badge import render_risk_badge, render_severity_badge  # noqa: E402

REPO_ROOT: Path = FRONTEND_DIR.parent
"""仓库根目录（读取 ``reports/`` 下的 Markdown 报告）。"""

SEVERITY_OPTIONS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
"""严重度筛选取值（与 ``UnifiedVuln.severity`` 一致）。"""

SOURCE_OPTIONS: tuple[str, ...] = ("nvd", "kev", "epss", "osv", "ghsa", "arxiv", "github", "rss")
"""数据源筛选取值（与 ``configs/sources.yaml`` 的源标识一致）。"""

TIME_OPTIONS: dict[str, int | None] = {"不限": None, "最近 7 天": 7, "最近 30 天": 30, "最近 90 天": 90}
"""时间筛选选项 → 回看天数。"""

PAGES: tuple[str, ...] = ("① 漏洞列表", "② 漏洞详情", "③ 智能问答", "④ 数据质量")
"""侧边栏页面顺序。"""


def session_id() -> str:
    """返回本次浏览器会话的多轮对话 ID（存于 ``st.session_state``）。

    Returns:
        会话 ID（首次调用生成 uuid4）。
    """
    if "qa_session_id" not in st.session_state:
        st.session_state.qa_session_id = f"web-{uuid.uuid4().hex[:12]}"
    return str(st.session_state.qa_session_id)


def goto_detail(cve_id: str) -> None:
    """跳转到详情页并记录当前 CVE（先写「待切换页面」，下一轮渲染时生效）。

    Args:
        cve_id: 目标漏洞主键。

    Note:
        Streamlit 不允许在导航组件实例化之后直接改它的 ``session_state`` 键，
        因此用 ``pending_page`` 做一次中转，在下一轮渲染开始时再落到导航键上。
    """
    st.session_state.selected_cve = cve_id.strip().upper()
    st.session_state.pending_page = PAGES[1]
    st.rerun()


def render_sidebar() -> str:
    """渲染侧边栏（页面切换 + 链路探活 + 当前 API 地址）。

    Returns:
        当前选中的页面名。
    """
    with st.sidebar:
        st.header("AI 安全知识情报系统")
        if st.session_state.get("pending_page"):
            st.session_state.nav_page = st.session_state.pop("pending_page")
        page = st.radio("导航", PAGES, key="nav_page", label_visibility="collapsed")
        st.divider()
        st.caption(f"API：{base_url()}")
        try:
            snapshot = health()
        except ApiError as exc:
            st.error(str(exc))
        else:
            flag = "🟢" if snapshot.get("status") == "ok" else "🟡"
            st.markdown(f"{flag} 问答链路：`{snapshot.get('status')}`")
            st.caption(
                f"LLM={'on' if snapshot.get('llm_enabled') else 'off'} ｜ "
                f"向量={snapshot.get('vector_backend')} ｜ Neo4j={'on' if snapshot.get('neo4j_enabled') else 'off'} ｜ "
                f"限流={snapshot.get('rate_limit_per_minute')}/min"
            )
            st.caption("主干：" + " → ".join(snapshot.get("plan") or []))
        st.divider()
        st.caption(f"会话 ID：`{session_id()}`")
    return page


def page_list() -> None:
    """页面①：漏洞列表（筛选 + 点击进入详情）。"""
    st.subheader("漏洞列表")
    col_severity, col_source, col_days, col_kev, col_limit = st.columns([2, 2, 1.4, 1, 1])
    severity = col_severity.multiselect("严重度", SEVERITY_OPTIONS, default=[])
    source = col_source.selectbox("数据源", ("全部", *SOURCE_OPTIONS))
    days_label = col_days.selectbox("时间", tuple(TIME_OPTIONS))
    kev_only = col_kev.checkbox("仅 KEV", value=False)
    limit = col_limit.number_input("条数", min_value=5, max_value=100, value=20, step=5)

    try:
        payload = list_vulnerabilities(
            severity=severity[0] if len(severity) == 1 else None,
            source=None if source == "全部" else source,
            days=TIME_OPTIONS[days_label],
            kev_only=kev_only,
            limit=int(limit),
            offset=0,
        )
    except ApiError as exc:
        st.error(str(exc))
        st.info("请先启动 API：`uvicorn aisec_intel.api.main:app --port 8000`")
        return

    items: list[dict[str, Any]] = list(payload.get("items") or [])
    if len(severity) > 1:
        items = [item for item in items if item.get("severity") in set(severity)]
    st.caption(f"命中 {payload.get('total', 0)} 条（当前展示 {len(items)} 条）")

    if not items:
        st.info("没有符合条件的漏洞：可放宽筛选，或先跑 `python -m scripts.run_collect --source nvd --cve ...`")
        return

    if hasattr(st, "dataframe"):
        try:
            event = st.dataframe(
                [
                    {
                        "CVE": item.get("vuln_id"),
                        "标题": (item.get("title") or "")[:48],
                        "严重度": item.get("severity") or "-",
                        "风险分": item.get("risk_score"),
                        "风险级别": item.get("risk_level") or "未富化",
                        "KEV": "是" if item.get("kev") else "",
                        "EPSS": item.get("epss_score"),
                        "来源": ",".join(item.get("sources") or []),
                        "发布": str(item.get("published_at") or "")[:19],
                    }
                    for item in items
                ],
                hide_index=True,
                width="stretch",
                on_select="rerun",
                selection_mode="single-row",
                key="vuln_table",
            )
        except TypeError:  # 老版本 Streamlit 不支持行选择
            st.dataframe(items, width="stretch")
            event = None
        rows = list(getattr(event, "selection", {}).get("rows", [])) if event is not None else []
        if rows:
            goto_detail(str(items[rows[0]].get("vuln_id")))

    options = [str(item.get("vuln_id")) for item in items]
    picked = st.selectbox("或直接选择漏洞", options, key="vuln_picker")
    if st.button("查看详情", type="primary"):
        goto_detail(picked)


def page_detail() -> None:
    """页面②：漏洞详情（7 维富化 + 知识子图）。"""
    st.subheader("漏洞详情")
    default_id = str(st.session_state.get("selected_cve") or "")
    cve_id = st.text_input("CVE 编号", value=default_id, placeholder="CVE-2024-3400").strip()
    if not cve_id:
        st.info("请在「漏洞列表」点击一行，或直接输入 CVE 编号。")
        return
    try:
        payload = get_vulnerability(cve_id)
    except ApiError as exc:
        st.error(str(exc))
        return
    st.session_state.selected_cve = cve_id.upper()

    unified: dict[str, Any] = payload.get("unified") or {}
    enriched: dict[str, Any] | None = payload.get("enriched")
    st.markdown(f"### {unified.get('vuln_id')} ｜ {unified.get('title') or '（无标题）'}")
    col_sev, col_risk, col_meta = st.columns([1, 1, 3])
    with col_sev:
        render_severity_badge(unified.get("severity"))
    with col_risk:
        render_risk_badge(
            (enriched or {}).get("risk_level"), (enriched or {}).get("risk_score")
        )
    with col_meta:
        st.caption(
            f"来源：{','.join(unified.get('sources') or []) or '-'} ｜ "
            f"KEV：{'是' if unified.get('kev') else '否'} ｜ "
            f"EPSS：{unified.get('epss_score')} ｜ "
            f"发布：{str(unified.get('published_at') or '')[:19]}"
        )
    st.write(unified.get("description") or "")

    if not enriched:
        st.warning(
            "该漏洞尚未富化（无 7 维结论）："
            f"`python -m scripts.run_enrich --cve {unified.get('vuln_id')}`"
        )
    else:
        render_dimensions(unified, enriched)

    st.divider()
    st.markdown("#### 知识图谱子图")
    render_graph(payload)


def render_dimensions(unified: dict[str, Any], enriched: dict[str, Any]) -> None:
    """渲染 7 维富化视图（论文 / 资产 / PoC / 风险 / 攻击链 / CVSS / 修复）。

    Args:
        unified: 事实层字典（提供 CVSS、参考链接等原始事实）。
        enriched: 富化层字典（提供 7 维结论与复核状态）。
    """
    tabs = st.tabs(["① 资产", "② 论文", "③ PoC/EXP", "④ 风险", "⑤ 攻击链", "⑥ CVSS", "⑦ 修复"])
    with tabs[0]:
        assets = enriched.get("affected_assets") or []
        st.metric("受影响资产", len(assets))
        if assets:
            st.dataframe(assets, hide_index=True, width="stretch")
        else:
            st.caption("无资产维度结论")
    with tabs[1]:
        papers = enriched.get("related_papers") or []
        st.metric("关联论文", len(papers))
        if papers:
            st.dataframe(papers, hide_index=True, width="stretch")
        else:
            st.caption("无关联论文")
    with tabs[2]:
        exploits = enriched.get("exploits") or []
        st.metric("PoC / EXP", len(exploits))
        if exploits:
            st.dataframe(exploits, hide_index=True, width="stretch")
        else:
            st.caption("暂无公开 PoC")
    with tabs[3]:
        col_score, col_level = st.columns(2)
        col_score.metric("风险分", enriched.get("risk_score"))
        col_level.metric("风险级别", enriched.get("risk_level"))
        breakdown = enriched.get("risk_breakdown") or {}
        if breakdown:
            st.bar_chart({"权重贡献": breakdown})
        st.caption(
            f"置信度={enriched.get('confidence')} ｜ 复核={enriched.get('review_status')} ｜ "
            f"模型={enriched.get('model_used')}"
        )
        if enriched.get("review_notes"):
            st.warning("；".join(enriched["review_notes"]))
    with tabs[4]:
        chain = enriched.get("attack_chain") or {}
        steps = chain.get("steps") or []
        st.caption(
            f"入口向量：{chain.get('entry_vector') or '-'} ｜ 所需权限：{chain.get('privileges_required') or '-'}"
        )
        for step in steps:
            st.markdown(
                f"**{step.get('order')}. {step.get('technique_id')}**（{step.get('tactic')} / {step.get('stage')}）"
                f" — {step.get('description')}"
            )
        if not steps:
            st.caption("无攻击链结论")
    with tabs[5]:
        vectors = unified.get("cvss") or []
        if vectors:
            st.dataframe(vectors, hide_index=True, width="stretch")
        st.caption(f"受影响版本：{'；'.join(unified.get('affected_versions') or []) or '-'}")
        st.caption(f"CWE：{','.join(unified.get('cwe_ids') or []) or '-'}")
    with tabs[6]:
        patch_tags = {"patch", "advisory", "vendor-advisory", "fix", "mitigation"}
        references = unified.get("references") or []
        fixes = [ref for ref in references if patch_tags & {str(tag).lower() for tag in ref.get("tags") or []}]
        st.metric("修复 / 公告链接", len(fixes))
        for ref in fixes:
            st.markdown(f"- [{ref.get('url')}]({ref.get('url')})（{ref.get('source')}）")
        if not fixes:
            st.caption("未识别到补丁 / 公告链接")


def page_qa() -> None:
    """页面③：智能问答（答案 + 引用 + 推理链，支持多轮会话）。"""
    st.subheader("智能问答")
    st.caption(
        f"多轮会话 ID：`{session_id()}`（同一 ID 的追问会自动带上上一轮上下文；"
        "L4 = query_understander → supervisor → reasoner → synthesizer）"
    )
    if "qa_history" not in st.session_state:
        st.session_state.qa_history = []
    history: list[dict[str, Any]] = st.session_state.qa_history
    for turn in history:
        with st.chat_message("user"):
            st.markdown(turn["question"])
        with st.chat_message("assistant"):
            st.markdown(turn["answer"])
            st.caption(
                f"置信度={turn.get('confidence')} ｜ 降级={'是' if turn.get('degraded') else '否'} ｜ "
                f"引用={len(turn.get('citations') or [])}"
            )

    col_query, col_clear = st.columns([5, 1])
    question = col_query.text_input("提问", placeholder="CVE-2021-44228 的攻击链和修复建议？")
    if col_clear.button("清空会话"):
        st.session_state.qa_history = []
        st.session_state.qa_session_id = f"web-{uuid.uuid4().hex[:12]}"
        st.rerun()
    if not st.button("提交", type="primary") or not question.strip():
        return

    try:
        response = ask(question.strip(), session_id=session_id())
    except ApiError as exc:
        st.error(str(exc))
        return
    history.append(
        {
            "question": question.strip(),
            "answer": response.get("answer") or "",
            "citations": response.get("citations") or [],
            "reasoning_chain": response.get("reasoning_chain") or [],
            "confidence": response.get("confidence"),
            "degraded": response.get("degraded"),
        }
    )
    st.markdown("#### 回答")
    st.markdown(response.get("answer") or "")
    chain = response.get("reasoning_chain") or []
    if chain:
        with st.expander(f"推理链（{len(chain)} 步，≤2 跳）"):
            for step in chain:
                st.markdown(
                    f"**Hop {step.get('hop')}** ｜ {step.get('conclusion')}\n\n"
                    f"- 检索子问题：{step.get('question')}\n"
                    f"- 证据：{', '.join(step.get('evidence') or []) or '-'}"
                )
    else:
        st.caption("本次未产出推理链（无证据或降级回答）")
    render_citations(response.get("citations"))


def page_quality() -> None:
    """页面④：数据质量（渲染 ``reports/*.md`` 报告）。"""
    st.subheader("数据质量与图谱规模")
    tabs = st.tabs(["采集数据质量", "图谱规模"])
    with tabs[0]:
        _render_report(REPO_ROOT / "reports" / "data_quality.md")
    with tabs[1]:
        _render_report(REPO_ROOT / "reports" / "graph_stats.md")


def _render_report(path: Path) -> None:
    """渲染仓库内的 Markdown 报告（缺失时给出生成命令）。

    Args:
        path: 报告路径。
    """
    if not path.is_file():
        st.info(
            f"报告尚未生成：{path.name}"
            "（跑 `python -m scripts.run_collect --mode incremental` 或 `python -m scripts.load_graph --all`）"
        )
        return
    st.caption(f"来源：{path}")
    st.markdown(path.read_text(encoding="utf-8"))


def main() -> None:
    """应用入口：页面配置 → 侧边栏 → 按导航分发。"""
    st.set_page_config(page_title="AI 安全知识情报系统", page_icon="🛡️", layout="wide")
    page = render_sidebar()
    if page == PAGES[0]:
        page_list()
    elif page == PAGES[1]:
        page_detail()
    elif page == PAGES[2]:
        page_qa()
    else:
        page_quality()


main()
