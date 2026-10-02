"""风险徽章组件（PROJECT_PLAN.md §5.9 ``frontend/components/risk_badge.py``）。

把富化维度④的 ``risk_level`` / ``risk_score`` 渲染为带颜色的徽章（纯展示，无业务逻辑）。
"""

from __future__ import annotations

import streamlit as st

LEVEL_COLORS: dict[str, str] = {
    "critical": "#b71c1c",
    "high": "#e65100",
    "medium": "#f9a825",
    "low": "#2e7d32",
}
"""风险级别 → 背景色（与 ``EnrichedVuln.risk_level`` 取值一一对应）。"""

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#e65100",
    "MEDIUM": "#f9a825",
    "LOW": "#2e7d32",
    "NONE": "#616161",
}
"""CVSS 严重度 → 背景色（事实层 ``UnifiedVuln.severity``）。"""


def badge(text: str, color: str) -> str:
    """生成一个内联 HTML 徽章（纯函数，便于单测与复用）。

    Args:
        text: 徽章文本。
        color: 背景色（十六进制）。

    Returns:
        HTML 片段。
    """
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:10px;'
        f'font-size:0.85rem;font-weight:600;">{text}</span>'
    )


def render_risk_badge(risk_level: str | None, risk_score: float | None = None) -> None:
    """在页面中渲染风险徽章。

    Args:
        risk_level: ``low`` / ``medium`` / ``high`` / ``critical``（``None`` 时不渲染）。
        risk_score: 风险分（0-100，``None`` 时只显示级别）。
    """
    if not risk_level:
        st.caption("未富化（无风险分）")
        return
    level = str(risk_level).lower()
    color = LEVEL_COLORS.get(level, "#616161")
    text = f"{level.upper()} {risk_score:.1f}" if risk_score is not None else level.upper()
    st.markdown(badge(text, color), unsafe_allow_html=True)


def render_severity_badge(severity: str | None) -> None:
    """在页面中渲染 CVSS 严重度徽章。

    Args:
        severity: ``NONE`` / ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``。
    """
    if not severity:
        st.caption("无 CVSS 严重度")
        return
    key = str(severity).upper()
    st.markdown(badge(key, SEVERITY_COLORS.get(key, "#616161")), unsafe_allow_html=True)
