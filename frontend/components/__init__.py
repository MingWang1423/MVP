"""前端可复用组件包（PROJECT_PLAN.md §5.9 P8，Day12 任务 4）。

组件职责（全部纯展示，不含业务逻辑与外部调用）：

- :mod:`components.risk_badge`：风险 / 严重度徽章；
- :mod:`components.citation_card`：问答引用卡片（可回溯定位 + 原文片段 + 原文链接）；
- :mod:`components.graph_view`：富化实体的知识子图（pyvis 力导向图）。

Note:
    本包只依赖 ``streamlit`` / ``pyvis``；数据一律由 :mod:`api_client` 从 API 取回。
"""

