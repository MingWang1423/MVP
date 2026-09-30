"""智能体驱动的 AI 安全知识情报系统（高校 ICT 产教融合创新大赛 · 赛题九）。

架构分层（详见 PROJECT_PLAN.md §1）：
- L1 ``connectors``  采集层：传统代码，禁止 LLM
- L2 ``normalize``   归一化层：纯函数，禁止 LLM
- L3 ``enrich``      富化层：LangGraph 多 Agent（7 Agent + 回流条件边）
- L4 ``qa``          问答层：LangGraph 多 Agent（SQL / Cypher / Vector 三路检索 + 引用）
- L5 ``api``         FastAPI 服务层
- 存储 ``storage``   PostgreSQL / Neo4j / ChromaDB 适配层
"""

from __future__ import annotations

__version__: str = "0.1.0"
"""包版本号（与 pyproject.toml 保持一致）。"""

__all__ = ["__version__"]
