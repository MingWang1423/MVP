"""L3 富化层（PROJECT_PLAN.md §5.6）：LangGraph 多 Agent 富化主干。

对外主要入口：

- :func:`aisec_intel.enrich.graph.build_enrichment_graph`：装配状态图
  （``paper_linker → poc_seeker → verifier`` + 回流条件边 + checkpointer）；
- :func:`aisec_intel.services.enrich_service.enrich_batch`：编排 + 落库。

本层是**唯一允许调用 LLM 的业务层**（且只能通过 ``aisec_intel.llm`` 的 provider 出口）。
"""

from __future__ import annotations

from aisec_intel.enrich.agents.paper_linker import PaperLinkerAgent
from aisec_intel.enrich.agents.poc_seeker import PoCSeekerAgent, default_poc_searchers
from aisec_intel.enrich.agents.risk_scorer import risk_level, score_risk
from aisec_intel.enrich.agents.verifier import VerifierAgent, compute_confidence, trust_score
from aisec_intel.enrich.graph import (
    DEFAULT_MAX_ROUNDS,
    EnrichmentDeps,
    build_enrichment_graph,
    graph_mermaid,
    make_retry_router,
)
from aisec_intel.enrich.state import EnrichmentState, new_state, state_summary

__all__ = [
    "DEFAULT_MAX_ROUNDS",
    "EnrichmentDeps",
    "EnrichmentState",
    "PaperLinkerAgent",
    "PoCSeekerAgent",
    "VerifierAgent",
    "build_enrichment_graph",
    "compute_confidence",
    "default_poc_searchers",
    "graph_mermaid",
    "make_retry_router",
    "new_state",
    "risk_level",
    "score_risk",
    "state_summary",
    "trust_score",
]

