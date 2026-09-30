"""接口层：Day1 冻结的跨层契约（PROJECT_PLAN.md §10）。

导出清单：
    - ``RawItem``：L1 采集层输出（§10.1 ①）
    - ``UnifiedVuln`` 及其组件 ``CVSSVector`` / ``CpeMatch`` / ``Reference``：L2 归一化输出（§10.1 ②）
    - ``EnrichedVuln`` 及其组件 ``AffectedAsset`` / ``ExploitRecord`` / ``AttackChain`` /
      ``AttackChainStep`` / ``AgentStep``：L3 富化输出（§10.1 ③）
    - ``Paper`` / ``PaperVulnLink``：富化维度② 的论文与关联
    - 基类与工具：``IntelBaseModel`` / ``UTCDateTime`` / ``utc_now`` / ``new_trace_id``

注意：本包字段变更必须走 §10.3 变更流程，并在 ``reports/INTERFACE_FREEZE.md`` 记录。
"""

from __future__ import annotations

from aisec_intel.models.agent_io import (
    Citation,
    CitationSource,
    EnrichmentInput,
    EnrichmentOutput,
    PaperRelevance,
    PaperRelevanceBatch,
    QAQuery,
    QAResponse,
    ReasoningStep,
    RiskScore,
    VerificationReport,
)
from aisec_intel.models.base import (
    SCHEMA_VERSION,
    IntelBaseModel,
    OptionalUTCDateTime,
    UTCDateTime,
    iso_z,
    new_trace_id,
    to_utc,
    utc_now,
)
from aisec_intel.models.enriched_vuln import (
    AffectedAsset,
    AgentStep,
    AttackChain,
    AttackChainStep,
    EnrichedVuln,
    ExploitRecord,
)
from aisec_intel.models.paper import Paper, PaperRelation, PaperSource, PaperVulnLink
from aisec_intel.models.raw_item import RawItem
from aisec_intel.models.unified_vuln import (
    UNIFIED_VULN_SCHEMA_VERSION,
    CpeMatch,
    CVSSVector,
    Reference,
    Severity,
    UnifiedVuln,
)

__all__ = [
    "SCHEMA_VERSION",
    "UNIFIED_VULN_SCHEMA_VERSION",
    "AffectedAsset",
    "AgentStep",
    "AttackChain",
    "AttackChainStep",
    "CVSSVector",
    "Citation",
    "CitationSource",
    "CpeMatch",
    "EnrichedVuln",
    "EnrichmentInput",
    "EnrichmentOutput",
    "ExploitRecord",
    "IntelBaseModel",
    "OptionalUTCDateTime",
    "Paper",
    "PaperRelation",
    "PaperRelevance",
    "PaperRelevanceBatch",
    "PaperSource",
    "PaperVulnLink",
    "QAQuery",
    "QAResponse",
    "RawItem",
    "ReasoningStep",
    "Reference",
    "RiskLevel",
    "RiskScore",
    "Severity",
    "UTCDateTime",
    "UnifiedVuln",
    "VerificationReport",
    "iso_z",
    "new_trace_id",
    "to_utc",
    "utc_now",
]
