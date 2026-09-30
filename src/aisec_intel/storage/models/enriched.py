"""``EnrichedVuln`` 的 ORM 映射（表 ``enriched_vuln``）。

与 ``unified_vuln`` 是 **1:1 父子关系**（原始事实与推断结论物理分离，§10.2 不变式 4）：
本表只存放 L3 追加的富化维度，基础字段通过 ``vuln_id`` 外键指向父表。

Note:
    为兼容 async 场景，本映射**不定义 ORM relationship**（避免隐式 lazy-load 触发
    ``MissingGreenlet``）；还原领域对象时由仓储显式传入父表领域对象。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.models.base import SCHEMA_VERSION
from aisec_intel.models.enriched_vuln import (
    AffectedAsset,
    AgentStep,
    AttackChain,
    EnrichedVuln,
    ExploitRecord,
)
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.base import Base


class EnrichedVulnRow(Base):
    """``enriched_vuln`` 表：L3 五维度富化结论 + 复核状态。"""

    __tablename__ = "enriched_vuln"

    vuln_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("unified_vuln.vuln_id", ondelete="CASCADE"),
        primary_key=True,
        doc="指向 unified_vuln.vuln_id（1:1）",
    )
    schema_version: Mapped[str] = mapped_column(String(8), default=SCHEMA_VERSION)
    affected_assets: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    related_papers: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    exploits: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), index=True)
    risk_breakdown: Mapped[dict[str, float]] = mapped_column(JSON, default=dict)
    attack_chain: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)
    confidence: Mapped[float] = mapped_column(Float)
    review_status: Mapped[str] = mapped_column(String(16), default="auto_pass", index=True)
    review_notes: Mapped[list[str]] = mapped_column(JSON, default=list)
    agent_trace: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    model_used: Mapped[str] = mapped_column(String(64), doc="fast / smart 模型标识")
    enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_error: Mapped[str | None] = mapped_column(Text, default=None, doc="最近一次富化失败原因")

    @classmethod
    def from_domain(cls, enriched: EnrichedVuln) -> EnrichedVulnRow:
        """由领域模型构造 ORM 行。

        Args:
            enriched: L3 富化输出实体。

        Returns:
            可直接 ``session.merge`` 的 ORM 行实例。
        """
        return cls(
            vuln_id=enriched.vuln_id,
            schema_version=enriched.schema_version,
            affected_assets=[item.model_dump(mode="json") for item in enriched.affected_assets],
            related_papers=[item.model_dump(mode="json") for item in enriched.related_papers],
            exploits=[item.model_dump(mode="json") for item in enriched.exploits],
            risk_score=enriched.risk_score,
            risk_level=enriched.risk_level,
            risk_breakdown=dict(enriched.risk_breakdown),
            attack_chain=enriched.attack_chain.model_dump(mode="json") if enriched.attack_chain else None,
            confidence=enriched.confidence,
            review_status=enriched.review_status,
            review_notes=list(enriched.review_notes),
            agent_trace=[item.model_dump(mode="json") for item in enriched.agent_trace],
            model_used=enriched.model_used,
            enriched_at=enriched.enriched_at,
        )

    def to_domain(self, base: UnifiedVuln) -> EnrichedVuln:
        """由 ORM 行 + 父表领域对象还原 ``EnrichedVuln``。

        Args:
            base: 父表 ``unified_vuln`` 的领域对象（由仓储显式查询得到）。

        Returns:
            完整的 ``EnrichedVuln``（父字段来自 ``base``，富化字段来自本行）。

        Raises:
            ValueError: ``base.vuln_id`` 与本行 ``vuln_id`` 不一致（数据不一致，应视为缺陷）。
        """
        if base.vuln_id != self.vuln_id:
            raise ValueError(f"父表 vuln_id({base.vuln_id}) 与富化行 vuln_id({self.vuln_id}) 不一致")

        payload: dict[str, Any] = base.model_dump()
        payload.update(
            affected_assets=[AffectedAsset.model_validate(item) for item in (self.affected_assets or [])],
            related_papers=[PaperVulnLink.model_validate(item) for item in (self.related_papers or [])],
            exploits=[ExploitRecord.model_validate(item) for item in (self.exploits or [])],
            risk_score=self.risk_score,
            risk_level=self.risk_level,
            risk_breakdown=dict(self.risk_breakdown or {}),
            attack_chain=AttackChain.model_validate(self.attack_chain) if self.attack_chain else None,
            confidence=self.confidence,
            review_status=self.review_status,
            review_notes=list(self.review_notes or []),
            agent_trace=[AgentStep.model_validate(item) for item in (self.agent_trace or [])],
            model_used=self.model_used,
            enriched_at=self.enriched_at,
        )
        return EnrichedVuln(**payload)
