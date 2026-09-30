"""``UnifiedVuln`` 的 ORM 映射（表 ``unified_vuln``）。

设计说明：
    - 标量字段（严重度、EPSS、时间、KEV）单独建列并加索引，支持 SQL Agent 的筛选与统计；
    - 嵌套结构（``cvss`` / ``cpe_matches`` / ``references``）以 JSON 列承载，
      避免 P0 阶段引入多张子表（P2 起如需 SQL 侧 join，可再拆表并追加迁移）。
    - ``to_domain()`` / ``from_domain()`` 是 ORM 与领域契约之间的**唯一**转换边界。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.models.unified_vuln import (
    UNIFIED_VULN_SCHEMA_VERSION,
    CpeMatch,
    CVSSVector,
    Reference,
    UnifiedVuln,
)
from aisec_intel.storage.base import Base


class UnifiedVulnRow(Base):
    """``unified_vuln`` 表：L2 归一化结果（纯事实，不含推断结论）。"""

    __tablename__ = "unified_vuln"

    vuln_id: Mapped[str] = mapped_column(String(32), primary_key=True, doc="规范主键，如 CVE-2024-3400")
    schema_version: Mapped[str] = mapped_column(String(8), default=UNIFIED_VULN_SCHEMA_VERSION)
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    trace_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    title: Mapped[str | None] = mapped_column(String(512), default=None)
    description: Mapped[str] = mapped_column(Text, default="")
    lang: Mapped[str | None] = mapped_column(String(16), default=None)
    cvss: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    severity: Mapped[str | None] = mapped_column(String(16), default=None, index=True)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    cpe_matches: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    affected_versions: Mapped[list[str] | None] = mapped_column(JSON, default=None)
    ecosystem_packages: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    epss_score: Mapped[float | None] = mapped_column(Float, default=None)
    epss_percentile: Mapped[float | None] = mapped_column(Float, default=None)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, index=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    normalized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    @classmethod
    def from_domain(cls, vuln: UnifiedVuln) -> UnifiedVulnRow:
        """由领域模型构造 ORM 行。

        Args:
            vuln: L2 归一化输出实体。

        Returns:
            可直接 ``session.merge`` 的 ORM 行实例。
        """
        return cls(
            vuln_id=vuln.vuln_id,
            schema_version=vuln.schema_version,
            aliases=list(vuln.aliases),
            trace_ids=list(vuln.trace_ids),
            title=vuln.title,
            description=vuln.description,
            lang=vuln.lang,
            cvss=[item.model_dump(mode="json") for item in vuln.cvss],
            severity=vuln.severity,
            cwe_ids=list(vuln.cwe_ids),
            cpe_matches=[item.model_dump(mode="json") for item in vuln.cpe_matches],
            affected_versions=list(vuln.affected_versions),
            ecosystem_packages=list(vuln.ecosystem_packages),
            references=[item.model_dump(mode="json") for item in vuln.references],
            kev=vuln.kev,
            epss_score=vuln.epss_score,
            epss_percentile=vuln.epss_percentile,
            published_at=vuln.published_at,
            modified_at=vuln.modified_at,
            sources=list(vuln.sources),
            normalized_at=vuln.normalized_at,
        )

    def to_domain(self) -> UnifiedVuln:
        """由 ORM 行还原领域模型。

        Returns:
            ``UnifiedVuln`` 实例；数据库中的 naive 时间会被基类归一化为 UTC（§10.2 不变式 3）。
        """
        return UnifiedVuln(
            schema_version=self.schema_version,
            vuln_id=self.vuln_id,
            aliases=list(self.aliases or []),
            trace_ids=list(self.trace_ids or []),
            title=self.title,
            description=self.description,
            lang=self.lang,
            cvss=[CVSSVector.model_validate(item) for item in (self.cvss or [])],
            severity=self.severity,  # type: ignore[arg-type]
            cwe_ids=list(self.cwe_ids or []),
            cpe_matches=[CpeMatch.model_validate(item) for item in (self.cpe_matches or [])],
            affected_versions=list(self.affected_versions or []),
            ecosystem_packages=list(self.ecosystem_packages or []),
            references=[Reference.model_validate(item) for item in (self.references or [])],
            kev=self.kev,
            epss_score=self.epss_score,
            epss_percentile=self.epss_percentile,
            published_at=self.published_at,
            modified_at=self.modified_at,
            sources=list(self.sources or []),
            normalized_at=self.normalized_at,
        )
