"""``external_evidence`` 的 ORM 映射（Day25 阶段 2 任务 2.1）。

用途：**受控外部检索的隔离区**——本地证据不足时从权威源（NVD / GHSA / OSV / CISA KEV）
补齐的事实只落本表：

1. **不写正式表**：``unified_vuln`` / ``enriched_vuln`` 仍只由 L1/L2/L3 链路写入，
   外部内容永远无法直接污染正式字段（§10.2 不变式 4 的延伸）；
2. **可回溯**：``url`` + ``content_hash`` 保证每条外部事实能回到原始来源；
3. **可复核**：``trust_score`` / ``verified`` 记录 :class:`~aisec_intel.qa.agents.verifier.ExternalEvidenceVerifier`
   的裁决结果，``verified=True`` 才允许提升为答案事实。

Note:
    ``to_domain()`` 不还原 ``facts``（事实标签由纯函数
    :func:`aisec_intel.qa.evidence_gap.facts_in_text` 在读取侧重算，
    保证「存储层不依赖问答层」的分层约束）。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.models.external_evidence import ExternalEvidence
from aisec_intel.storage.base import Base


class ExternalEvidenceRow(Base):
    """``external_evidence`` 表：受控外部证据（不可信内容隔离区）。"""

    __tablename__ = "external_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    query: Mapped[str] = mapped_column(String(512), index=True, default="", doc="触发检索的问题原文")
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True, default=None, doc="关联 CVE 编号")
    source_type: Mapped[str] = mapped_column(String(16), index=True, doc="nvd / ghsa / osv / kev")
    source_name: Mapped[str] = mapped_column(String(128), default="", doc="来源内标识（GHSA / OSV / CVE ID）")
    url: Mapped[str] = mapped_column(String(512), default="", doc="原始链接")
    title: Mapped[str] = mapped_column(Text, default="", doc="标题")
    snippet: Mapped[str] = mapped_column(Text, default="", doc="已清洗正文片段（≤2000 字符）")
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, doc="抓取时间（UTC）")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, doc="源侧发布时间")
    trust_score: Mapped[float] = mapped_column(Float, default=0.0, doc="可信度评分 0~1")
    verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True, doc="是否通过复核")
    content_hash: Mapped[str] = mapped_column(String(64), index=True, default="", doc="内容指纹（幂等键）")

    def to_domain(self) -> ExternalEvidence:
        """转换为领域模型（``facts`` 留空，由读取侧纯函数重算）。

        Returns:
            :class:`~aisec_intel.models.external_evidence.ExternalEvidence`。
        """
        return ExternalEvidence(
            query=self.query or "",
            cve_id=self.cve_id,
            source_type=self.source_type,  # type: ignore[arg-type]
            source_name=self.source_name or "",
            url=self.url or "",
            title=self.title or "",
            snippet=self.snippet or "",
            retrieved_at=self.retrieved_at,
            published_at=self.published_at,
            trust_score=float(self.trust_score or 0.0),
            verified=bool(self.verified),
            content_hash=self.content_hash or "",
            facts=[],
            untrusted=True,
        )

    @classmethod
    def from_domain(cls, item: ExternalEvidence) -> ExternalEvidenceRow:
        """由领域模型构造 ORM 行（唯一转换边界）。

        Args:
            item: 外部证据领域对象。

        Returns:
            :class:`ExternalEvidenceRow`（未绑定会话，由仓储 ``add``）。
        """
        return cls(
            query=item.query,
            cve_id=item.cve_id,
            source_type=item.source_type,
            source_name=item.source_name,
            url=item.url,
            title=item.title,
            snippet=item.snippet,
            retrieved_at=item.retrieved_at,
            published_at=item.published_at,
            trust_score=item.trust_score,
            verified=item.verified,
            content_hash=item.content_hash,
        )
