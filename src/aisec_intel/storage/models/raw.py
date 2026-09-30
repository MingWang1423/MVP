"""``RawItem`` 的 ORM 映射（表 ``raw_item``）。

设计说明：
    - 主键为内容指纹 ``sha256``：**内容寻址**，重复采集同一内容天然幂等（§10.2 不变式 5）；
    - ``(source, source_id)`` 建复合索引，支撑「按源+源内 ID 查历史版本」；
    - 源侧更新会使 ``raw_text`` 变化 → ``sha256`` 变化 → 新增一行（保留可审计版本历史）。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.models.base import SCHEMA_VERSION
from aisec_intel.models.raw_item import RawItem
from aisec_intel.storage.base import Base


class RawItemRow(Base):
    """``raw_item`` 表：L1 采集层的原始件（保真原文 + 链接 + 指纹）。"""

    __tablename__ = "raw_item"
    __table_args__ = (Index("ix_raw_item_source_source_id", "source", "source_id"),)

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True, doc="raw_text 内容指纹（内容寻址主键）")
    schema_version: Mapped[str] = mapped_column(String(8), default=SCHEMA_VERSION)
    trace_id: Mapped[str] = mapped_column(String(64), index=True, doc="全链路追踪 ID")
    source: Mapped[str] = mapped_column(String(32), index=True, doc="源标识，如 kev")
    source_id: Mapped[str] = mapped_column(String(64), doc="源内唯一 ID，如 CVE-2024-3400")
    url: Mapped[str] = mapped_column(Text, doc="原文链接")
    title: Mapped[str | None] = mapped_column(String(1024), default=None)
    raw_text: Mapped[str] = mapped_column(Text, doc="保真原文（JSON 或正文）")
    lang: Mapped[str | None] = mapped_column(String(16), default=None)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    meta: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)

    @classmethod
    def from_domain(cls, item: RawItem) -> RawItemRow:
        """由 ``RawItem`` 构造 ORM 行。

        Args:
            item: L1 采集输出。

        Returns:
            可直接 ``session.add`` 的 ORM 行实例。
        """
        return cls(
            sha256=item.sha256,
            schema_version=item.schema_version,
            trace_id=item.trace_id,
            source=item.source,
            source_id=item.source_id,
            url=item.url,
            title=item.title,
            raw_text=item.raw_text,
            lang=item.lang,
            published_at=item.published_at,
            fetched_at=item.fetched_at,
            meta=dict(item.meta),
        )

    def to_domain(self) -> RawItem:
        """由 ORM 行还原 ``RawItem``。

        Returns:
            ``RawItem`` 实例（naive 时间由基类归一化为 UTC）。
        """
        return RawItem(
            schema_version=self.schema_version,
            trace_id=self.trace_id,
            source=self.source,
            source_id=self.source_id,
            url=self.url,
            title=self.title,
            raw_text=self.raw_text,
            lang=self.lang,
            published_at=self.published_at,
            fetched_at=self.fetched_at,
            sha256=self.sha256,
            meta=dict(self.meta or {}),
        )
