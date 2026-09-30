"""采集源登记表 ``source``（PROJECT_PLAN.md §2 ``scripts/seed_sources.py``）。

用途：把「代码里注册的采集器」同步为数据库中的**可运维清单**，供：
    - 前端「采集运维」页展示各源开关 / 限流 / 上次成功时间；
    - P4 调度器按 ``enabled`` 决定本次要跑哪些源。

Note:
    该表是**运维元数据**，不是漏洞事实数据；``last_run_at`` 为 ``task_run`` 的冗余视图，
    权威游标仍以 ``task_run`` 为准（``TaskRepository.last_run_at``）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from sqlalchemy import JSON, Boolean, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.models.base import OptionalUTCDateTime, UTCDateTime
from aisec_intel.storage.base import Base


class SourceSnapshot(BaseModel):
    """采集源登记快照（供 CLI 打印与运维页展示）。

    Attributes:
        name: 源标识（主键）。
        connector_class: 采集器类名。
        display_name: 展示名。
        rate_limit: 限流规格（``次数/秒``）。
        timeout_s: 单请求超时（秒）。
        enabled: 是否启用。
        last_run_at: 上次成功采集时间（UTC）。
        updated_at: 登记信息更新时间（UTC）。
        meta: 附加信息。
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    connector_class: str
    display_name: str | None = None
    rate_limit: str = "10/1"
    timeout_s: float = 30.0
    enabled: bool = True
    last_run_at: OptionalUTCDateTime = None
    updated_at: UTCDateTime
    meta: dict[str, Any] = {}


class SourceRow(Base):
    """``source`` 表：采集源登记与运维状态。"""

    __tablename__ = "source"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    connector_class: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str | None] = mapped_column(String(128), default=None)
    rate_limit: Mapped[str] = mapped_column(String(16), default="10/1")
    timeout_s: Mapped[float] = mapped_column(Float, default=30.0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    def to_snapshot(self) -> SourceSnapshot:
        """转换为运维快照。

        Returns:
            ``SourceSnapshot`` 实例。
        """
        return SourceSnapshot(
            name=self.name,
            connector_class=self.connector_class,
            display_name=self.display_name,
            rate_limit=self.rate_limit,
            timeout_s=self.timeout_s,
            enabled=self.enabled,
            last_run_at=self.last_run_at,
            updated_at=self.updated_at,
            meta=dict(self.meta or {}),
        )


__all__ = ["SourceRow", "SourceSnapshot"]
