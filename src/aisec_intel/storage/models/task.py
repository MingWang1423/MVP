"""采集任务运行记录（表 ``task_run``，PROJECT_PLAN.md §5.2 P1 / §5.3 P2）。

用途：
    - 记录每次采集任务的 started / succeeded / failed 与统计（拉取 / 新增 / 跳过）；
    - 提供**增量游标**：``task_repo.last_run_at(source)`` 即「上次成功时间」，
      ``run_collect`` 用它推导默认 ``--since``（P4 的增量采集基础）。

对应 ORM 诊断快照 ``TaskRunSnapshot`` 一并定义在本模块（运维数据，非跨层契约）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.models.base import OptionalUTCDateTime, UTCDateTime
from aisec_intel.storage.base import Base

TaskStatus = Literal["running", "succeeded", "failed"]
"""任务状态：运行中 / 成功 / 失败。"""


class TaskRunSnapshot(BaseModel):
    """任务运行记录快照（供 CLI 打印与前端「采集运维」页展示）。

    Attributes:
        id: 自增主键。
        source: 源标识（如 ``kev``）。
        task_name: 任务名（默认 ``collect:<source>``）。
        status: 任务状态。
        started_at: 开始时间（UTC）。
        finished_at: 结束时间（UTC），运行中为 ``None``。
        fetched: 拉取条数。
        created: 新增条数。
        skipped: 跳过条数（指纹已存在）。
        duration_s: 耗时（秒），未结束时为 ``None``。
        error: 失败原因。
        meta: 附加信息。
    """

    model_config = ConfigDict(extra="forbid")

    id: int
    source: str
    task_name: str
    status: TaskStatus
    started_at: UTCDateTime
    finished_at: OptionalUTCDateTime = None
    fetched: int = 0
    created: int = 0
    skipped: int = 0
    duration_s: float | None = None
    error: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class TaskRunRow(Base):
    """``task_run`` 表：采集/富化任务运行记录与增量游标。"""

    __tablename__ = "task_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    task_name: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    fetched: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    def to_snapshot(self) -> TaskRunSnapshot:
        """转换为诊断快照。

        Returns:
            ``TaskRunSnapshot`` 实例（含耗时计算）。
        """
        duration: float | None = None
        if self.finished_at is not None:
            started = self.started_at
            finished = self.finished_at
            # SQLite 读回 naive、PostgreSQL 读回 aware，这里对齐后相减
            if started.tzinfo is None and finished.tzinfo is not None:
                started = started.replace(tzinfo=finished.tzinfo)
            elif started.tzinfo is not None and finished.tzinfo is None:
                finished = finished.replace(tzinfo=started.tzinfo)
            duration = (finished - started).total_seconds()
        return TaskRunSnapshot(
            id=self.id,
            source=self.source,
            task_name=self.task_name,
            status=self.status,  # type: ignore[arg-type]
            started_at=self.started_at,
            finished_at=self.finished_at,
            fetched=self.fetched,
            created=self.created,
            skipped=self.skipped,
            duration_s=duration,
            error=self.error,
            meta=dict(self.meta or {}),
        )
