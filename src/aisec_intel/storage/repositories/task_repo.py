"""``task_run`` 仓储：任务状态与增量游标（PROJECT_PLAN.md §5.2 P1 / §5.3 P2）。

提供三类能力：

1. **状态流转**：``start()`` → ``succeeded()`` / ``failed()``；
2. **统计留痕**：每次任务记录「拉取 / 新增 / 跳过」条数与耗时；
3. **增量游标**：``last_run_at(source)`` 返回该源**上次成功完成时间**，
   供 ``run_collect`` 推导默认 ``--since``（P4 增量采集的基础）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.base import to_utc, utc_now
from aisec_intel.storage.models.task import TaskRunRow, TaskRunSnapshot


class TaskRepository:
    """任务运行记录仓储。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    @staticmethod
    def default_task_name(source: str) -> str:
        """默认任务名。

        Args:
            source: 源标识。

        Returns:
            形如 ``collect:kev`` 的任务名。
        """
        return f"collect:{source}"

    async def _require(self, task_id: int) -> TaskRunRow:
        """取出任务行，不存在则报错。

        Args:
            task_id: 任务主键。

        Returns:
            ORM 行。

        Raises:
            LookupError: 任务不存在。
        """
        row = await self._session.get(TaskRunRow, task_id)
        if row is None:
            raise LookupError(f"task_run 中不存在 id={task_id}")
        return row

    async def start(
        self,
        *,
        source: str,
        task_name: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> int:
        """登记任务开始。

        Args:
            source: 源标识。
            task_name: 任务名；缺省为 ``collect:<source>``。
            meta: 附加信息（如 ``{"since": ..., "limit": ...}``）。

        Returns:
            新建任务的 ``id``。
        """
        row = TaskRunRow(
            source=source,
            task_name=task_name or self.default_task_name(source),
            status="running",
            started_at=utc_now(),
            meta=dict(meta or {}),
        )
        self._session.add(row)
        await self._session.flush()
        return int(row.id)

    async def succeeded(
        self,
        task_id: int,
        *,
        fetched: int = 0,
        created: int = 0,
        skipped: int = 0,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """标记任务成功并写入统计。

        Args:
            task_id: 任务主键。
            fetched: 拉取条数。
            created: 新增条数。
            skipped: 跳过条数。
            meta: 附加信息（与 start 时的 meta 合并）。
        """
        row = await self._require(task_id)
        row.status = "succeeded"
        row.finished_at = utc_now()
        row.fetched = fetched
        row.created = created
        row.skipped = skipped
        if meta:
            merged = dict(row.meta or {})
            merged.update(meta)
            row.meta = merged
        await self._session.flush()

    async def failed(self, task_id: int, error: str) -> None:
        """标记任务失败并记录原因。

        Args:
            task_id: 任务主键。
            error: 失败原因（截断至 2000 字符）。
        """
        row = await self._require(task_id)
        row.status = "failed"
        row.finished_at = utc_now()
        row.error = error[:2000]
        await self._session.flush()

    async def last_run_at(self, source: str) -> datetime | None:
        """返回该源**上次成功完成时间**（增量游标）。

        Args:
            source: 源标识。

        Returns:
            UTC ``datetime``；该源从未成功跑过时返回 ``None``。
        """
        await self._session.flush()
        stmt = (
            select(TaskRunRow.finished_at)
            .where(
                TaskRunRow.source == source,
                TaskRunRow.status == "succeeded",
                TaskRunRow.finished_at.is_not(None),
            )
            .order_by(TaskRunRow.finished_at.desc())
            .limit(1)
        )
        value = (await self._session.execute(stmt)).scalar_one_or_none()
        return None if value is None else to_utc(value)

    async def get(self, task_id: int) -> TaskRunSnapshot | None:
        """按主键读取任务快照。

        Args:
            task_id: 任务主键。

        Returns:
            命中时返回快照，否则 ``None``。
        """
        row = await self._session.get(TaskRunRow, task_id)
        return row.to_snapshot() if row is not None else None

    async def list_recent(
        self,
        *,
        source: str | None = None,
        status: str | None = None,
        limit: int = 20,
    ) -> list[TaskRunSnapshot]:
        """按开始时间倒序列出最近任务。

        Args:
            source: 仅列出指定源。
            status: 仅列出指定状态（``running`` / ``succeeded`` / ``failed``）。
            limit: 返回条数上限。

        Returns:
            任务快照列表。
        """
        await self._session.flush()
        stmt = select(TaskRunRow).order_by(TaskRunRow.started_at.desc()).limit(limit)
        if source:
            stmt = stmt.where(TaskRunRow.source == source)
        if status:
            stmt = stmt.where(TaskRunRow.status == status)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [row.to_snapshot() for row in rows]
