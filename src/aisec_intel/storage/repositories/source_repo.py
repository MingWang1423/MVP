"""``source`` 表仓储：采集源登记与启用开关（PROJECT_PLAN.md §2）。

只做「登记同步」与查询；运行时是否真正采集由调度器依据 ``enabled`` 决定（P4）。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.base import utc_now
from aisec_intel.storage.models.source import SourceRow, SourceSnapshot


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """采集源登记入参（由连接器注册表构建）。

    Attributes:
        name: 源标识。
        connector_class: 采集器类名。
        rate_limit: 限流规格。
        timeout_s: 单请求超时（秒）。
        enabled: 是否启用。
        display_name: 展示名。
        meta: 附加信息。
    """

    name: str
    connector_class: str
    rate_limit: str = "10/1"
    timeout_s: float = 30.0
    enabled: bool = True
    display_name: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class SourceRepository:
    """采集源登记仓储。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 ``session_scope`` 提供的会话。
        """
        self._session = session

    async def upsert_many(self, specs: Sequence[SourceSpec]) -> tuple[int, int]:
        """批量幂等登记（存在则更新限流/超时/类名等）。

        Args:
            specs: 源登记入参列表。

        Returns:
            ``(created, updated)`` 计数。

        Raises:
            ValueError: 出现重复源标识（登记数据自身不一致）。
        """
        names = [spec.name for spec in specs]
        if len(names) != len(set(names)):
            raise ValueError(f"登记列表存在重复源标识：{names}")
        created = 0
        updated = 0
        now = utc_now()
        for spec in specs:
            row = await self._session.get(SourceRow, spec.name)
            if row is None:
                self._session.add(
                    SourceRow(
                        name=spec.name,
                        connector_class=spec.connector_class,
                        display_name=spec.display_name or spec.name,
                        rate_limit=spec.rate_limit,
                        timeout_s=spec.timeout_s,
                        enabled=spec.enabled,
                        updated_at=now,
                        meta=dict(spec.meta),
                    )
                )
                created += 1
                continue
            row.connector_class = spec.connector_class
            row.display_name = spec.display_name or spec.name
            row.rate_limit = spec.rate_limit
            row.timeout_s = spec.timeout_s
            row.enabled = spec.enabled
            row.updated_at = now
            row.meta = {**(row.meta or {}), **spec.meta}
            updated += 1
        await self._session.flush()
        return created, updated

    async def list_all(self, *, enabled_only: bool = False) -> list[SourceSnapshot]:
        """列出已登记的源（按名称排序）。

        Args:
            enabled_only: 仅返回启用中的源。

        Returns:
            源快照列表。
        """
        await self._session.flush()
        stmt = select(SourceRow).order_by(SourceRow.name)
        if enabled_only:
            stmt = stmt.where(SourceRow.enabled.is_(True))
        rows = (await self._session.execute(stmt)).scalars().all()
        return [row.to_snapshot() for row in rows]

    async def count(self, *, enabled_only: bool = True) -> int:
        """统计已登记的采集源数量（仪表盘「数据源」KPI）。

        Args:
            enabled_only: 仅统计启用中的源（默认 ``True``）。

        Returns:
            源数量。
        """
        await self._session.flush()
        stmt = select(func.count()).select_from(SourceRow)
        if enabled_only:
            stmt = stmt.where(SourceRow.enabled.is_(True))
        return int((await self._session.execute(stmt)).scalar() or 0)

    async def get(self, name: str) -> SourceSnapshot | None:
        """按源标识读取登记信息。

        Args:
            name: 源标识。

        Returns:
            命中时返回快照，否则 ``None``。
        """
        row = await self._session.get(SourceRow, name.strip().lower())
        return row.to_snapshot() if row is not None else None

    async def set_enabled(self, name: str, *, enabled: bool) -> bool:
        """启用 / 停用某个源。

        Args:
            name: 源标识。
            enabled: 目标状态。

        Returns:
            命中并更新返回 ``True``，源不存在返回 ``False``。
        """
        row = await self._session.get(SourceRow, name.strip().lower())
        if row is None:
            return False
        row.enabled = enabled
        row.updated_at = utc_now()
        await self._session.flush()
        return True

    async def sync_last_run_at(self, name: str, last_run_at: Any) -> bool:
        """同步 ``task_run`` 的增量游标（冗余视图，供运维页直接展示）。

        Args:
            name: 源标识。
            last_run_at: 上次成功时间（UTC ``datetime``）。

        Returns:
            命中并更新返回 ``True``。
        """
        row = await self._session.get(SourceRow, name.strip().lower())
        if row is None:
            return False
        row.last_run_at = last_run_at
        await self._session.flush()
        return True
