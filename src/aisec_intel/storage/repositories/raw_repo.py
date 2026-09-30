"""``raw_item`` 仓储（PROJECT_PLAN.md §5.2 P1 / §5.3 P2）。

设计：
    - **内容寻址**：主键为 ``RawItem.sha256``，同一内容重复采集天然幂等；
      源侧更新会改变 ``raw_text`` → 改变指纹 → 新增一行（保留版本历史）；
    - ``upsert()`` 返回 ``RawUpsertResult(created=...)``，供 ``run_collect`` 统计
      「新增 / 跳过」条数；
    - 仓储是唯一允许出现 ORM 语句的层，对外只暴露 ``RawItem``。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.raw_item import RawItem
from aisec_intel.storage.models.raw import RawItemRow
from aisec_intel.utils.hashing import is_sha256


@dataclass(frozen=True, slots=True)
class RawUpsertResult:
    """``upsert`` 的结果。

    Attributes:
        created: ``True`` 表示本次为新增（指纹此前不存在），``False`` 表示已存在被跳过。
        item: 落库后的 ``RawItem``（内容与入参一致）。
    """

    created: bool
    item: RawItem


class RawRepository:
    """原始件仓储（内容寻址 + 幂等写入）。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    async def exists(self, sha256: str) -> bool:
        """判断指纹是否已存在。

        Args:
            sha256: 64 位十六进制内容指纹。

        Returns:
            已存在返回 ``True``。

        Raises:
            ValueError: 指纹格式非法。
        """
        if not is_sha256(sha256):
            raise ValueError(f"非法 sha256：{sha256!r}")
        row = await self._session.get(RawItemRow, sha256.lower())
        return row is not None

    async def upsert(self, item: RawItem) -> RawUpsertResult:
        """幂等写入（按 ``sha256`` 判重）。

        Args:
            item: L1 采集输出的原始件。

        Returns:
            :class:`RawUpsertResult`（``created`` 标识是否新增）。
        """
        key = item.sha256.lower()
        existing = await self._session.get(RawItemRow, key)
        if existing is not None:
            return RawUpsertResult(created=False, item=existing.to_domain())

        row = RawItemRow.from_domain(item)
        self._session.add(row)
        await self._session.flush()
        return RawUpsertResult(created=True, item=row.to_domain())

    async def get_by_hash(self, sha256: str) -> RawItem | None:
        """按内容指纹读取原始件。

        Args:
            sha256: 64 位十六进制内容指纹。

        Returns:
            命中时返回 ``RawItem``，否则 ``None``。

        Raises:
            ValueError: 指纹格式非法。
        """
        if not is_sha256(sha256):
            raise ValueError(f"非法 sha256：{sha256!r}")
        row = await self._session.get(RawItemRow, sha256.lower())
        return row.to_domain() if row is not None else None

    async def list_by_source(
        self,
        source: str,
        *,
        limit: int = 100,
        offset: int = 0,
        since: datetime | None = None,
        source_id: str | None = None,
    ) -> list[RawItem]:
        """按源列出原始件（发布时间倒序，缺失时回退采集时间）。

        Args:
            source: 源标识，如 ``"kev"``。
            limit: 返回条数上限。
            offset: 分页偏移。
            since: 仅返回 ``fetched_at >= since`` 的记录（UTC）。
            source_id: 仅返回指定源内 ID（如某个 CVE）的记录。

        Returns:
            ``RawItem`` 列表。
        """
        await self._session.flush()
        stmt = (
            select(RawItemRow)
            .where(RawItemRow.source == source)
            .order_by(func.coalesce(RawItemRow.published_at, RawItemRow.fetched_at).desc())
            .limit(limit)
            .offset(offset)
        )
        if since is not None:
            # 与排序口径保持一致：按「发布时间，缺失时回退采集时间」过滤
            stmt = stmt.where(func.coalesce(RawItemRow.published_at, RawItemRow.fetched_at) >= since)
        if source_id:
            stmt = stmt.where(RawItemRow.source_id == source_id)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [row.to_domain() for row in rows]

    async def count_by_source(self, source: str) -> int:
        """统计某源的原始件数量。

        Args:
            source: 源标识。

        Returns:
            记录数。
        """
        await self._session.flush()
        stmt = select(func.count()).select_from(RawItemRow).where(RawItemRow.source == source)
        return int((await self._session.execute(stmt)).scalar_one())
