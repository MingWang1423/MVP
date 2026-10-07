"""``external_evidence`` 仓储：受控外部证据的幂等落库与读取（Day25 阶段 2 任务 2.1）。

口径：
    - **幂等键 = ``content_hash``**：同一份外部内容重复检索不会产生重复行，
      只刷新 ``retrieved_at`` / ``trust_score`` / ``verified``（可审计的复核结果）；
    - **只读投影**：``to_domain()`` 不还原 ``facts``（问答层用纯函数重算，保持分层）；
    - **隔离**：本仓储只服务问答层的「外部证据」通道，任何写正式表的动作都不在此发生。
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.base import utc_now
from aisec_intel.models.external_evidence import ExternalEvidence
from aisec_intel.storage.models.external_evidence import ExternalEvidenceRow


class ExternalEvidenceRepository:
    """``external_evidence`` 表读写。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    async def upsert_many(self, items: Sequence[ExternalEvidence]) -> int:
        """按 ``content_hash`` 幂等写入一批外部证据。

        Args:
            items: 外部证据列表（同一批次内重复指纹自动去重）。

        Returns:
            实际写入 / 刷新的条数。
        """
        payload: dict[str, ExternalEvidence] = {}
        for item in items:
            key = item.content_hash or item.url or item.locator
            payload.setdefault(key, item)
        if not payload:
            return 0

        hashes = list(payload)
        stmt = select(ExternalEvidenceRow).where(ExternalEvidenceRow.content_hash.in_(hashes))
        rows = (await self._session.execute(stmt)).scalars().all()
        existing = {row.content_hash: row for row in rows}
        written = 0
        for key, item in payload.items():
            stored = item if item.content_hash else item.model_copy(update={"content_hash": key})
            row = existing.get(key)
            if row is None:
                self._session.add(ExternalEvidenceRow.from_domain(stored))
            else:
                row.trust_score = stored.trust_score
                row.verified = stored.verified
                row.retrieved_at = stored.retrieved_at or utc_now()
                row.query = stored.query or row.query
                row.snippet = stored.snippet or row.snippet
            written += 1
        await self._session.flush()
        return written

    async def list_by_cve(
        self,
        cve_id: str,
        *,
        limit: int = 20,
        verified_only: bool = False,
    ) -> list[ExternalEvidence]:
        """按 CVE 编号读取外部证据（按可信度 / 抓取时间倒序）。

        Args:
            cve_id: CVE 编号（大小写不敏感）。
            limit: 返回条数上限。
            verified_only: 只返回通过复核（``verified=True``）的条目。

        Returns:
            领域对象列表。
        """
        stmt = (
            select(ExternalEvidenceRow)
            .where(ExternalEvidenceRow.cve_id == str(cve_id).strip().upper())
            .order_by(
                ExternalEvidenceRow.verified.desc(),
                ExternalEvidenceRow.trust_score.desc(),
                ExternalEvidenceRow.retrieved_at.desc(),
            )
            .limit(max(1, limit))
        )
        if verified_only:
            stmt = stmt.where(ExternalEvidenceRow.verified.is_(True))
        rows = (await self._session.execute(stmt)).scalars().all()
        return [row.to_domain() for row in rows]

    async def list_recent(self, *, limit: int = 20) -> list[ExternalEvidence]:
        """读取最近抓取的外部证据（运维 / 审计视图）。

        Args:
            limit: 返回条数上限。

        Returns:
            领域对象列表（抓取时间倒序）。
        """
        stmt = select(ExternalEvidenceRow).order_by(ExternalEvidenceRow.retrieved_at.desc()).limit(max(1, limit))
        rows = (await self._session.execute(stmt)).scalars().all()
        return [row.to_domain() for row in rows]

    async def count(self, *, cve_id: str | None = None, verified_only: bool = False) -> int:
        """统计外部证据条数（验收 / 运维用）。

        Args:
            cve_id: 可选 CVE 过滤（大小写不敏感）。
            verified_only: 只统计通过复核的条目。

        Returns:
            条目数。
        """
        await self._session.flush()
        stmt = select(func.count()).select_from(ExternalEvidenceRow)
        if cve_id:
            stmt = stmt.where(ExternalEvidenceRow.cve_id == str(cve_id).strip().upper())
        if verified_only:
            stmt = stmt.where(ExternalEvidenceRow.verified.is_(True))
        return int((await self._session.execute(stmt)).scalar_one())
