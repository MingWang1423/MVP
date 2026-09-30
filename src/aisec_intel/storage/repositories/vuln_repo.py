"""``unified_vuln`` / ``enriched_vuln`` 的读写仓储（PROJECT_PLAN.md §5.2）。

约束：
    - 仓储是**唯一**允许拼写 ORM 语句的层，其他层只依赖领域模型（``aisec_intel.models``）；
    - 写操作幂等：以 ``vuln_id`` 为幂等键；``trace_ids`` / ``sources`` 做并集合并，
      保证「多源重复采集不新增、不丢链路」（§10.2 不变式 5）。
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.models.enriched import EnrichedVulnRow
from aisec_intel.storage.models.vuln import UnifiedVulnRow


def normalize_vuln_id(vuln_id: str) -> str:
    """规范化漏洞主键（去首尾空格 + 转大写）。

    Note:
        这是仓储层的**最小**规范化；完整规范化（别名归并、格式校验）属于 L2
        ``normalize/cve.py``（P2）。

    Args:
        vuln_id: 原始主键，如 ``" cve-2024-3400 "``。

    Returns:
        规范化后的主键，如 ``"CVE-2024-3400"``。
    """
    return vuln_id.strip().upper()


@dataclass(frozen=True, slots=True)
class VulnUpsertResult:
    """``upsert_with_status`` 的结果。

    Attributes:
        created: ``True`` 表示本次为新增行，``False`` 表示更新既有行。
        vuln: 写入后读回的领域实体。
    """

    created: bool
    vuln: UnifiedVuln


class VulnRepository:
    """漏洞实体仓储：``unified_vuln``（事实层）与 ``enriched_vuln``（富化层）。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    @staticmethod
    def _column_names() -> list[str]:
        """返回 ``unified_vuln`` 表的列名列表（``vuln_id`` 除外，主键不参与覆盖）。

        Returns:
            可安全 ``setattr`` 的列名列表。
        """
        return [column.key for column in UnifiedVulnRow.__table__.columns if column.key != "vuln_id"]

    @staticmethod
    def _apply_columns(row: UnifiedVulnRow, source: UnifiedVulnRow) -> None:
        """把 ``source`` 的列值覆盖到已存在的 ``row``（跳过主键）。

        Args:
            row: 库中已存在的行。
            source: 由领域模型新构造的行。
        """
        for column in VulnRepository._column_names():
            setattr(row, column, getattr(source, column))

    async def upsert(self, vuln: UnifiedVuln) -> UnifiedVuln:
        """按 ``vuln_id`` 幂等写入（不存在则插入，存在则更新）。

        Args:
            vuln: L2 归一化输出的领域实体。

        Returns:
            写入后读回的领域实体（``trace_ids`` / ``sources`` 已做并集合并）。
        """
        key = normalize_vuln_id(vuln.vuln_id)
        normalized = vuln.model_copy(update={"vuln_id": key})
        existing = await self._session.get(UnifiedVulnRow, key)
        if existing is None:
            row = UnifiedVulnRow.from_domain(normalized)
            self._session.add(row)
            await self._session.flush()
            return row.to_domain()

        merged = normalized.model_copy(
            update={
                "trace_ids": sorted({*(existing.trace_ids or []), *normalized.trace_ids}),
                "sources": sorted({*(existing.sources or []), *normalized.sources}),
            }
        )
        self._apply_columns(existing, UnifiedVulnRow.from_domain(merged))
        await self._session.flush()
        return existing.to_domain()

    async def upsert_with_status(self, vuln: UnifiedVuln) -> VulnUpsertResult:
        """与 :meth:`upsert` 相同，但额外返回「本次是否新增」。

        Note:
            与 :meth:`upsert` 分离，是为了在不破坏既有调用方的同时，
            支持 ``run_collect --normalize`` 统计「新增 / 更新」条数（P3 验收口径）。

        Args:
            vuln: L2 归一化输出的领域实体。

        Returns:
            :class:`VulnUpsertResult`。
        """
        created = await self._session.get(UnifiedVulnRow, normalize_vuln_id(vuln.vuln_id)) is None
        stored = await self.upsert(vuln)
        return VulnUpsertResult(created=created, vuln=stored)

    async def get_by_cve(self, cve_id: str) -> UnifiedVuln | None:
        """按 CVE 编号读取。

        Args:
            cve_id: 漏洞主键（大小写不敏感）。

        Returns:
            命中时返回领域实体，否则 ``None``。
        """
        row = await self._session.get(UnifiedVulnRow, normalize_vuln_id(cve_id))
        return row.to_domain() if row is not None else None

    async def list_recent(
        self,
        *,
        limit: int = 20,
        kev_only: bool = False,
        offset: int = 0,
    ) -> list[UnifiedVuln]:
        """按发布时间倒序返回最近漏洞（``published_at`` 为空时回退 ``normalized_at``）。

        Args:
            limit: 返回条数上限。
            kev_only: 仅返回 CISA KEV（已知被利用）条目。
            offset: 分页偏移。

        Returns:
            领域实体列表（时间字段已归一化为 UTC）。
        """
        await self._session.flush()
        stmt = (
            select(UnifiedVulnRow)
            .order_by(func.coalesce(UnifiedVulnRow.published_at, UnifiedVulnRow.normalized_at).desc())
            .limit(limit)
            .offset(offset)
        )
        if kev_only:
            stmt = stmt.where(UnifiedVulnRow.kev.is_(True))
        rows = (await self._session.execute(stmt)).scalars().all()
        return [row.to_domain() for row in rows]


    async def upsert_enriched(self, enriched: EnrichedVuln) -> EnrichedVuln:
        """幂等写入富化结果（要求父表 ``unified_vuln`` 已存在同主键行）。

        Args:
            enriched: L3 富化输出实体。

        Returns:
            规范化主键后的富化实体。

        Raises:
            ValueError: 父表缺少对应 ``vuln_id``（富化结论必须挂在已知事实上，§10.2 不变式 4）。
        """
        key = normalize_vuln_id(enriched.vuln_id)
        base_row = await self._session.get(UnifiedVulnRow, key)
        if base_row is None:
            raise ValueError(f"unified_vuln 中不存在 {key}，无法写入富化结果（请先 upsert 事实层）")

        normalized = enriched.model_copy(update={"vuln_id": key})
        source = EnrichedVulnRow.from_domain(normalized)
        existing = await self._session.get(EnrichedVulnRow, key)
        if existing is None:
            self._session.add(source)
        else:
            for column in [col.key for col in EnrichedVulnRow.__table__.columns if col.key != "vuln_id"]:
                setattr(existing, column, getattr(source, column))
        await self._session.flush()
        return normalized

    async def get_enriched(self, cve_id: str) -> EnrichedVuln | None:
        """按 CVE 编号读取富化结果（父字段 + 富化维度合并还原）。

        Args:
            cve_id: 漏洞主键（大小写不敏感）。

        Returns:
            命中时返回 ``EnrichedVuln``，否则 ``None``。

        Raises:
            ValueError: 富化行存在但事实层缺失（数据不一致，属于缺陷）。
        """
        key = normalize_vuln_id(cve_id)
        row = await self._session.get(EnrichedVulnRow, key)
        if row is None:
            return None
        base_row = await self._session.get(UnifiedVulnRow, key)
        if base_row is None:
            raise ValueError(f"富化行 {key} 存在但 unified_vuln 缺失，数据不一致")
        return row.to_domain(base_row.to_domain())

    async def list_top_risk(self, *, limit: int = 10) -> list[tuple[str, float, str]]:
        """返回风险分最高的条目（供前端「情报看板」直接消费）。

        Args:
            limit: 返回条数上限。

        Returns:
            ``(vuln_id, risk_score, risk_level)`` 三元组列表，按风险分倒序。
        """
        await self._session.flush()
        stmt = (
            select(EnrichedVulnRow.vuln_id, EnrichedVulnRow.risk_score, EnrichedVulnRow.risk_level)
            .order_by(EnrichedVulnRow.risk_score.desc())
            .limit(limit)
        )
        return [(row[0], row[1], row[2]) for row in (await self._session.execute(stmt)).all()]
