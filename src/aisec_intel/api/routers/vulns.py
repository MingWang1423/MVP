"""漏洞查询路由（Day12 任务 5；PROJECT_PLAN.md §5.8 ``api/routers/vulns.py``）。

端点：

===============================  ==============================================
``GET /vulnerabilities``         漏洞列表（分页 + 严重度 / 来源 / 时间 / KEV 筛选）
``GET /vulnerabilities/{cve_id}`` 漏洞详情（事实层 + 富化层双契约）
===============================  ==============================================

前端（``frontend/pages/``）只消费这两个端点即可完成「列表 → 详情」主流程；
富化七维展示所需字段全部来自冻结契约 ``EnrichedVuln``，无需 DTO 映射。
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status

from aisec_intel.api.deps import get_settings_dep, get_vuln_repo
from aisec_intel.api.schemas.vuln import VulnDetailResponse, VulnListResponse, VulnSummary
from aisec_intel.config import Settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import utc_now
from aisec_intel.models.unified_vuln import Severity, UnifiedVuln
from aisec_intel.storage.repositories.vuln_repo import VulnRepository

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
"""漏洞查询路由（挂载后路径为 ``/api/v1/vulnerabilities/...``）。"""

MAX_PAGE_SIZE: int = 100
"""单页最大条数（防止前端一次拉全库）。"""


def _to_summary(vuln: UnifiedVuln, risk: tuple[float, str] | None) -> VulnSummary:
    """把事实层实体 + 可选风险分组装为列表条目（纯函数）。

    Args:
        vuln: ``UnifiedVuln`` 实体。
        risk: ``(risk_score, risk_level)``；未富化时为 ``None``。

    Returns:
        :class:`VulnSummary`。

    Note:
        实际装配逻辑在 :meth:`~aisec_intel.api.schemas.vuln.VulnSummary.from_unified`，
        与 ``GET /stats`` 的表格共用同一口径。
    """
    return VulnSummary.from_unified(vuln, risk)


@router.get(
    "",
    response_model=VulnListResponse,
    summary="漏洞列表（严重度 / 来源 / 时间筛选）",
)
async def list_vulnerabilities(
    severity: Severity | None = Query(default=None, description="严重度过滤：CRITICAL/HIGH/..."),
    source: str | None = Query(default=None, description="数据源过滤：nvd/osv/ghsa/kev/epss/..."),
    days: int | None = Query(default=None, ge=1, le=3650, description="仅返回最近 N 天（按发布时间）"),
    kev_only: bool = Query(default=False, description="仅返回 CISA KEV（已知被利用）条目"),
    limit: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE, description="单页条数"),
    offset: int = Query(default=0, ge=0, description="分页偏移"),
    repo: VulnRepository = Depends(get_vuln_repo),
    settings: Settings = Depends(get_settings_dep),
) -> VulnListResponse:
    """返回漏洞列表（按发布时间倒序，附带富化风险分）。

    Args:
        severity: 严重度过滤。
        source: 数据源过滤。
        days: 时间窗（天）。
        kev_only: 仅 KEV 条目。
        limit: 单页条数。
        offset: 分页偏移。
        repo: 漏洞仓储（请求级会话）。
        settings: 全局配置（时间窗换算用 UTC 当前时间）。

    Returns:
        :class:`VulnListResponse`。
    """
    since = utc_now() - timedelta(days=days) if days else None
    rows, total = await repo.list_filtered(
        severity=severity,
        source=source,
        since=since,
        kev_only=kev_only,
        limit=limit,
        offset=offset,
    )
    risks = await repo.risk_levels([row.vuln_id for row in rows])
    items = [_to_summary(row, risks.get(row.vuln_id)) for row in rows]
    logger.info(
        f"漏洞列表：env={settings.app_env} 命中={total} 返回={len(items)} "
        f"severity={severity} source={source} days={days} kev_only={kev_only}"
    )
    return VulnListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{cve_id}",
    response_model=VulnDetailResponse,
    summary="漏洞详情（事实层 + 富化层）",
)
async def get_vulnerability(
    cve_id: str,
    repo: VulnRepository = Depends(get_vuln_repo),
) -> VulnDetailResponse:
    """返回单条漏洞的事实层与富化层实体。

    Args:
        cve_id: 漏洞主键（大小写不敏感，如 ``cve-2024-3400``）。
        repo: 漏洞仓储（请求级会话）。

    Returns:
        :class:`VulnDetailResponse`（``enriched`` 未富化时为 ``None``）。

    Raises:
        HTTPException: 404 —— 库中不存在该漏洞。
    """
    unified = await repo.get_by_cve(cve_id)
    if unified is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"未找到漏洞 {cve_id}")
    enriched = await repo.get_enriched(unified.vuln_id)
    return VulnDetailResponse(unified=unified, enriched=enriched)
