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

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import get_args

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

ALLOWED_SEVERITIES: tuple[str, ...] = tuple(get_args(Severity))
"""合法严重度取值（直接取自冻结契约 ``Severity``，避免与模型漂移）。"""


def normalize_severity_params(values: Sequence[str]) -> list[str]:
    """把查询参数中的严重度归一化为大写并校验（纯函数）。

    Args:
        values: 原始查询值（可能大小写混杂、可能为空）。

    Returns:
        去重后的大写严重度列表。

    Raises:
        HTTPException: 出现不在 :data:`ALLOWED_SEVERITIES` 内的取值（422）。
    """
    normalized: list[str] = []
    invalid: list[str] = []
    for raw in values:
        item = str(raw).strip().upper()
        if not item:
            continue
        if item not in ALLOWED_SEVERITIES:
            invalid.append(str(raw))
        elif item not in normalized:
            normalized.append(item)
    if invalid:
        raise HTTPException(
            # 用字面量 422：starlette 新版本把 HTTP_422_UNPROCESSABLE_ENTITY 标记为弃用，
            # 字面量在旧/新版本上都不会触发弃用告警。
            status_code=422,
            detail=f"非法严重度 {invalid}；可选值：{', '.join(ALLOWED_SEVERITIES)}",
        )
    return normalized



def _to_summary(
    vuln: UnifiedVuln,
    risk: tuple[float, str] | None,
    poc_count: int = 0,
) -> VulnSummary:
    """把事实层实体 + 可选风险分组 + PoC 数装为列表条目（纯函数）。

    Args:
        vuln: ``UnifiedVuln`` 实体。
        risk: ``(risk_score, risk_level)``；未富化时为 ``None``。
        poc_count: PoC / EXP 条数（未富化时为 0）。

    Returns:
        :class:`VulnSummary`。

    Note:
        实际装配逻辑在 :meth:`~aisec_intel.api.schemas.vuln.VulnSummary.from_unified`，
        与 ``GET /stats`` 的表格共用同一口径。
    """
    return VulnSummary.from_unified(vuln, risk, poc_count)


@router.get(
    "",
    response_model=VulnListResponse,
    summary="漏洞列表（严重度 / 来源 / 时间 / KEV / PoC / 关键词筛选）",
)
async def list_vulnerabilities(
    severity: list[str] = Query(
        default_factory=list,
        description="严重度过滤，可重复传参（多选取并集）；取值 CRITICAL/HIGH/MEDIUM/LOW，大小写不敏感",
    ),
    source: list[str] = Query(
        default_factory=list, description="数据源过滤，可重复传参（多选取并集，如 nvd/kev/osv）"
    ),
    days: int | None = Query(default=None, ge=1, le=3650, description="仅返回最近 N 天（时间轴）"),
    since: datetime | None = Query(default=None, description="起始时间（ISO8601，含；优先于 days）"),
    until: datetime | None = Query(default=None, description="结束时间（ISO8601，含）"),
    kev: bool | None = Query(default=None, description="true=仅 KEV；false=仅非 KEV；缺省不过滤"),
    kev_only: bool = Query(default=False, description="兼容旧前端的布尔开关，等价于 kev=true"),
    has_poc: bool | None = Query(default=None, description="true=仅有 PoC；false=仅无 PoC"),
    q: str | None = Query(default=None, max_length=200, description="关键词：CVE 编号 / 标题 / 描述"),
    limit: int = Query(default=20, ge=1, le=MAX_PAGE_SIZE, description="单页条数"),
    offset: int = Query(default=0, ge=0, description="分页偏移"),
    repo: VulnRepository = Depends(get_vuln_repo),
    settings: Settings = Depends(get_settings_dep),
) -> VulnListResponse:
    """返回漏洞列表（按时间轴倒序，附带富化风险分与 PoC 数）。

    Args:
        severity: 严重度过滤（多选）。
        source: 数据源过滤（多选）。
        days: 时间窗（天）；仅在未显式传 ``since`` 时生效。
        since: 起始时间（UTC，含）。
        until: 结束时间（UTC，含）。
        kev: KEV 过滤（三态）。
        kev_only: 兼容开关，等价于 ``kev=true``。
        has_poc: PoC 存在性过滤（三态）。
        q: 关键词（CVE 编号 / 标题 / 描述）。
        limit: 单页条数。
        offset: 分页偏移。
        repo: 漏洞仓储（请求级会话）。
        settings: 全局配置（日志用）。

    Returns:
        :class:`VulnListResponse`。
    """
    since_effective = since
    if since_effective is None and days:
        since_effective = utc_now() - timedelta(days=days)
    severities = normalize_severity_params(severity)
    rows, total = await repo.list_filtered(
        severity=severities,
        source=source,
        since=since_effective,
        until=until,
        kev_only=kev_only,
        kev=kev,
        has_poc=has_poc,
        q=q,
        limit=limit,
        offset=offset,
    )
    risks = await repo.risk_levels([row.vuln_id for row in rows])
    pocs = await repo.poc_counts([row.vuln_id for row in rows])
    items = [_to_summary(row, risks.get(row.vuln_id), pocs.get(row.vuln_id, 0)) for row in rows]
    logger.info(
        f"漏洞列表：env={settings.app_env} 命中={total} 返回={len(items)} "
        f"severity={severities} source={source} days={days} kev={kev or kev_only} "
        f"has_poc={has_poc} q={q!r}"
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
