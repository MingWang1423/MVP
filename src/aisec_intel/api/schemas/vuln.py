"""漏洞查询 API 的数据传输契约（Day12 任务 5；PROJECT_PLAN.md §5.8）。

设计原则：**不复制冻结模型**——

- 事实层直接复用 ``UnifiedVuln``（冻结契约）；
- 富化层直接复用 ``EnrichedVuln``（冻结契约，含 7 维富化字段）；
- 本模块只定义「列表条目」与「分页包装」两个展示型 DTO，
  它们**不是跨层契约**，可随前端需求调整（与 ``AskRequest`` 同类）。
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from aisec_intel.models.base import IntelBaseModel
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import Severity, UnifiedVuln

VulnSummaryLevel = Literal["low", "medium", "high", "critical"]


class VulnSummary(IntelBaseModel):
    """漏洞列表条目（前端「情报看板」表格一行）。

    Attributes:
        vuln_id: 漏洞主键（如 ``CVE-2024-3400``）。
        title: 标题（可为空）。
        severity: CVSS 严重度（事实层，可为空）。
        risk_score: 富化风险分（未富化时为 ``None``）。
        risk_level: 富化风险级别（未富化时为 ``None``）。
        kev: 是否进入 CISA KEV。
        epss_score: FIRST EPSS 概率。
        sources: 贡献源列表。
        published_at: 发布时间（UTC）。
        enriched: 是否已完成富化（前端据此决定是否跳详情页的七维视图）。
    """

    model_config = ConfigDict(extra="forbid")

    vuln_id: str = Field(description="漏洞主键")
    title: str | None = Field(default=None, description="标题")
    severity: Severity | None = Field(default=None, description="CVSS 严重度")
    risk_score: float | None = Field(default=None, description="富化风险分（0-100）")
    risk_level: VulnSummaryLevel | None = Field(default=None, description="富化风险级别")
    kev: bool = Field(default=False, description="是否进入 CISA KEV")
    epss_score: float | None = Field(default=None, description="EPSS 概率（0-1）")
    sources: list[str] = Field(default_factory=list, description="贡献源")
    published_at: datetime | None = Field(default=None, description="发布时间（UTC）")
    enriched: bool = Field(default=False, description="是否已富化")

    @classmethod
    def from_unified(
        cls,
        vuln: UnifiedVuln,
        risk: tuple[float, str] | None = None,
    ) -> VulnSummary:
        """由事实层实体（+ 可选富化风险分组）构造列表条目（纯函数）。

        Note:
            ``GET /vulnerabilities`` 与 ``GET /stats`` 的表格共用本方法，
            保证两处的「列表条目」口径完全一致。

        Args:
            vuln: ``UnifiedVuln`` 实体。
            risk: ``(risk_score, risk_level)``；未富化时为 ``None``。

        Returns:
            :class:`VulnSummary`。
        """
        return cls(
            vuln_id=vuln.vuln_id,
            title=vuln.title,
            severity=vuln.severity,
            risk_score=risk[0] if risk else None,
            risk_level=risk[1] if risk else None,  # type: ignore[arg-type]
            kev=vuln.kev,
            epss_score=vuln.epss_score,
            sources=list(vuln.sources),
            published_at=vuln.published_at or vuln.normalized_at,
            enriched=risk is not None,
        )



class VulnListResponse(IntelBaseModel):
    """``GET /vulnerabilities`` 的响应体（分页包装）。

    Attributes:
        items: 当前页条目。
        total: 命中总条数（分页前的总数）。
        limit: 单页条数。
        offset: 分页偏移。
    """

    model_config = ConfigDict(extra="forbid")

    items: list[VulnSummary] = Field(default_factory=list, description="当前页条目")
    total: int = Field(default=0, ge=0, description="命中总条数")
    limit: int = Field(ge=1, description="单页条数")
    offset: int = Field(default=0, ge=0, description="分页偏移")


class VulnDetailResponse(IntelBaseModel):
    """``GET /vulnerabilities/{cve_id}`` 的响应体（事实 + 富化，双契约并列）。

    Attributes:
        unified: 事实层实体（冻结契约 ``UnifiedVuln``）。
        enriched: 富化层实体（冻结契约 ``EnrichedVuln``）；未富化时为 ``None``。
    """

    model_config = ConfigDict(extra="forbid")

    unified: UnifiedVuln = Field(description="事实层实体（UnifiedVuln）")
    enriched: EnrichedVuln | None = Field(default=None, description="富化层实体（EnrichedVuln）")
