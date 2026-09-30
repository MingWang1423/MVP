"""论文元数据与「论文-漏洞」关联模型（PROJECT_PLAN.md §2 / §5.2）。

说明：``EnrichedVuln.related_papers`` 依赖 ``PaperVulnLink``（§10.1 ③），因此本模块在 Day1
即以最小可用形态落地，P1（Day2）再按富化 Agent② 的需要扩展字段（只增不改，走 §10.3 流程）。
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from aisec_intel.models.base import IntelBaseModel, OptionalUTCDateTime

PaperSource = Literal["arxiv", "openalex", "doi", "other"]
"""论文来源标识。"""

PaperRelation = Literal["mentions", "proposes-attack", "proposes-defense", "evaluates", "surveys"]
"""论文与漏洞的关联类型（由富化 Agent② 判定）。"""


class Paper(IntelBaseModel):
    """学术论文元数据（只存元数据与摘要，不存全文 PDF —— 许可证合规 R10）。

    Attributes:
        paper_id: 论文主键（arXiv ID / DOI），如 ``2403.01234``。
        source: 来源（``arxiv`` / ``openalex`` / ``doi``）。
        title: 论文标题。
        abstract: 摘要（用于向量化与语义匹配）。
        authors: 作者列表。
        venue: 发表期刊 / 会议。
        url: 论文链接。
        published_at: 发布时间（UTC）。
        trace_ids: 对应 ``RawItem.trace_id`` 列表。
    """

    model_config = ConfigDict(extra="forbid")

    paper_id: str = Field(min_length=1, description="arXiv ID 或 DOI")
    source: PaperSource = Field(default="arxiv", description="来源标识")
    title: str = Field(description="论文标题")
    abstract: str | None = Field(default=None, description="摘要（向量化输入）")
    authors: list[str] = Field(default_factory=list, description="作者列表")
    venue: str | None = Field(default=None, description="发表期刊/会议")
    url: str | None = Field(default=None, description="论文链接")
    published_at: OptionalUTCDateTime = Field(default=None, description="发布时间（UTC）")
    trace_ids: list[str] = Field(default_factory=list, description="关联的 RawItem.trace_id 列表")


class PaperVulnLink(IntelBaseModel):
    """「论文 ↔ 漏洞」关联边（富化维度②）。

    Attributes:
        paper_id: 论文主键。
        vuln_id: 漏洞主键（形如 ``CVE-2024-3400``）。
        relation: 关联类型（提及 / 提出攻击 / 提出防御 / 评测 / 综述）。
        confidence: 关联置信度，区间 ``[0.0, 1.0]``。
        evidence: 支撑该关联的原文片段（引用回溯用）。
        evidence_refs: 证据来源标识（``trace_id`` 或 URL）。
    """

    model_config = ConfigDict(extra="forbid")

    paper_id: str = Field(min_length=1, description="论文主键")
    vuln_id: str = Field(min_length=1, description="漏洞主键，如 CVE-2024-3400")
    relation: PaperRelation = Field(default="mentions", description="关联类型")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="关联置信度")
    evidence: str | None = Field(default=None, description="支撑关联的原文片段")
    evidence_refs: list[str] = Field(default_factory=list, description="trace_id 或 URL")
