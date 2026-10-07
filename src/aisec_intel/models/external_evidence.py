"""外部证据契约（Day25 阶段 2；PROJECT_PLAN.md §5.8 受控外部检索）。

问答层在「本地检索证据不足」时，允许向**权威源白名单**（NVD / GHSA / OSV / CISA KEV）
补齐事实；本模块定义该通道的唯一出参 :class:`ExternalEvidence`。

设计约束（§0 / §10）：

1. **只接权威源**：``source_type`` 为 :data:`ExternalSourceType` 白名单，普通网页搜索
   （Google / Bing / 任意 URL 抓取）**不在通道内**；
2. **外部证据不直接写正式表**：只落 ``external_evidence``（隔离表），
   正式字段（``unified_vuln`` / ``enriched_vuln``）只能由 L1/L2/L3 链路写入；
3. **内容一律不可信**：``untrusted`` 恒为 ``True``，正文必须过
   :mod:`aisec_intel.security.external_sanitizer`（去 HTML / 截断 / 注入检测）；
4. **可回溯**：``url`` + ``content_hash`` 保证每条外部事实都能回到原始来源。
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from aisec_intel.models.base import IntelBaseModel, OptionalUTCDateTime, UTCDateTime

ExternalSourceType = Literal["nvd", "ghsa", "osv", "kev"]
"""受控外部源白名单（按可信度优先级排列：NVD > GHSA > OSV > KEV）。"""

EXTERNAL_SOURCE_ORDER: tuple[str, ...] = ("nvd", "ghsa", "osv", "kev")
"""源优先级（检索顺序与冲突裁决的兜底顺序）。"""

EXTERNAL_SOURCE_TRUST: dict[str, float] = {
    "nvd": 1.0,
    "ghsa": 0.9,
    "osv": 0.85,
    "kev": 0.8,
}
"""源基础可信度（与 L3 ``enrich/agents/verifier.py`` 的 ``SOURCE_TRUST`` 同口径）。"""

EXTERNAL_SOURCE_LABELS: dict[str, str] = {
    "nvd": "NVD（美国国家漏洞库）",
    "ghsa": "GitHub Security Advisory",
    "osv": "OSV.dev",
    "kev": "CISA KEV（已知被利用漏洞）",
}
"""源中文标签（前端 / CLI 展示用）。"""

ExternalFact = Literal[
    "fixed_version",
    "vendor_advisory",
    "affected_components",
    "affected_versions",
    "attack_techniques",
    "kev",
    "epss",
]
"""外部证据可支撑的事实标签（与 :mod:`aisec_intel.qa.evidence_gap` 的缺口口径一致）。"""


class ExternalEvidence(IntelBaseModel):
    """一条外部权威证据（**不可信内容**，只用于补齐本地缺口）。

    Attributes:
        query: 触发本次检索的用户问题（原文，便于审计「为什么去查外部」）。
        cve_id: 关联 CVE 编号（``None`` 表示与具体编号无关，如 KEV 目录条目）。
        source_type: 来源类型（白名单：``nvd`` / ``ghsa`` / ``osv`` / ``kev``）。
        source_name: 来源内标识（如 GHSA ID / OSV ID / NVD CVE ID）。
        url: 原始链接（引用回溯用，禁止编造）。
        title: 标题（公告摘要 / 漏洞名）。
        snippet: **已清洗**的正文片段（≤ :data:`MAX_EXTERNAL_SNIPPET_CHARS` 字符；不可信）。
        retrieved_at: 本次抓取时间（UTC）。
        published_at: 源侧发布时间（UTC，可能为空）。
        trust_score: 可信度评分（``[0,1]``，由 ``ExternalEvidenceVerifier`` 复核）。
        verified: 是否通过复核（**只有 ``True`` 才能提升为答案事实**）。
        content_hash: 内容指纹（``sha256(snippet)``，幂等键）。
        facts: 本条证据支撑的事实标签（由纯函数从 ``snippet`` 提取）。
        untrusted: 恒为 ``True``（外部内容永不进入正式表 / 永不获得系统指令地位）。
    """

    query: str = Field(default="", description="触发检索的问题原文")
    cve_id: str | None = Field(default=None, description="关联 CVE 编号")
    source_type: ExternalSourceType = Field(description="来源类型（权威源白名单）")
    source_name: str = Field(default="", description="来源内标识（GHSA / OSV / CVE ID）")
    url: str = Field(default="", description="原始链接")
    title: str = Field(default="", description="标题")
    snippet: str = Field(default="", description="已清洗正文片段")
    retrieved_at: UTCDateTime = Field(description="抓取时间（UTC）")
    published_at: OptionalUTCDateTime = Field(default=None, description="源侧发布时间（UTC）")
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0, description="可信度评分")
    verified: bool = Field(default=False, description="是否通过复核（可提升为答案事实）")
    content_hash: str = Field(default="", description="内容指纹（幂等键）")
    facts: list[ExternalFact] = Field(default_factory=list, description="支撑的事实标签")
    untrusted: bool = Field(default=True, description="外部内容标记（恒为 True）")

    @property
    def locator(self) -> str:
        """引用定位符（形如 ``external:ghsa:GHSA-56xg-wfcc-g829``）。

        Returns:
            可直接写入 ``Citation.locator`` 的稳定标识。
        """
        return f"external:{self.source_type}:{self.source_name or self.cve_id or 'unknown'}"

    @property
    def label(self) -> str:
        """来源中文标签（展示用）。

        Returns:
            形如 ``GitHub Security Advisory``；未登记来源回退为 ``source_type``。
        """
        return EXTERNAL_SOURCE_LABELS.get(self.source_type, self.source_type)


MAX_EXTERNAL_SNIPPET_CHARS: int = 2000
"""单条外部证据正文长度上限（与 :mod:`aisec_intel.security.external_sanitizer` 一致）。"""

FACT_LABELS: dict[str, str] = {
    "fixed_version": "修复版本",
    "vendor_advisory": "厂商公告/补丁",
    "affected_components": "受影响组件",
    "affected_versions": "受影响版本",
    "attack_techniques": "攻击技术",
    "kev": "在野利用（KEV）",
    "epss": "EPSS 利用概率",
}
"""事实标签 → 中文名（缺口报告 / 复核汇总 / CLI 展示共用，契约层唯一定义）。"""


class ExternalVerification(IntelBaseModel):
    """一次外部证据复核的汇总（写入 ``QAState.external_verification``）。

    Attributes:
        accepted: 通过复核（可提升）的条数。
        rejected: 被丢弃的条数。
        verified_facts: 通过复核的事实标签（可提升为答案事实）。
        authoritative: 「事实 → 权威证据定位符」（多源冲突裁决结果）。
        conflicts: 冲突说明（同一事实多源内容不一致）。
        sources: 参与复核的源（按优先级）。
        trust_scores: 定位符 → 复核后可信度。
        reasons: 丢弃原因（可观测）。
    """

    accepted: int = Field(default=0, ge=0, description="通过复核条数")
    rejected: int = Field(default=0, ge=0, description="被丢弃条数")
    verified_facts: list[str] = Field(default_factory=list, description="可提升的事实标签")
    authoritative: dict[str, str] = Field(default_factory=dict, description="事实 → 权威证据定位符")
    conflicts: list[str] = Field(default_factory=list, description="多源冲突说明")
    sources: list[str] = Field(default_factory=list, description="参与复核的源")
    trust_scores: dict[str, float] = Field(default_factory=dict, description="定位符 → 可信度")
    reasons: list[str] = Field(default_factory=list, description="丢弃原因")

    @property
    def verified_labels(self) -> list[str]:
        """可提升事实的中文标签（展示用）。

        Returns:
            形如 ``["修复版本"]``。
        """
        return [FACT_LABELS.get(item, item) for item in self.verified_facts]
