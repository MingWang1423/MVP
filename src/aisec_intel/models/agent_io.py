"""Agent 输入输出契约（PROJECT_PLAN.md §5.2 / §3.2）。

本模块定义 L3 富化层与 L4 问答层**跨 Agent 传递**的结构化契约：

- 富化：``EnrichmentInput`` → ``EnrichmentOutput``
- 问答：``QAQuery`` → ``QAResponse``

设计约束（§3.2 四道闸门）：

1. 所有 Agent 的 LLM 调用必须返回本模块声明的 Pydantic 模型（``with_structured_output``）；
2. 禁止自由文本直出到库 —— 未在契约中声明的字段会被 ``extra="forbid"`` 直接拒绝；
3. ``trace_id`` 必须透传（§10.2 不变式 5）；
4. 答案必须可回溯：非降级模式下 ``QAResponse.answer`` 非空即要求至少一条 ``Citation``。
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from aisec_intel.models.base import SCHEMA_VERSION, IntelBaseModel
from aisec_intel.models.enriched_vuln import AgentStep, EnrichedVuln
from aisec_intel.models.paper import PaperRelation
from aisec_intel.models.unified_vuln import CVSSVector, UnifiedVuln

CitationSource = Literal["pg", "neo4j", "chroma", "raw", "external"]
"""引用来源类型：PostgreSQL 表 / Neo4j 节点 / Chroma 文档切片 / ``data/raw`` 原文快照 /
受控外部证据（Day25：NVD / GHSA / OSV / CISA KEV，**不可信内容**，引用会显式标注来源）。"""

RiskLevel = Literal["low", "medium", "high", "critical"]
"""风险级别（与 ``EnrichedVuln.risk_level`` 同构）。"""


class PaperRelevance(IntelBaseModel):
    """单篇候选论文与漏洞的相关性判定（富化 Agent② 的结构化输出，§3.2 闸门 ①）。

    Attributes:
        paper_id: 论文主键（arXiv ID / OpenAlex Work ID）。
        relevant: 是否与漏洞相关（``False`` 时该候选被丢弃，避免写脏数据）。
        relation: 关联类型（提及 / 提出攻击 / 提出防御 / 评测 / 综述）。
        confidence: 判定置信度，区间 ``[0.0, 1.0]``。
        evidence: 支撑该判定的原文片段（引用回溯用）。
    """

    model_config = ConfigDict(extra="forbid")

    paper_id: str = Field(min_length=1, description="论文主键")
    relevant: bool = Field(description="是否相关")
    relation: PaperRelation = Field(default="mentions", description="关联类型")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="判定置信度")
    evidence: str | None = Field(default=None, description="支撑判定的原文片段")


class PaperRelevanceBatch(IntelBaseModel):
    """一批候选论文的相关性判定结果（PaperLinker 单次 LLM 调用的输出）。

    Attributes:
        items: 逐篇判定结果。
    """

    model_config = ConfigDict(extra="forbid")

    items: list[PaperRelevance] = Field(default_factory=list, description="逐篇判定结果")


class RiskScore(IntelBaseModel):
    """风险评分（富化维度④，**确定性公式**，不调用 LLM，§3.2 闸门 ③）。

    Attributes:
        score: 风险分，区间 ``[0.0, 100.0]``。
        level: 风险级别。
        breakdown: 各因子权重贡献（``cvss`` / ``epss`` / ``kev`` / ``poc``）。
    """

    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=100.0, description="风险分")
    level: RiskLevel = Field(description="风险级别")
    breakdown: dict[str, float] = Field(default_factory=dict, description="各因子贡献")


class CVSSInference(IntelBaseModel):
    """LLM 对缺失 CVSS 的推断结果（富化维度⑥，P5 收尾）。

    **只接受向量串**：基础分与严重度一律由 :func:`aisec_intel.normalize.cvss.parse_cvss_vector`
    复算得出（禁止 LLM 直接给分，避免臆造数值）。

    Attributes:
        vector: CVSS v3.1 向量串，如 ``CVSS:3.1/AV:N/AC:L/...``。
        confidence: 推断置信度，区间 ``[0.0, 1.0]``。
        rationale: 推断依据（引用描述中的关键句）。
    """

    model_config = ConfigDict(extra="forbid")

    vector: str = Field(min_length=8, description="CVSS v3.1 向量串")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="推断置信度")
    rationale: str | None = Field(default=None, description="推断依据")


class Remediation(IntelBaseModel):
    """修复建议（富化维度⑦，P5 收尾）。

    Attributes:
        summary: 一句话修复结论。
        fixed_versions: 已修复版本（如 ``["0.1.34"]``）。
        mitigations: 无法升级时的缓解措施。
        patch_urls: 补丁链接（**必须来自 ``UnifiedVuln.references``**，禁止 LLM 生成 URL）。
        confidence: 置信度，区间 ``[0.0, 1.0]``。
        evidence_refs: 证据标识（``trace_id`` / URL）。
    """

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, description="一句话修复结论")
    fixed_versions: list[str] = Field(default_factory=list, description="已修复版本")
    mitigations: list[str] = Field(default_factory=list, description="缓解措施")
    patch_urls: list[str] = Field(default_factory=list, description="补丁链接（须来自 references）")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)


class AttackChainStepDraft(IntelBaseModel):
    """攻击链单步的 **LLM 面向**草稿（宽松字段，便于模型填写）。

    与冻结模型 :class:`~aisec_intel.models.enriched_vuln.AttackChainStep` 的差异：
    ``preconditions`` 允许字符串（模型常给一句话），``tactic`` 允许显示名
    （``"Initial Access"``）。经 :func:`~aisec_intel.enrich.agents.attack_mapper.to_attack_chain`
    **确定性归一化**后才写入冻结模型。

    Attributes:
        order: 步骤序号（可为任意整数，归一化时重排）。
        technique_id: ATT&CK 技术 ID。
        tactic: 战术名（显示名或连字符名）。
        stage: Kill Chain 阶段。
        description: 该步说明。
        preconditions: 前置条件（字符串或字符串列表）。
    """

    model_config = ConfigDict(extra="forbid")

    order: int = 1
    technique_id: str = Field(min_length=2)
    tactic: str = Field(min_length=2)
    stage: str = Field(default="Exploitation")
    description: str = Field(min_length=1)
    preconditions: str | list[str] = Field(default_factory=list)


class AttackChainDraft(IntelBaseModel):
    """攻击链草稿（LLM 面向，宽松）。

    Attributes:
        steps: 步骤草稿。
        entry_vector: 入口向量描述。
        privileges_required: 所需权限（自由文本，归一化时映射为字面量）。
    """

    model_config = ConfigDict(extra="forbid")

    steps: list[AttackChainStepDraft] = Field(default_factory=list)
    entry_vector: str | None = None
    privileges_required: str = Field(default="unknown")


class VerificationReport(IntelBaseModel):
    """Verifier 的交叉验证报告（确定性检查，不调用 LLM）。

    Attributes:
        confidence: 综合置信度，区间 ``[0.0, 1.0]``。
        conflicts: 冲突标记（如 CVSS 复算不一致、引用不可达）。
        checked_urls: 参与可达性检查的 URL 数。
        reachable_urls: 其中可达的 URL 数。
        source_trust: 来源可信度加权分，区间 ``[0.0, 1.0]``。
        notes: 补充说明（如「跳过了无向量的 CVSS 复算」）。
    """

    model_config = ConfigDict(extra="forbid")

    confidence: float = Field(ge=0.0, le=1.0, description="综合置信度")
    conflicts: list[str] = Field(default_factory=list, description="冲突标记")
    checked_urls: int = Field(default=0, ge=0, description="参与检查的 URL 数")
    reachable_urls: int = Field(default=0, ge=0, description="可达 URL 数")
    source_trust: float = Field(default=0.0, ge=0.0, le=1.0, description="来源可信度加权分")
    notes: list[str] = Field(default_factory=list, description="补充说明")


class Citation(IntelBaseModel):
    """答案中的一条可回溯引用（验收指标「引用可回溯率 100%」的最小单元）。

    Attributes:
        source_type: 引用来源类型。
        locator: 存储位置标识（表名+主键 / 节点 ID / 文档 ID+切片号 / 快照路径）。
        cve_id: 相关漏洞主键（可选）。
        trace_id: 关联的采集追踪 ID（可选，用于回溯 ``data/raw`` 原文）。
        url: 原始外部链接（可选）。
        quote: 支撑该断言的原文字段（可选，但强烈建议填写）。
    """

    model_config = ConfigDict(extra="forbid")

    source_type: CitationSource = Field(description="引用来源类型")
    locator: str = Field(min_length=1, description="存储位置：表名+主键 / 节点 ID / 文档切片 / 快照路径")
    cve_id: str | None = Field(default=None, description="相关漏洞主键，如 CVE-2024-3400")
    trace_id: str | None = Field(default=None, description="关联的 RawItem.trace_id")
    url: str | None = Field(default=None, description="原始外部链接")
    quote: str | None = Field(default=None, description="支撑断言的原文片段")


class ReasoningStep(IntelBaseModel):
    """推理链中的一步（多跳推理的可解释性单元）。

    Attributes:
        hop: 第几跳，从 1 开始。
        question: 本跳要回答的子问题。
        evidence: 本跳使用的证据引用。
        conclusion: 本跳结论。
    """

    model_config = ConfigDict(extra="forbid")

    hop: int = Field(ge=1, description="第几跳（从 1 开始）")
    question: str = Field(min_length=1, description="本跳的子问题")
    evidence: list[Citation] = Field(default_factory=list, description="本跳使用的证据")
    conclusion: str = Field(description="本跳结论")


class ReasoningStepDraft(IntelBaseModel):
    """**LLM 面向**的推理步草稿（Day11 Reasoner，宽松字段）。

    与 :class:`ReasoningStep` 的差异：证据只允许引用**候选文档主键**
    （``evidence_doc_ids``），由 :func:`aisec_intel.qa.agents.reasoner.normalize_steps`
    映射为 :class:`Citation` —— 从根本上杜绝 LLM 编造 URL / 表名。

    Attributes:
        hop: 第几跳（LLM 可填任意正整数，归一化时重排）。
        question: 本跳子问题。
        conclusion: 本跳结论。
        evidence_doc_ids: 本跳依据的候选文档标识（必须来自检索结果）。
    """

    model_config = ConfigDict(extra="forbid")

    hop: int = Field(default=1, ge=1, description="第几跳")
    question: str = Field(min_length=1, description="本跳子问题")
    conclusion: str = Field(min_length=1, description="本跳结论")
    evidence_doc_ids: list[str] = Field(default_factory=list, description="依据的候选文档标识")


class ReasoningDraft(IntelBaseModel):
    """Reasoner 的完整结构化输出（≤ ``max_hops`` 步）。

    Attributes:
        steps: 推理步草稿。
    """

    model_config = ConfigDict(extra="forbid")

    steps: list[ReasoningStepDraft] = Field(default_factory=list, description="推理步草稿")


class AnswerClaimDraft(IntelBaseModel):
    """**LLM 面向**的论断草稿（Day11 Synthesizer，强制引用）。

    Attributes:
        claim: 一句结论性论断（面向用户）。
        evidence_doc_ids: 支撑该论断的候选文档标识（必须来自检索结果）。
    """

    model_config = ConfigDict(extra="forbid")

    claim: str = Field(min_length=1, description="结论性论断")
    evidence_doc_ids: list[str] = Field(default_factory=list, description="支撑该论断的候选文档标识")


class AnswerDraft(IntelBaseModel):
    """Synthesizer 的结构化输出（论断列表 + 总结 + 置信度）。

    Attributes:
        summary: 一句话总体结论（标题句）。
        claims: 逐条论断（每条须带证据标识，否则合成阶段被丢弃）。
        confidence: 答案置信度，区间 ``[0.0, 1.0]``。
    """

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, description="一句话总体结论")
    claims: list[AnswerClaimDraft] = Field(default_factory=list, description="逐条论断")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="答案置信度")


class EnrichmentInput(IntelBaseModel):
    """L3 富化层的单条输入（由 L2 归一化结果构造，不含任何推断结论）。

    Attributes:
        schema_version: 契约版本号。
        cve_id: 漏洞主键（必须与 ``unified_vuln.vuln_id`` 一致）。
        unified_vuln: L2 归一化输出实体。
        trace_id: 本次富化任务的全链路追踪 ID（若 ``unified_vuln.trace_ids`` 非空则必须命中）。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION, description="契约版本号，变更必须 bump")
    cve_id: str = Field(min_length=1, description="漏洞主键，如 CVE-2024-3400")
    unified_vuln: UnifiedVuln = Field(description="L2 归一化输出实体")
    trace_id: str = Field(min_length=1, description="全链路追踪 ID")

    @model_validator(mode="after")
    def _check_consistency(self) -> EnrichmentInput:
        """校验 ``cve_id`` 与 ``trace_id`` 的一致性（§10.2 不变式 5）。

        Returns:
            校验通过的自身实例。

        Raises:
            ValueError: ``cve_id`` 与 ``unified_vuln.vuln_id`` 不一致；
                或 ``trace_id`` 不在非空的 ``unified_vuln.trace_ids`` 中（链路断裂）。
        """
        if self.cve_id.strip().upper() != self.unified_vuln.vuln_id.strip().upper():
            raise ValueError(
                f"cve_id({self.cve_id}) 与 unified_vuln.vuln_id({self.unified_vuln.vuln_id}) 不一致"
            )
        if self.unified_vuln.trace_ids and self.trace_id not in self.unified_vuln.trace_ids:
            raise ValueError(
                f"trace_id({self.trace_id}) 未出现在 unified_vuln.trace_ids 中，链路已断（§10.2 不变式 5）"
            )
        return self


class EnrichmentOutput(IntelBaseModel):
    """L3 富化层的聚合输出（一条 CVE 的完整富化结果 + 执行轨迹）。

    Attributes:
        schema_version: 契约版本号。
        enriched_vuln: 富化后的漏洞实体（五维度结论）。
        agent_steps: 7 个 Agent 的执行轨迹（与 ``enriched_vuln.agent_trace`` 同源）。
        confidence: 输出级整体置信度（Reviewer 裁决后的汇总值）。
        errors: 非致命错误列表（如某 Agent 降级执行、外部检索超时）。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION, description="契约版本号，变更必须 bump")
    enriched_vuln: EnrichedVuln = Field(description="五维度富化结果")
    agent_steps: list[AgentStep] = Field(default_factory=list, description="Agent 执行轨迹")
    confidence: float = Field(ge=0.0, le=1.0, description="输出级整体置信度")
    errors: list[str] = Field(default_factory=list, description="非致命错误（降级 / 超时等）")
    remediation: Remediation | None = Field(
        default=None, description="修复建议（维度⑦；与事实层分离，不写回 UnifiedVuln）"
    )
    cvss_inferred: list[CVSSVector] = Field(
        default_factory=list, description="推断出的 CVSS 向量（维度⑥；仅当事实层缺失时才非空）"
    )


class QAQuery(IntelBaseModel):
    """L4 问答层的一次用户查询。

    Attributes:
        schema_version: 契约版本号。
        query: 自然语言问题。
        session_id: 多轮会话 ID；单轮问答为 ``None``。
        trace_id: 本次问答的全链路追踪 ID。
        top_k: 单路检索返回条数上限。
        max_hops: 多跳推理上限（验收要求 ≥2 跳）。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION, description="契约版本号，变更必须 bump")
    query: str = Field(min_length=1, description="自然语言问题")
    session_id: str | None = Field(default=None, description="多轮会话 ID；单轮为 None")
    trace_id: str = Field(min_length=1, description="全链路追踪 ID")
    top_k: int = Field(default=8, ge=1, le=50, description="单路检索条数上限")
    max_hops: int = Field(default=2, ge=1, le=4, description="多跳推理上限（≥2）")


class QAResponse(IntelBaseModel):
    """L4 问答层的结构化回答（含推理链与强制引用）。

    Attributes:
        schema_version: 契约版本号。
        answer: 自然语言答案。
        citations: 引用列表；**非降级模式下 ``answer`` 非空即不得为空**。
        reasoning_chain: 多跳推理链（单跳问题可为空）。
        confidence: 答案置信度。
        degraded: 是否来自降级链路（离线兜底 / 模板化作答），降级时允许无引用。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION, description="契约版本号，变更必须 bump")
    answer: str = Field(description="自然语言答案")
    citations: list[Citation] = Field(default_factory=list, description="引用（可回溯）")
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list, description="多跳推理链")
    confidence: float = Field(ge=0.0, le=1.0, description="答案置信度")
    degraded: bool = Field(default=False, description="是否来自降级链路（§3.3 离线兜底）")

    @model_validator(mode="after")
    def _require_citations(self) -> QAResponse:
        """强制引用：非降级且答案非空时，必须至少给出 1 条可回溯引用。

        Returns:
            校验通过的自身实例。

        Raises:
            ValueError: 答案非空但没有任何引用（违反「引用可回溯率 100%」验收要求）。
        """
        if not self.degraded and self.answer.strip() and not self.citations:
            raise ValueError("非降级模式下答案非空必须至少给出 1 条 Citation（引用可回溯率 100%）")
        return self
