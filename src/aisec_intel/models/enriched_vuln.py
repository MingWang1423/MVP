"""富化层输出契约（PROJECT_PLAN.md §10.1 ③，Day1 冻结）。

``EnrichedVuln`` 在 ``UnifiedVuln`` 之上**只追加**推断性结论与复核状态（§10.2 不变式 4），
父类的原始事实字段不得覆写。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict, Field, model_validator

from aisec_intel.models.base import IntelBaseModel, UTCDateTime
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import UnifiedVuln

ENRICHED_VULN_SCHEMA_VERSION: str = "1.3"
"""``EnrichedVuln`` 契约版本（v1.2：新增富化维度⑦ ``remediation_json``，§10.3 流程）。

Note:
    仅 ``EnrichedVuln`` 递增（v1.1 → v1.2），父契约 ``UnifiedVuln`` 仍为 ``1.1``：
    本次新增字段是 L3 富化结论，**不触碰事实层**（§10.2 不变式 4）。
"""


def _version_tuple(value: str) -> tuple[int, ...]:
    """把版本号字符串解析为可比较的元组（纯函数）。

    Args:
        value: 形如 ``"1.2"`` 的版本号（非法输入按 ``(0,)`` 处理）。

    Returns:
        逐段整型元组，如 ``(1, 2)``。
    """
    try:
        return tuple(int(part) for part in str(value).split(".") if part != "")
    except ValueError:
        return (0,)


class AgentStep(IntelBaseModel):
    """单个 Agent 节点的执行轨迹（可观测性与审计依据）。

    Attributes:
        agent: 节点名，如 ``extractor`` / ``reviewer``。
        round: 回流轮次，``0`` 表示首轮。
        confidence: 该步输出的置信度，区间 ``[0.0, 1.0]``。
        latency_ms: 耗时（毫秒）。
        model_used: 使用的模型标识，如 ``deepseek-chat`` / ``qwen2.5:7b``。
        output_digest: 输出摘要（不含大段原文，便于审计与入库）。
        error: 失败原因，成功时为 ``None``。
    """

    model_config = ConfigDict(extra="forbid")

    agent: str = Field(description="节点名：extractor/paper_linker/asset_mapper/...")
    round: int = Field(default=0, ge=0, description="回流轮次，0 表示首轮")
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: int = Field(ge=0)
    model_used: str = Field(description="如 deepseek-chat / deepseek-reasoner / qwen2.5:7b")
    output_digest: str = Field(description="输出摘要（不含大段原文，便于审计）")
    error: str | None = None


class AffectedAsset(IntelBaseModel):
    """受影响资产条目（富化维度①）。

    Attributes:
        asset_type: 资产类型。
        name: 资产名称。
        vendor: 厂商。
        version_range: 受影响版本区间描述，如 ``<2.4.6``。
        ecosystem: 包生态（``PyPI`` / ``npm`` / ``Maven``）。
        confidence: 置信度，区间 ``[0.0, 1.0]``。
        evidence_refs: 证据标识（``trace_id`` 或 URL）。
    """

    model_config = ConfigDict(extra="forbid")

    asset_type: Literal["library", "framework", "os", "device", "service", "cloud", "other"]
    name: str
    vendor: str | None = None
    version_range: str | None = Field(default=None, description="如 <2.4.6")
    ecosystem: str | None = Field(default=None, description="PyPI / npm / Maven / ...")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list, description="证据：trace_id 或 url")


class ExploitRecord(IntelBaseModel):
    """PoC / EXP 记录（富化维度③）。

    Attributes:
        source: 来源（``exploitdb`` / ``github`` / ``paper``）。
        url: 链接。
        exploit_type: 利用类型。
        maturity: 成熟度。
        reliability: 可信度，区间 ``[0.0, 1.0]``。
        verified: 是否经规则或人工二次确认。
        evidence_refs: 证据标识。
    """

    model_config = ConfigDict(extra="forbid")

    source: str = Field(description="exploitdb / github / paper / ...")
    url: str
    exploit_type: Literal["poc", "weaponized", "analysis", "unknown"] = "unknown"
    maturity: Literal["none", "poc", "functional", "high"] = "none"
    reliability: float = Field(default=0.5, ge=0.0, le=1.0)
    verified: bool = Field(default=False, description="是否经规则/人工二次确认")
    evidence_refs: list[str] = Field(default_factory=list)


class AttackChainStep(IntelBaseModel):
    """攻击链单步（富化维度⑤）。

    Attributes:
        order: 步骤序号，从 1 开始。
        technique_id: ATT&CK 技术 ID，如 ``T1190``。
        tactic: ATT&CK 战术，如 ``initial-access``。
        stage: Kill Chain 阶段，如 ``Delivery``。
        description: 该步说明。
        preconditions: 前置条件。
    """

    model_config = ConfigDict(extra="forbid")

    order: int = Field(ge=1)
    technique_id: str = Field(description="ATT&CK 技术 ID，如 T1190")
    tactic: str = Field(description="ATT&CK 战术，如 initial-access")
    stage: str = Field(description="Kill Chain 阶段，如 Delivery")
    description: str
    preconditions: list[str] = Field(default_factory=list)


class AttackChain(IntelBaseModel):
    """攻击链整体（富化维度⑤）。

    Attributes:
        steps: 攻击链步骤序列。
        entry_vector: 入口向量描述。
        privileges_required: 所需权限级别。
    """

    model_config = ConfigDict(extra="forbid")

    steps: list[AttackChainStep] = Field(default_factory=list)
    entry_vector: str | None = None
    privileges_required: Literal["none", "low", "high", "unknown"] = "unknown"


class EnrichedVuln(UnifiedVuln):
    """L3 富化输出：五维度富化结论 + 复核状态。

    Attributes:
        schema_version: 契约版本号（EnrichedVuln 独立版本号，v1.2 起）。
        affected_assets: 受影响资产（维度①）。
        related_papers: 关联论文（维度②）。
        exploits: PoC / EXP 记录（维度③）。
        risk_score: 风险分，区间 ``[0.0, 100.0]``，由确定性公式计算（非 LLM 猜测）。
        risk_level: 风险级别。
        risk_breakdown: 各因子权重贡献（``cvss`` / ``epss`` / ``kev`` / ``poc``）。
        attack_chain: 攻击链（维度⑤），未识别时为 ``None``。
        confidence: 整体置信度（Reviewer 裁决），区间 ``[0.0, 1.0]``。
        review_status: 复核状态（自动通过 / 已修订 / 需人工 / 重试耗尽永久失败）。
        review_notes: Reviewer 修订或驳回理由。
        agent_trace: 7 个 Agent 的执行轨迹。
        model_used: ``fast`` / ``smart`` 模型标识。
        enriched_at: 富化完成时间（UTC）。
        remediation_json: 富化维度⑦的修复建议 JSON 快照（``Remediation`` 的
            ``model_dump(mode="json")``）；未产出修复建议时为 ``None``。
    """

    model_config = ConfigDict(extra="forbid")

    # v1.2：EnrichedVuln 契约版本独立递增（父契约 UnifiedVuln 仍为 1.1）
    schema_version: str = Field(
        default=ENRICHED_VULN_SCHEMA_VERSION,
        description="契约版本号，变更必须 bump",
    )
    affected_assets: list[AffectedAsset] = Field(default_factory=list, description="富化维度①")
    related_papers: list[PaperVulnLink] = Field(default_factory=list, description="富化维度②")
    exploits: list[ExploitRecord] = Field(default_factory=list, description="富化维度③")
    risk_score: float = Field(ge=0.0, le=100.0, description="富化维度④：确定性公式计算，非 LLM 猜测")
    risk_level: Literal["low", "medium", "high", "critical"]
    risk_breakdown: dict[str, float] = Field(default_factory=dict, description="cvss/epss/kev/poc 各权重贡献")
    attack_chain: AttackChain | None = Field(default=None, description="富化维度⑤")
    confidence: float = Field(ge=0.0, le=1.0, description="整体置信度（Reviewer 裁决）")
    review_status: Literal["auto_pass", "revised", "needs_human", "permanently_failed"] = "auto_pass"
    review_notes: list[str] = Field(default_factory=list, description="Reviewer 修订/驳回理由")
    agent_trace: list[AgentStep] = Field(default_factory=list, description="7 个 Agent 执行轨迹")
    model_used: str = Field(description="fast / smart 模型标识")
    enriched_at: UTCDateTime = Field(description="富化完成时间（UTC）")
    remediation_json: dict[str, Any] | None = Field(
        default=None,
        description=(
            "富化维度⑦：修复建议 JSON 快照（summary / fixed_versions / mitigations / "
            "patch_urls / confidence）；未产出时为 None"
        ),
    )

    @model_validator(mode="after")
    def _ensure_contract_version(self) -> EnrichedVuln:
        """确保契约版本不低于 :data:`ENRICHED_VULN_SCHEMA_VERSION`（只升不降）。

        富化实体常由父契约（``UnifiedVuln``，v1.1）字段派生构造，此时 ``schema_version``
        会被继承为 ``1.1``；本校验把它抬到富化契约版本 ``1.2``，避免「新增字段却沿用旧版本号」
        （§10.2 不变式 2）。

        Returns:
            已校正版本的自身实例。
        """
        if _version_tuple(self.schema_version) < _version_tuple(ENRICHED_VULN_SCHEMA_VERSION):
            self.schema_version = ENRICHED_VULN_SCHEMA_VERSION
        return self
