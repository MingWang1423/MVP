r"""富化图状态（PROJECT_PLAN.md §5.6 ``enrich/state.py``）。

``EnrichmentState`` 是 LangGraph 各节点之间传递的**唯一**状态对象：

| 键 | 类型 | 说明 |
|---|---|---|
| ``unified_vuln`` | :class:`~aisec_intel.models.unified_vuln.UnifiedVuln` | 输入事实（不可变，节点只读） |
| ``enriched_vuln`` | :class:`~aisec_intel.models.enriched_vuln.EnrichedVuln` \\| None | Verifier 产出的最终富化结果 |
| ``paper_hits`` | ``list[PaperHit]`` | PaperLinker 的检索候选（中间结果） |
| ``related_papers`` | ``list[PaperVulnLink]`` | PaperLinker 判定后的关联（写入 ``enriched_vuln``） |
| ``exploits`` | ``list[ExploitRecord]`` | PoCSeeker 产出 |
| ``verification`` | :class:`~aisec_intel.models.agent_io.VerificationReport` \\| None | Verifier 交叉验证报告 |
| ``agent_steps`` | ``list[AgentStep]`` | 执行轨迹（写入 ``enriched_vuln.agent_trace``） |
| ``errors`` | ``list[str]`` | 非致命错误（降级 / 超时，不中断整条链路） |
| ``confidence`` | ``float`` | 当前整体置信度（Verifier 裁决；用于回流条件边） |
| ``trace_id`` | ``str`` | 全链路追踪 ID（§10.2 不变式 5） |
| ``round`` | ``int`` | 回流轮次（``0`` 为首轮；> ``max_rounds`` 强制结束） |
| ``model_used`` | ``str`` | 本次富化使用的模型标识（fast / smart / fake） |

设计说明：
    - 中间结果显式放进 state，便于**回流时复用**（例如 Verifier 打回后 PoCSeeker 仍能拿到候选）；
    - 状态只增不改上游键（``unified_vuln`` 全程只读，§10.2 不变式 4）。
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, NotRequired, TypedDict

from aisec_intel.models.agent_io import Remediation, VerificationReport
from aisec_intel.models.enriched_vuln import AffectedAsset, AgentStep, AttackChain, EnrichedVuln, ExploitRecord
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import CVSSVector, UnifiedVuln
from aisec_intel.storage.repositories.paper_repo import PaperHit

UNDEFINED_CONFIDENCE: float = 0.0
"""初始置信度（尚未裁决，等价「无结论」）。"""


class EnrichmentState(TypedDict):
    """富化图的共享状态（TypedDict，见模块 docstring 的字段表）。

    Note:
        ``agent_steps`` / ``errors`` 声明了 ``operator.add`` 归约器（LangGraph reducer）：
        节点只需返回**增量列表**即自动追加，天然支持回流时的多轮累积。
    """

    unified_vuln: UnifiedVuln
    trace_id: str
    round: int
    confidence: float
    agent_steps: Annotated[list[AgentStep], operator.add]
    errors: Annotated[list[str], operator.add]
    enriched_vuln: NotRequired[EnrichedVuln | None]
    paper_hits: NotRequired[list[PaperHit]]
    related_papers: NotRequired[list[PaperVulnLink]]
    cvss_inferred: NotRequired[list[CVSSVector]]
    affected_assets: NotRequired[list[AffectedAsset]]
    attack_chain: NotRequired[AttackChain | None]
    remediation: NotRequired[Remediation | None]
    exploits: NotRequired[list[ExploitRecord]]
    verification: NotRequired[VerificationReport | None]
    model_used: NotRequired[str]


def new_state(vuln: UnifiedVuln, *, trace_id: str | None = None, model_used: str = "unset") -> EnrichmentState:
    """构造初始状态（所有键均显式赋值，避免 LangGraph 通道缺省歧义）。

    Args:
        vuln: L2 归一化输出实体（本次富化的输入事实）。
        trace_id: 追踪 ID；缺省取 ``vuln.trace_ids[0]``，再退化为 ``vuln.vuln_id``。
        model_used: 模型标识占位（由 Agent 覆盖）。

    Returns:
        可直接交给 ``graph.ainvoke`` 的初始状态。
    """
    resolved_trace = trace_id or (vuln.trace_ids[0] if vuln.trace_ids else vuln.vuln_id)
    return EnrichmentState(
        unified_vuln=vuln,
        trace_id=resolved_trace,
        round=0,
        confidence=UNDEFINED_CONFIDENCE,
        agent_steps=[],
        errors=[],
        enriched_vuln=None,
        paper_hits=[],
        related_papers=[],
        cvss_inferred=[],
        affected_assets=[],
        attack_chain=None,
        remediation=None,
        exploits=[],
        verification=None,
        model_used=model_used,
    )


def state_summary(state: EnrichmentState) -> dict[str, Any]:
    """返回状态摘要（日志 / 测试断言用，不含大段文本）。

    Args:
        state: 富化图状态。

    Returns:
        形如 ``{"cve_id", "round", "confidence", "papers", "exploits", "steps", "errors"}`` 的字典。
    """
    return {
        "cve_id": state["unified_vuln"].vuln_id,
        "round": state["round"],
        "confidence": round(float(state["confidence"]), 4),
        "papers": len(state.get("related_papers") or []),
        "exploits": len(state.get("exploits") or []),
        "assets": len(state.get("affected_assets") or []),
        "cvss_inferred": len(state.get("cvss_inferred") or []),
        "attack_steps": len(state.get("attack_chain").steps) if state.get("attack_chain") else 0,
        "remediation": bool(state.get("remediation")),
        "steps": len(state["agent_steps"]),
        "errors": len(state["errors"]),
    }
