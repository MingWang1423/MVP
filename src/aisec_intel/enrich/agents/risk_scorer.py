"""风险评分 Agent（富化维度④，PROJECT_PLAN.md §5.6 ``risk_scorer.py``）。

**确定性公式，不调用 LLM**（§3.2 闸门 ③）：数值类字段一律由规则计算，模型只做文本理解。

公式（满分 100，权重之和 = 1）：

| 因子 | 权重 | 计算 |
|---|---|---|
| ``cvss`` | 0.45 | ``max(base_score) / 10``（无 CVSS → 0） |
| ``epss`` | 0.25 | ``epss_score``（无 → 0） |
| ``kev`` | 0.15 | 进入 CISA KEV → 1，否则 0 |
| ``poc`` | 0.15 | ``min(1, 实战级 PoC 数 / 2)``；仅统计 ``maturity ∈ {poc, functional, high}``，检索入口候选不计分 |

级别阈值：``≥85 critical`` / ``≥70 high`` / ``≥40 medium`` / 其余 ``low``。
"""

from __future__ import annotations

from collections.abc import Sequence

from aisec_intel.models.agent_io import RiskLevel, RiskScore
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.unified_vuln import UnifiedVuln

WEIGHT_CVSS: float = 0.45
"""CVSS 因子权重。"""

WEIGHT_EPSS: float = 0.25
"""EPSS 因子权重。"""

WEIGHT_KEV: float = 0.15
"""CISA KEV 因子权重。"""

WEIGHT_POC: float = 0.15
"""PoC 因子权重。"""

CRITICAL_THRESHOLD: float = 85.0
"""``critical`` 阈值。"""

HIGH_THRESHOLD: float = 70.0
"""``high`` 阈值。"""

MEDIUM_THRESHOLD: float = 40.0
"""``medium`` 阈值。"""

ACTIONABLE_MATURITY: frozenset[str] = frozenset({"poc", "functional", "high"})
"""计入 PoC 因子的成熟度（排除 ``none``——检索入口候选不计分）。"""

POC_SATURATION: float = 2.0
"""PoC 因子饱和条数（达到即拿满权重）。"""


def score_risk(vuln: UnifiedVuln, exploits: Sequence[ExploitRecord] = ()) -> RiskScore:
    """按确定性公式计算风险分与级别（纯函数）。

    Args:
        vuln: 归一化后的漏洞事实（提供 CVSS / EPSS / KEV）。
        exploits: 富化得到的 PoC / EXP 记录（用于 PoC 因子）。

    Returns:
        :class:`~aisec_intel.models.agent_io.RiskScore`（含各因子贡献拆解）。
    """
    cvss_score = max((vector.base_score for vector in vuln.cvss), default=0.0)
    epss_score = float(vuln.epss_score or 0.0)
    kev_factor = 1.0 if vuln.kev else 0.0
    actionable = sum(1 for record in exploits if record.maturity in ACTIONABLE_MATURITY)
    poc_factor = min(1.0, actionable / POC_SATURATION)

    breakdown = {
        "cvss": round(min(1.0, cvss_score / 10.0) * WEIGHT_CVSS * 100, 2),
        "epss": round(min(1.0, epss_score) * WEIGHT_EPSS * 100, 2),
        "kev": round(kev_factor * WEIGHT_KEV * 100, 2),
        "poc": round(poc_factor * WEIGHT_POC * 100, 2),
    }
    total = round(min(100.0, sum(breakdown.values())), 2)
    return RiskScore(score=total, level=risk_level(total), breakdown=breakdown)


def risk_level(score: float) -> RiskLevel:
    """把风险分映射为级别（纯函数，边界确定）。

    Args:
        score: 风险分（``[0, 100]``）。

    Returns:
        ``critical`` / ``high`` / ``medium`` / ``low``。
    """
    if score >= CRITICAL_THRESHOLD:
        return "critical"
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"
