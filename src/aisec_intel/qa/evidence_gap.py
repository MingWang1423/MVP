"""证据缺口检测（Day25 阶段 1；PROJECT_PLAN.md §5.8 问答层增强）。

职责：在**本地检索之后、推理之前**判断「问题所需的事实是否已具备」，
把「知识库答不了」变成可观测、可路由的信号：

============  ==========================================================================
意图 / 问法     ``required_facts``（必须命中的事实标签）
============  ==========================================================================
修复 / 升级     ``fixed_version`` + ``vendor_advisory``
影响资产        ``affected_components`` + ``affected_versions``
攻击链          ``attack_techniques``
是否在野        ``kev`` + ``epss``
============  ==========================================================================

设计要点：

1. **纯函数优先**：:func:`required_facts_for` / :func:`facts_in_evidence` / :func:`detect_gaps`
   全部无 IO、无 LLM（规则式抽取，离线可复现），单测直接断言；
2. **口径与本地渲染对齐**：事实标签的文本标记（``修复版本`` / ``受影响版本`` / ``攻击技术`` /
   ``受影响组件`` 等）与 :mod:`aisec_intel.normalize.index_text` 和
   :func:`~aisec_intel.services.retrieval_service.render_structured_summary` 的渲染口径一致，
   并有元数据键（``cpe_matches`` / ``ecosystem_packages`` / ``kev`` …）作为高精度通道；
3. **缺口即路由信号**：``has_enough=False`` 时由图的条件边转入受控外部检索
   （:mod:`aisec_intel.qa.agents.external_retriever`），而不是任由 LLM 编造；
4. **缺口入答案**：:class:`GapReport` 透传给 Synthesizer，缺 ``fixed_version`` 时必须明说
   「知识库暂无修复版本信息」（见 :func:`aisec_intel.qa.agents.synthesizer.ensure_gap_notice`）。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from aisec_intel.logging_config import get_logger
from aisec_intel.models.external_evidence import FACT_LABELS
from aisec_intel.qa.state import GapReport, QAState, QueryIntent, RetrievalResult

logger = get_logger(__name__)

AGENT_NAME: str = "gap_checker"
"""节点名（写入 ``errors`` 与日志）。"""

# 说明：事实标签中文名（FACT_LABELS）与缺口报告契约（GapReport）定义在契约层
# （``models/external_evidence.py`` / ``qa/state.py``），此处重导出以保持问答层调用口径不变：
# ``from aisec_intel.qa.evidence_gap import GapReport, FACT_LABELS`` 依旧可用。
__all__ = [
    "FACT_LABELS",
    "GapChecker",
    "GapReport",
    "detect_gaps",
    "facts_in_evidence",
    "facts_in_text",
    "required_facts_for",
    "unique_evidence",
]

REMEDIATION_FACTS: tuple[str, ...] = ("fixed_version", "vendor_advisory")
"""修复 / 升级类问题必须具备的事实。"""

ASSET_FACTS: tuple[str, ...] = ("affected_components", "affected_versions")
"""「影响哪些资产」类问题必须具备的事实。"""

CHAIN_FACTS: tuple[str, ...] = ("attack_techniques",)
"""攻击链类问题必须具备的事实。"""

EXPLOITATION_FACTS: tuple[str, ...] = ("kev", "epss")
"""「是否在野利用」类问题必须具备的事实。"""

FACT_ORDER: tuple[str, ...] = (
    "fixed_version",
    "vendor_advisory",
    "affected_components",
    "affected_versions",
    "attack_techniques",
    "kev",
    "epss",
)
"""事实标签的规范顺序（输出稳定性：GapReport 按此排序）。"""

REQUIRED_BY_INTENT: dict[str, tuple[str, ...]] = {
    "remediation": REMEDIATION_FACTS,
    "asset_lookup": ASSET_FACTS,
    "attack_chain": CHAIN_FACTS,
}
"""意图 → 必需事实（语义兜底；关键词判定优先，两者取并集）。"""

REMEDIATION_KEYWORDS: tuple[str, ...] = (
    "修复",
    "升级",
    "补丁",
    "缓解",
    "处置",
    "fixed",
    "fix version",
    "upgrade",
    "patch",
    "mitigat",
    "remediat",
)
"""修复类问法关键词。"""

ASSET_KEYWORDS: tuple[str, ...] = (
    "资产",
    "哪些系统",
    "哪些设备",
    "影响面",
    "受影响",
    "installed",
    "asset",
    "affected system",
    "inventory",
)
"""资产类问法关键词。"""

CHAIN_KEYWORDS: tuple[str, ...] = (
    "攻击链",
    "攻击路径",
    "利用链",
    "利用步骤",
    "横向移动",
    "attack chain",
    "kill chain",
    "exploit chain",
)
"""攻击链类问法关键词。"""

EXPLOITATION_KEYWORDS: tuple[str, ...] = (
    "在野",
    "被利用",
    "是否已被",
    "kev",
    "epss",
    "exploited in the wild",
    "in the wild",
    "actively exploited",
)
"""「是否在野利用」类问法关键词。"""

REQUIRED_BY_KEYWORDS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (REMEDIATION_KEYWORDS, REMEDIATION_FACTS),
    (ASSET_KEYWORDS, ASSET_FACTS),
    (CHAIN_KEYWORDS, CHAIN_FACTS),
    (EXPLOITATION_KEYWORDS, EXPLOITATION_FACTS),
)
"""关键词组 → 必需事实（按此顺序判定并取并集）。"""

METADATA_FACT_KEYS: dict[str, tuple[str, ...]] = {
    "fixed_version": ("fixed_versions", "fixed_version", "first_patched_version"),
    "vendor_advisory": ("advisory_urls", "advisory", "advisories"),
    "affected_components": (
        "components",
        "component",
        "cpe_matches",
        "ecosystem_packages",
        "packages",
        "package",
        "affected_assets",
        "assets",
    ),
    "affected_versions": ("affected_versions", "versions", "vulnerable_version_range"),
    "attack_techniques": ("technique_ids", "technique_id"),
    "kev": ("kev",),
    "epss": ("epss", "epss_score"),
}
"""事实标签 → 元数据键（高精度通道：命中即认为该事实存在）。"""

FACT_MARKERS: dict[str, tuple[str, ...]] = {
    "fixed_version": (
        "修复版本",
        "已修复",
        "修复于",
        "升级到",
        "升级至",
        "fixed version",
        "fixed in",
        "fixed by",
        "firstpatchedversion",
        "patched in",
        "upgrade to",
    ),
    "vendor_advisory": (
        "官方补丁",
        "厂商公告",
        "安全公告",
        "补丁链接",
        "vendor advisory",
        "security advisory",
        "security bulletin",
        "advisory",
    ),
    "affected_components": ("受影响组件", "受影响资产", "组件:", "组件：", "component"),
    "affected_versions": (
        "受影响版本",
        "影响版本",
        "affected version",
        "vulnerableversionrange",
        "affected:",
    ),
    "attack_techniques": ("攻击技术", "attack technique", "att&ck", "mitre"),
    "kev": ("cisa kev", "known exploited", "在野利用", "已知被利用"),
    "epss": ("epss",),
}
"""事实标签 → 文本标记（渲染口径对齐；小写子串匹配）。"""

URL_PATTERN: re.Pattern[str] = re.compile(r"https?://\S+", re.IGNORECASE)
"""URL 匹配（组件 token 抽取前先剔除，避免把域名误判为 ``vendor:product``）。"""

COMPONENT_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"[a-z0-9][a-z0-9._-]{1,40}:[a-z0-9][a-z0-9._-]{1,40}")
"""组件 token（``vendor:product`` / ``PyPI:fsspec``，Apple 生态 ``cpe:2.3:...`` 亦可命中）。"""

TECHNIQUE_PATTERN: re.Pattern[str] = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
"""MITRE ATT&CK 技术 ID（``T1190`` / ``T1059.001``）。"""

TRUTHY_TEXT: frozenset[str] = frozenset({"true", "1", "yes", "y", "是"})
"""字符串形式的布尔真值（元数据里常以字符串落库）。"""


def facts_in_text(text: str) -> set[str]:
    """从任意文本中抽取可支撑的事实标签（纯函数）。

    判定顺序：先做文本标记匹配，再做结构化 token 抽取（组件 / ATT&CK 技术）。

    Args:
        text: 待检测文本（证据正文 / 元数据拼接串）。

    Returns:
        命中的事实标签集合。

    Examples:
        >>> sorted(facts_in_text("修复版本: 0.2.72"))
        ['fixed_version']
        >>> sorted(facts_in_text("受影响版本: paloaltonetworks:pan-os ==10.2.0"))
        ['affected_components', 'affected_versions']
        >>> sorted(facts_in_text("攻击技术: T1190(initial-access)"))
        ['attack_techniques']
    """
    lowered = (text or "").lower()
    if not lowered.strip():
        return set()
    found: set[str] = set()
    for fact, markers in FACT_MARKERS.items():
        if any(marker in lowered for marker in markers):
            found.add(fact)
    without_urls = URL_PATTERN.sub(" ", lowered)
    if COMPONENT_TOKEN_PATTERN.search(without_urls):
        found.add("affected_components")
    if TECHNIQUE_PATTERN.search(without_urls):
        found.add("attack_techniques")
    return found


def _metadata_truthy(value: Any) -> bool:
    """判断元数据值是否表示「事实存在」（纯函数）。

    Args:
        value: 元数据值（``bool`` / 字符串 / 数字 / 列表 / ``None``）。

    Returns:
        非空且非假值时返回 ``True``（``0`` / ``"false"`` / 空容器为假）。
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value) > 0.0
    if isinstance(value, str):
        token = value.strip().lower()
        return token in TRUTHY_TEXT or (bool(token) and token != "false")
    if isinstance(value, Iterable):
        return any(_metadata_truthy(item) for item in value)
    return bool(value)


def unique_evidence(items: Iterable[RetrievalResult]) -> list[RetrievalResult]:
    """按 ``doc_id`` 去重（保序，纯函数）。

    用途：把「融合代表 + 各路原始结果」合成一个证据池供缺口检测使用——
    RRF 融合对同一实体只保留一份代表载荷（较长者优先），会**遮蔽结构化事实**
    （如多跳路径文本较长、覆盖了图谱摘要里的「受影响版本」），因此缺口判定必须看全量。

    Args:
        items: 检索结果（可含重复 ``doc_id``）。

    Returns:
        去重后的列表（保留首次出现）。
    """
    seen: set[str] = set()
    unique: list[RetrievalResult] = []
    for item in items:
        if item.doc_id in seen:
            continue
        seen.add(item.doc_id)
        unique.append(item)
    return unique


def facts_in_evidence(evidence: Sequence[RetrievalResult]) -> set[str]:
    """汇总一批检索结果中已具备的事实标签（纯函数）。

    两路判定：① 元数据键（``cpe_matches`` / ``ecosystem_packages`` / ``kev`` …）；
    ② 正文文本标记（与本地渲染口径一致）。

    Args:
        evidence: 本地检索结果（Supervisor 融合后的 ``fused``）。

    Returns:
        命中的事实标签集合。

    Examples:
        >>> from aisec_intel.qa.state import RetrievalResult
        >>> item = RetrievalResult(source="graph", doc_id="d", content="受影响版本: pan-os >=10.2.0")
        >>> sorted(facts_in_evidence([item]))
        ['affected_versions']
        >>> graph = RetrievalResult(source="graph", doc_id="g", metadata={"kev": "true"})
        >>> sorted(facts_in_evidence([graph]))
        ['kev']
    """
    found: set[str] = set()
    for result in evidence:
        metadata = result.metadata or {}
        for fact, keys in METADATA_FACT_KEYS.items():
            if any(key in metadata and _metadata_truthy(metadata[key]) for key in keys):
                found.add(fact)
        found |= facts_in_text(result.content or "")
    return found


def required_facts_for(intent: QueryIntent) -> list[str]:
    """按意图与问法推导「必须具备的事实」清单（纯函数）。

    Args:
        intent: 查询理解结果（读 ``intent`` / ``query`` / ``rewritten_query`` / ``keywords``）。

    Returns:
        去重后的事实标签列表（按 :data:`FACT_ORDER` 排序）。

    Examples:
        >>> from aisec_intel.qa.state import QueryIntent
        >>> required_facts_for(QueryIntent(query="CVE-2024-34359 应升级到哪个版本", intent="remediation"))
        ['fixed_version', 'vendor_advisory']
        >>> required_facts_for(QueryIntent(query="CVE-2024-3400 影响哪些资产", intent="asset_lookup"))
        ['affected_components', 'affected_versions']
        >>> required_facts_for(QueryIntent(query="CVE-2024-3400 的攻击链", intent="attack_chain"))
        ['attack_techniques']
        >>> required_facts_for(QueryIntent(query="CVE-2024-3400 是否在野被利用", intent="vuln_lookup"))
        ['kev', 'epss']
    """
    haystack = " ".join([intent.intent, intent.query, intent.rewritten_query, *intent.entities.keywords]).lower()
    found: set[str] = set(REQUIRED_BY_INTENT.get(intent.intent, ()))
    for keywords, facts in REQUIRED_BY_KEYWORDS:
        if any(keyword.lower() in haystack for keyword in keywords):
            found.update(facts)
    return [fact for fact in FACT_ORDER if fact in found]


def detect_gaps(query_intent: QueryIntent, local_evidence: Sequence[RetrievalResult]) -> GapReport:
    r"""检测本地证据缺口（纯函数，Day25 阶段 1 的核心）。

    规则：
        1. 由 :func:`required_facts_for` 得到必须具备的事实；
        2. 由 :func:`facts_in_evidence` 得到已具备的事实；
        3. ``missing = required - present``，``has_enough = not missing``；
        4. **无强制事实要求**（如综合类问题）时：本地有证据即足够；无证据但问题含可查实体
           （CVE / 组件）判为不足，交由受控外部检索补齐；既无证据也无实体则按「足够」放行
           （由 Synthesizer 回「未找到相关信息」，**不发起外部调用**）。

    Args:
        query_intent: 查询理解结果。
        local_evidence: 本地检索证据（Supervisor 融合结果）。

    Returns:
        :class:`GapReport`。

    Examples:
        >>> from aisec_intel.qa.state import QueryIntent, RetrievalResult
        >>> intent = QueryIntent(query="CVE-2024-34359 应升级到哪个版本", intent="remediation")
        >>> detect_gaps(intent, []).missing
        ['fixed_version', 'vendor_advisory']
        >>> detect_gaps(intent, []).has_enough
        False
        >>> filled = RetrievalResult(source="vector", doc_id="d", content="修复版本: 0.2.72\\n官方补丁/公告: https://x")
        >>> detect_gaps(intent, [filled]).has_enough
        True
    """
    required = required_facts_for(query_intent)
    present = facts_in_evidence(local_evidence)
    satisfied = [fact for fact in required if fact in present]
    missing = [fact for fact in required if fact not in present]
    entities = [*query_intent.entities.cve_ids, *query_intent.entities.components]
    if required:
        has_enough = not missing
        rationale = (
            f"问题需要 {[FACT_LABELS[fact] for fact in required]}；"
            f"本地证据命中 {[FACT_LABELS[fact] for fact in satisfied]}、"
            f"缺失 {[FACT_LABELS[fact] for fact in missing]}"
        )
    else:
        has_enough = bool(local_evidence) or not entities
        suffix = "（含可查实体，交由受控外部检索补齐）" if not has_enough else ""
        rationale = f"该问题无强制事实要求；本地证据 {len(local_evidence)} 条{suffix}"
    return GapReport(
        required_facts=required,
        satisfied=satisfied,
        missing=missing,
        has_enough=has_enough,
        evidence_count=len(local_evidence),
        rationale=rationale,
    )


class GapChecker:
    """证据缺口检测节点（LangGraph：``supervisor`` 之后、``reasoner`` 之前）。

    Attributes:
        enabled: 是否启用缺口检测（``False`` 时恒返回「已足够」，用于对照实验）。
    """

    def __init__(self, *, enabled: bool = True) -> None:
        """初始化节点。

        Args:
            enabled: 是否启用缺口检测（默认启用）。
        """
        self._enabled = bool(enabled)

    @property
    def enabled(self) -> bool:
        """是否启用缺口检测。"""
        return self._enabled

    async def __call__(self, state: QAState) -> dict[str, Any]:
        """读 ``intent`` / ``fused``，写入 ``gap_report``（缺口时附 ``errors`` 留痕）。

        Args:
            state: 问答图状态。

        Returns:
            含 ``gap_report`` 的增量字典。

        Note:
            节点**不抛异常**：检测失败退化为「已足够」，保证问答链路不中断。
        """
        intent = state.get("intent")
        if intent is None:
            return {"errors": [f"{AGENT_NAME}: 状态缺少 intent（请先执行查询理解节点）"]}
        # 融合代表 + 各路未融合原始结果（去重）：避免融合代表遮蔽结构化事实
        evidence = unique_evidence([*list(state.get("fused") or []), *list(state.get("results") or [])])
        if not self._enabled:
            return {
                "gap_report": GapReport(
                    has_enough=True, evidence_count=len(evidence), rationale="缺口检测未启用"
                )
            }
        try:
            report = detect_gaps(intent, evidence)
        except Exception as exc:  # noqa: BLE001 - 缺口检测失败不得中断问答
            logger.warning(f"证据缺口检测失败（按「足够」继续）：{type(exc).__name__}: {exc}")
            return {
                "gap_report": GapReport(has_enough=True, evidence_count=len(evidence), rationale=f"检测失败：{exc}"),
                "errors": [f"{AGENT_NAME}: 检测失败：{type(exc).__name__}"],
            }
        payload: dict[str, Any] = {"gap_report": report}
        if report.missing:
            logger.info(f"[{AGENT_NAME}] 证据缺口：missing={report.missing}｜{report.rationale}")
            payload["errors"] = [f"{AGENT_NAME}: 本地证据缺口（{', '.join(report.missing_labels)}）"]
        return payload
