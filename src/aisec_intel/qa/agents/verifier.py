"""外部证据复核 Agent（Day25 阶段 2 任务 2.4；PROJECT_PLAN.md §5.8 受控外部检索）。

职责：对 :mod:`aisec_intel.qa.agents.external_retriever` 拿到的一批外部证据做**确定性复核**
（不调用 LLM），把「不可信内容」变成「可引用的答案事实」或「丢弃」：

1. **可信度评分**（纯函数 :func:`score_evidence`）::

       score = base×0.7 + 佐证×0.2 + 权威链接×0.1 − 扣分项

   - ``base``：源白名单基础可信度（NVD 1.0 > GHSA 0.9 > OSV 0.85 > KEV 0.8）；
   - 佐证：同一事实被**另一个源**同时给出（多源交叉印证）；
   - 权威链接：``https`` 且指向公告 / 补丁 / 官方漏洞库；
   - 扣分：CVE 与问题不一致（−0.25）、未支撑任何事实（−0.1）。

2. **多源冲突裁决**（纯函数 :func:`resolve_conflicts`）：同一事实多源给出不同内容时，
   取 ``trust_score`` 最高者为权威（并列时按源优先级 NVD > GHSA > OSV > KEV），并记录冲突说明；

3. **提升门槛**：``verified = score >= 阈值 且 CVE 与问题一致``；**只有 ``verified=True``
   的证据才允许转成 :class:`~aisec_intel.qa.state.RetrievalResult` 进入 Reasoner / Synthesizer**
   （即「提升为答案事实」）。注意：正式表 ``unified_vuln`` / ``enriched_vuln`` 仍只由
   L1/L2/L3 链路写入，本 Agent 不做任何正式表写入（约束 2）。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.external_evidence import (
    EXTERNAL_SOURCE_ORDER,
    EXTERNAL_SOURCE_TRUST,
    FACT_LABELS,
    ExternalEvidence,
    ExternalVerification,
)
from aisec_intel.qa.state import QAState, RetrievalResult
from aisec_intel.storage.repositories.external_evidence_repo import ExternalEvidenceRepository

logger = get_logger(__name__)

AGENT_NAME: str = "verifier"
"""节点名（写入 ``errors`` / 日志）。"""

DEFAULT_MIN_TRUST: float = 0.6
"""复核通过阈值（低于该值不得提升为答案事实）。"""

BASE_WEIGHT: float = 0.7
"""源基础可信度权重。"""

CORROBORATION_WEIGHT: float = 0.2
"""多源交叉印证权重。"""

AUTHORITY_WEIGHT: float = 0.1
"""权威链接权重。"""

MISMATCH_PENALTY: float = 0.25
"""CVE 与用户问题不一致的扣分。"""

NO_FACT_PENALTY: float = 0.1
"""未支撑任何事实的扣分。"""

AUTHORITY_HOSTS: tuple[str, ...] = (
    "nvd.nist.gov",
    "github.com",
    "osv.dev",
    "cisa.gov",
    "security.",
)
"""权威链接主机 / 前缀（``https`` + 命中即得满分权项）。"""

EXTERNAL_EVIDENCE_SOURCE: str = "external"
"""外部证据在 :class:`RetrievalResult` 中的通路名（引用来源标记为 ``external``）。"""

UNTRUSTED_FLAG: str = "untrusted_external_content"
"""``RetrievalResult.metadata`` 中的不可信标记键（下游据此识别外部内容）。"""


def is_authoritative_url(url: str) -> bool:
    """判断链接是否指向权威源（纯函数）。

    Args:
        url: 证据链接。

    Returns:
        ``https`` 且主机命中 :data:`AUTHORITY_HOSTS` 时返回 ``True``。
    """
    lowered = (url or "").strip().lower()
    return lowered.startswith("https://") and any(host in lowered for host in AUTHORITY_HOSTS)


def score_evidence(
    item: ExternalEvidence,
    *,
    corroborated: bool = False,
    cve_ids: Sequence[str] = (),
) -> float:
    """对外部证据做确定性可信度评分（纯函数）。

    Args:
        item: 外部证据。
        corroborated: 该证据支撑的事实是否被**另一个源**同时给出。
        cve_ids: 用户问题中指定的 CVE 编号（为空表示不约束）。

    Returns:
        ``[0,1]`` 区间的可信度评分。

    Examples:
        >>> from aisec_intel.models.base import utc_now
        >>> from aisec_intel.models.external_evidence import ExternalEvidence
        >>> ghsa = ExternalEvidence(
        ...     cve_id="CVE-2024-34359", source_type="ghsa", source_name="GHSA-56xg-wfcc-g829",
        ...     url="https://github.com/advisories/GHSA-56xg-wfcc-g829", snippet="修复版本: 0.2.72",
        ...     retrieved_at=utc_now(), facts=["fixed_version"], trust_score=0.9,
        ... )
        >>> round(score_evidence(ghsa, corroborated=True, cve_ids=["CVE-2024-34359"]), 3)
        0.93
        >>> round(score_evidence(ghsa, cve_ids=["CVE-2024-3400"]), 3)
        0.48
    """
    base = EXTERNAL_SOURCE_TRUST.get(item.source_type, 0.5)
    score = base * BASE_WEIGHT
    if corroborated:
        score += CORROBORATION_WEIGHT
    if is_authoritative_url(item.url):
        score += AUTHORITY_WEIGHT
    wanted = {str(value).strip().upper() for value in cve_ids if str(value).strip()}
    if wanted and (not item.cve_id or item.cve_id.upper() not in wanted):
        score -= MISMATCH_PENALTY
    if not item.facts:
        score -= NO_FACT_PENALTY
    return round(max(0.0, min(1.0, score)), 4)


def fact_groups(items: Sequence[ExternalEvidence]) -> dict[str, list[ExternalEvidence]]:
    """按事实标签分组（纯函数）。

    Args:
        items: 外部证据列表。

    Returns:
        ``事实标签 → 支撑该事实的证据列表``。
    """
    groups: dict[str, list[ExternalEvidence]] = {}
    for item in items:
        for fact in item.facts:
            groups.setdefault(fact, []).append(item)
    return groups


def resolve_conflicts(
    items: Sequence[ExternalEvidence],
) -> tuple[dict[str, str], list[str], set[str]]:
    """多源冲突裁决（纯函数）：同一事实取可信度最高者为权威。

    Args:
        items: 通过复核的外部证据。

    Returns:
        ``(权威映射, 冲突说明, 被多源佐证的定位符集合)``：
        权威映射为 ``事实标签 → 定位符``；佐证集合用于评分加权的可见性。
    """
    order = {name: index for index, name in enumerate(EXTERNAL_SOURCE_ORDER)}
    authoritative: dict[str, str] = {}
    conflicts: list[str] = []
    corroborated: set[str] = set()
    for fact, group in fact_groups(items).items():
        best = max(group, key=lambda item: (item.trust_score, -order.get(item.source_type, 9)))
        authoritative[fact] = best.locator
        for item in group:
            if item.source_type != best.source_type:
                corroborated.add(item.locator)
                corroborated.add(best.locator)
        if len({item.source_type for item in group}) > 1:
            sources = ", ".join(dict.fromkeys(item.source_type for item in group))
            conflicts.append(
                f"{FACT_LABELS.get(fact, fact)}：{len(group)} 条证据来自多个源（{sources}），"
                f"按 trust_score 取 {best.locator}"
            )
    return authoritative, conflicts, corroborated


def verify_evidence(
    items: Sequence[ExternalEvidence],
    *,
    cve_ids: Sequence[str] = (),
    threshold: float = DEFAULT_MIN_TRUST,
) -> tuple[list[ExternalEvidence], ExternalVerification]:
    """对外部证据做复核并裁决多源冲突（纯函数）。

    评分链路：先按 :func:`score_evidence` 打分（含多源佐证加权），
    再按 :func:`resolve_conflicts` 得出权威映射；``verified = score >= threshold``。

    Args:
        items: 外部证据（清洗后）。
        cve_ids: 用户问题中指定的 CVE 编号（为空表示不约束）。
        threshold: 通过阈值（默认 :data:`DEFAULT_MIN_TRUST`）。

    Returns:
        ``(accepted, verification)``：``accepted`` 已带复核后的 ``trust_score`` 与 ``verified=True``。
    """
    if not items:
        return [], ExternalVerification()
    wanted = {str(value).strip().upper() for value in cve_ids if str(value).strip()}
    _, _, corroborated = resolve_conflicts(items)
    scored: list[ExternalEvidence] = []
    reasons: list[str] = []
    for item in items:
        score = score_evidence(item, corroborated=item.locator in corroborated, cve_ids=wanted)
        mismatch = bool(wanted) and (not item.cve_id or item.cve_id.upper() not in wanted)
        passed = score >= threshold and not mismatch
        scored.append(item.model_copy(update={"trust_score": score, "verified": passed}))
        if not passed:
            reasons.append(
                f"丢弃 {item.locator}（score={score:.2f} < {threshold:.2f}"
                + ("，CVE 与问题不一致" if mismatch else "")
                + "）"
            )
    accepted = [item for item in scored if item.verified]
    authoritative, conflicts, _ = resolve_conflicts(accepted)
    verification = ExternalVerification(
        accepted=len(accepted),
        rejected=len(scored) - len(accepted),
        verified_facts=sorted({fact for fact, locator in authoritative.items() if locator}),
        authoritative=authoritative,
        conflicts=conflicts,
        sources=list(dict.fromkeys(item.source_type for item in accepted)),
        trust_scores={item.locator: item.trust_score for item in scored},
        reasons=reasons,
    )
    return accepted, verification


def to_retrieval_results(items: Sequence[ExternalEvidence]) -> list[RetrievalResult]:
    """把**通过复核**的外部证据转成统一检索结果（纯函数，唯一提升通道）。

    只有 ``verified=True`` 的条目会被转换（未通过复核的一律丢弃，约束 2/4）。

    Args:
        items: 外部证据列表（通常为 :func:`verify_evidence` 的 ``accepted``）。

    Returns:
        :class:`~aisec_intel.qa.state.RetrievalResult` 列表（``source="external"``）。

    Examples:
        >>> from aisec_intel.models.base import utc_now
        >>> from aisec_intel.models.external_evidence import ExternalEvidence
        >>> item = ExternalEvidence(
        ...     cve_id="CVE-2024-34359", source_type="ghsa", source_name="GHSA-56xg-wfcc-g829",
        ...     url="https://github.com/advisories/GHSA-56xg-wfcc-g829", title="llama-cpp-python RCE",
        ...     snippet="修复版本: 0.2.72", retrieved_at=utc_now(), trust_score=0.93, verified=True,
        ...     facts=["fixed_version"],
        ... )
        >>> result = to_retrieval_results([item])[0]
        >>> result.source, result.metadata["cve_id"], result.metadata["untrusted_external_content"]
        ('external', 'CVE-2024-34359', True)
        >>> to_retrieval_results([item.model_copy(update={"verified": False})])
        []
    """
    results: list[RetrievalResult] = []
    for item in items:
        if not item.verified:
            continue
        facts = "、".join(FACT_LABELS.get(fact, fact) for fact in item.facts) or "无标注事实"
        results.append(
            RetrievalResult(
                source=EXTERNAL_EVIDENCE_SOURCE,
                doc_id=item.locator,
                content=(
                    f"[外部证据｜不可信内容｜{item.label}｜trust={item.trust_score:.2f}｜支撑事实：{facts}]\n"
                    f"{item.title}\n{item.snippet}"
                ),
                score=item.trust_score,
                metadata={
                    "cve_id": item.cve_id,
                    "url": item.url,
                    "source_type": item.source_type,
                    "source_name": item.source_name,
                    "trust_score": item.trust_score,
                    "verified": True,
                    "untrusted": True,
                    UNTRUSTED_FLAG: True,
                },
            )
        )
    return results


def apply_verification(
    items: Sequence[ExternalEvidence],
    accepted: Sequence[ExternalEvidence],
    verification: ExternalVerification,
) -> list[ExternalEvidence]:
    """把复核结果套回证据列表（纯函数，供落库：``verified`` / ``trust_score`` 持久化）。

    Args:
        items: 原始外部证据（来自检索节点）。
        accepted: 通过复核的证据。
        verification: 复核汇总（含被丢弃条目的评分）。

    Returns:
        与 ``items`` 等长、已带复核结论的列表。
    """
    accepted_by_key = {(item.locator, item.content_hash): item for item in accepted}
    restored: list[ExternalEvidence] = []
    for item in items:
        scored = accepted_by_key.get((item.locator, item.content_hash))
        if scored is not None:
            restored.append(scored)
        else:
            restored.append(
                item.model_copy(
                    update={
                        "trust_score": verification.trust_scores.get(item.locator, item.trust_score),
                        "verified": False,
                    }
                )
            )
    return restored


class ExternalEvidenceVerifier:
    """外部证据复核节点（LangGraph：``external_retriever`` 之后、``reasoner`` 之前）。

    Attributes:
        threshold: 复核通过阈值。
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        threshold: float | None = None,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        """初始化节点。

        Args:
            settings: 全局配置；``None`` 时使用进程级单例。
            threshold: 显式阈值；``None`` 时取 ``Settings.qa_external_trust_threshold``。
            session_factory: 返回异步上下文管理器的会话工厂（复核结论回写 ``external_evidence``）；
                ``None`` 时不回写（离线单测）。
        """
        resolved = settings or get_settings()
        self._settings = resolved
        self._threshold = resolved.qa_external_trust_threshold if threshold is None else float(threshold)
        self._session_factory = session_factory

    @property
    def threshold(self) -> float:
        """当前复核通过阈值。"""
        return self._threshold

    async def __call__(self, state: QAState) -> dict[str, Any]:
        """复核 ``external_evidence``，把通过的证据并入 ``fused``（唯一提升通道）。

        Args:
            state: 问答图状态。

        Returns:
            含 ``external_verification`` / ``external_evidence``（复核后）与 ``fused``（追加外部证据）
            的增量字典。

        Note:
            ``fused`` 为无归约器通道，本节点**显式重写**为「本地融合结果 + 已复核外部证据」，
            供 Reasoner / Synthesizer 统一消费；``unified_vuln`` / ``enriched_vuln`` 仍不被写入。
        """
        items = list(state.get("external_evidence") or [])
        if not items:
            return {"external_verification": ExternalVerification()}
        intent = state.get("intent")
        cve_ids = list(intent.entities.cve_ids) if intent is not None else []
        try:
            accepted, verification = verify_evidence(items, cve_ids=cve_ids, threshold=self._threshold)
        except Exception as exc:  # noqa: BLE001 - 复核失败不得中断问答
            logger.warning(f"[{AGENT_NAME}] 外部证据复核失败（全部丢弃）：{type(exc).__name__}: {exc}")
            return {
                "external_verification": ExternalVerification(),
                "errors": [f"{AGENT_NAME}: 复核失败：{type(exc).__name__}: {exc}"],
            }
        promoted = to_retrieval_results(accepted)
        fused = [*list(state.get("fused") or []), *promoted]
        persisted = await self._persist(apply_verification(items, accepted, verification))
        payload: dict[str, Any] = {
            "external_evidence": accepted,
            "external_verification": verification,
            "fused": fused,
        }
        if verification.conflicts:
            payload["errors"] = [
                f"{AGENT_NAME}: 外部证据冲突（已按 trust_score 裁决）：{item}" for item in verification.conflicts
            ]
        extra = f"｜可提升事实={verification.verified_labels}" if verification.verified_facts else ""
        logger.info(
            f"[{AGENT_NAME}] 外部证据复核：通过={verification.accepted} 丢弃={verification.rejected}"
            f"｜源={verification.sources}{extra}｜回写={persisted}"
        )
        return payload

    async def _persist(self, items: Sequence[ExternalEvidence]) -> int:
        """把复核结论回写 ``external_evidence``（更新 ``verified`` / ``trust_score``）。

        Args:
            items: 已带复核结论的证据列表。

        Returns:
            回写条数（未注入会话工厂 / 写入失败时为 0）。

        Note:
            回写失败**不影响问答**（答案仍能用内存中的复核结论）。
        """
        if self._session_factory is None or not items:
            return 0
        try:
            async with self._session_factory() as session:
                return await ExternalEvidenceRepository(session).upsert_many(items)
        except Exception as exc:  # noqa: BLE001 - 回写失败不得影响回答
            logger.warning(f"[{AGENT_NAME}] 复核结论回写失败（已忽略）：{type(exc).__name__}: {exc}")
            return 0


def build_external_verifier(
    settings: Settings | None = None,
    *,
    threshold: float | None = None,
    session_factory: Callable[[], Any] | None = None,
) -> ExternalEvidenceVerifier:
    """按配置构建外部证据复核节点（唯一工厂）。

    Args:
        settings: 全局配置；``None`` 时使用进程级单例。
        threshold: 显式阈值；``None`` 时取配置值。
        session_factory: 复核结论回写用的会话工厂；``None`` 时不回写。

    Returns:
        可用的 :class:`ExternalEvidenceVerifier`。
    """
    return ExternalEvidenceVerifier(settings=settings, threshold=threshold, session_factory=session_factory)