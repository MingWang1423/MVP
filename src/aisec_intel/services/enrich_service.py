"""富化编排服务（PROJECT_PLAN.md §5.6 ``services/enrich_service.py``）。

职责：把「一条 ``UnifiedVuln``」喂给富化状态图，并把结果落库：

1. 从 ``unified_vuln`` 读取待富化事实（``--only-missing`` 时跳过已有富化结果的行）；
2. 装配依赖（只读论文检索、PoC 检索器、HTTP 客户端、可选 LLM）；
3. ``graph.ainvoke(new_state(vuln))`` → ``EnrichedVuln``；
4. ``VulnRepository.upsert_enriched`` 落库（**只追加**，不覆写事实层，§10.2 不变式 4）；
5. 返回 :class:`EnrichmentRun`（含 ``EnrichmentOutput``、token 计量、耗时）。

自愈链路（Day23 任务 2，见 :func:`retry_failed`）：富化输出二次校验 3 次未通过 →
``review_status='needs_human'``；随后由「失败重试队列」每日 02:00 自动重试最多 3 次，
通过则恢复（``auto_pass``/``revised``），用尽则标记 ``permanently_failed`` 并保留全部结论。

**离线可用**：当 ``LLM_API_KEY`` 未配置（占位值）或 ``use_llm=False`` 时，PaperLinker 走
检索折算降级路径，整条链路仍可产出 ``EnrichedVuln``（``model_used`` 会标明 ``retrieval-only``）。
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from aisec_intel.config import Settings
from aisec_intel.connectors.http_client import HttpClient
from aisec_intel.enrich.graph import (
    DEFAULT_MAX_ROUNDS,
    EnrichmentDeps,
    build_enrichment_graph,
    thread_config,
)
from aisec_intel.enrich.state import EnrichmentState, new_state
from aisec_intel.enrich.tools.search_tools import search_papers
from aisec_intel.llm.cache import TokenUsageTracker, wrap_with_cache
from aisec_intel.llm.fallback import Candidate, DegradingStructuredRunnable, fallback_plan
from aisec_intel.llm.provider import LLMError, build_provider
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import (
    AttackChainDraft,
    CVSSInference,
    EnrichmentOutput,
    PaperRelevanceBatch,
    Remediation,
)
from aisec_intel.models.enriched_vuln import AgentStep, EnrichedVuln
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.security.prompt_guard import OutputValidationError, validate_llm_output
from aisec_intel.services.alert_service import emit_alerts_safely
from aisec_intel.services.metrics_service import record_enrich
from aisec_intel.services.self_heal import (
    ACTION_EXHAUSTED,
    ACTION_RECOVERED,
    ACTION_RETRY,
    COMPONENT_ENRICH,
    SelfHealEvent,
    configure_self_heal_log,
    log_self_heal,
)
from aisec_intel.storage.database import get_engine, session_scope
from aisec_intel.storage.repositories.stats_repo import HIGH_RISK_LEVELS
from aisec_intel.storage.repositories.vuln_repo import VulnRepository

logger = get_logger(__name__)

PLACEHOLDER_API_KEYS: frozenset[str] = frozenset({"", "sk-REPLACE_ME", "REPLACE_ME", "ollama"})
"""占位 Key：出现即视为「未配置真实密钥」，自动走无 LLM 降级路径。"""


@dataclass(slots=True)
class EnrichmentRun:
    """单条富化的执行结果。

    Attributes:
        cve_id: 漏洞主键。
        output: 富化输出（``None`` 表示未产出结论，如 Pydantic 二次校验失败）。
        duration_s: 耗时（秒）。
        errors: 非致命错误 / 降级说明。
        usage: token 计量快照（``TokenUsageTracker.summary()``）。
        state: 完整图状态（调试与断言用）。
        degraded: 是否降级（Day18 任务 2：输出二次校验 3 次未通过 → ``needs_human``）。
    """

    cve_id: str
    output: EnrichmentOutput | None
    duration_s: float
    errors: list[str] = field(default_factory=list)
    usage: list[dict[str, Any]] = field(default_factory=list)
    state: EnrichmentState | None = None
    degraded: bool = False

    @property
    def enriched(self) -> EnrichedVuln | None:
        """富化实体（``output`` 为空时为 ``None``）。"""
        return None if self.output is None else self.output.enriched_vuln


OUTPUT_VALIDATION_ATTEMPTS: int = 3
"""LLM 输出二次校验的最大尝试次数（含首次）；耗尽即标记 degraded（Day18 任务 2）。"""


def repair_output(output: EnrichmentOutput, attempt: int) -> EnrichmentOutput:
    """对未通过校验的输出做逐级「保守修复」（纯函数）。

    修复顺序（每级都只**丢弃不可信内容**，绝不编造）：
        1. 第 1 次失败 → 丢弃修复建议（``remediation`` / ``remediation_json``）；
        2. 第 2 次失败 → 复核状态降级为 ``needs_human``、置信度清零；
        3. 第 3 次仍失败 → 不再修复（由 :func:`validate_and_repair_output` 统一标记 degraded）。

    Args:
        output: 校验失败的输出。
        attempt: 已失败的次数（从 1 开始）。

    Returns:
        修复后的输出（调用方会再次校验）。
    """
    if attempt == 1:
        enriched = output.enriched_vuln.model_copy(update={"remediation_json": None})
        return output.model_copy(update={"enriched_vuln": enriched, "remediation": None})
    if attempt == 2:
        enriched = output.enriched_vuln.model_copy(update={"review_status": "needs_human"})
        return output.model_copy(update={"enriched_vuln": enriched, "confidence": 0.0})
    return output


def validate_and_repair_output(
    output: EnrichmentOutput,
    *,
    attempts: int = OUTPUT_VALIDATION_ATTEMPTS,
) -> tuple[EnrichmentOutput, bool, list[str]]:
    """对富化输出做 Pydantic 二次校验，最多 ``attempts`` 次；耗尽即标记 degraded。

    校验内容（Day18 任务 2）：
        1. ``EnrichmentOutput`` 自身（``extra="forbid"``，字段类型齐全）；
        2. 修复建议 JSON 必须能还原为 :class:`~aisec_intel.models.agent_io.Remediation`；
        3. ``enriched_vuln`` 的 ``remediation_json`` 快照与 ``remediation`` 一致。

    Args:
        output: 待校验输出。
        attempts: 最大尝试次数（默认 :data:`OUTPUT_VALIDATION_ATTEMPTS`）。

    Returns:
        ``(可用输出, 是否降级, 校验留痕)``；降级时输出已改写为 ``needs_human`` 且置信度 0。
    """
    notes: list[str] = []
    candidate = output
    for attempt in range(1, max(1, attempts) + 1):
        try:
            validated = validate_llm_output(candidate, EnrichmentOutput, context="enrichment")
            if validated.remediation is not None:
                validate_llm_output(
                    validated.remediation.model_dump(mode="json"), Remediation, context="remediation"
                )
            snapshot = validated.enriched_vuln.remediation_json
            if snapshot is not None:
                validate_llm_output(snapshot, Remediation, context="remediation_json")
            return validated, False, notes
        except OutputValidationError as exc:
            notes.append(f"富化输出二次校验失败（第 {attempt}/{attempts} 次）：{exc}")
            candidate = repair_output(candidate, attempt)
    degraded_entity = candidate.enriched_vuln.model_copy(
        update={"review_status": "needs_human", "remediation_json": None}
    )
    degraded_output = candidate.model_copy(update={"enriched_vuln": degraded_entity, "confidence": 0.0})
    return degraded_output, True, notes


def llm_available(settings: Settings) -> bool:
    """判断是否具备真实 LLM 调用条件（纯函数）。

    Args:
        settings: 全局配置。

    Returns:
        ``LLM_API_KEY`` 非占位值（或 provider=ollama）时返回 ``True``。
    """
    if settings.llm_provider == "ollama":
        return True
    return settings.llm_api_key.get_secret_value().strip() not in PLACEHOLDER_API_KEYS


def build_deps(
    settings: Settings,
    *,
    http: HttpClient | None = None,
    use_llm: bool | None = None,
    tracker: TokenUsageTracker | None = None,
    session: Any | None = None,
) -> EnrichmentDeps:
    """装配富化图依赖（生产路径）。

    Args:
        settings: 全局配置。
        http: HTTP 客户端；``None`` 时新建（由调用方负责关闭）。
        use_llm: 是否启用 LLM；``None`` 时按 :func:`llm_available` 自动判断。
        tracker: token 计量器。
        session: 已打开的会话（论文检索复用，避免重复建连）。

    Returns:
        :class:`~aisec_intel.enrich.graph.EnrichmentDeps`。
    """
    resolved_http = http or HttpClient(timeout=30.0)
    resolved_use_llm = llm_available(settings) if use_llm is None else use_llm

    async def _paper_search(keywords: Any, limit: int) -> Any:
        return await search_papers(keywords, limit=limit, session=session, settings=settings)

    structured_llm: Any | None = None
    smart_llm: Any | None = None
    attack_llm_fast: Any | None = None
    cvss_llm: Any | None = None
    remediation_llm: Any | None = None
    model_tag = "retrieval-only"
    smart_model_tag = "retrieval-only"
    if resolved_use_llm:
        try:
            provider = build_provider(settings)
            model_tag = provider.model_for("fast")
            smart_model_tag = provider.model_for("smart")
            session_factory = lambda: session_scope(get_engine(settings))  # noqa: E731 - 会话工厂
            # Day17 任务 4.2：降级链末级为 Ollama（主 provider 已是 ollama 时无需再建）
            fallback_provider: Any | None = None
            if settings.llm_fallback_enabled and settings.llm_provider != "ollama":
                try:
                    fallback_provider = build_provider(settings.model_copy(update={"llm_provider": "ollama"}))
                except LLMError as exc:  # 本地未装 ollama 时跳过该级，不影响其余降级
                    logger.warning(f"Ollama 兜底 provider 不可用（跳过该级降级）：{exc}")

            def _bind(bound: Any, schema: type[BaseModel], role: str) -> Any:
                """按角色绑定结构化输出 Runnable（真实 token 计量优先）。"""
                structured = getattr(bound, "structured_with_usage", None)
                return structured(schema, role=role) if callable(structured) else bound.structured(schema, role=role)

            def _wrap(schema: type[BaseModel], role: str, model: str) -> Any:
                """按角色绑定结构化输出 + 降级链 + 缓存（真实 token 计量）。"""
                candidates = [Candidate(label=model, runnable=_bind(provider, schema, role))]
                if settings.llm_fallback_enabled:
                    for fb_role, fb_model in fallback_plan(
                        role, fast_model=model_tag, smart_model=smart_model_tag
                    ):
                        bound = provider if fb_role != "ollama" else fallback_provider
                        if bound is None:
                            continue
                        candidates.append(Candidate(label=fb_model, runnable=_bind(bound, schema, fb_role)))
                runnable = (
                    DegradingStructuredRunnable(candidates, schema_name=schema.__name__)
                    if len(candidates) > 1
                    else candidates[0].runnable
                )
                return wrap_with_cache(
                    runnable,
                    schema=schema,
                    model=model,
                    provider=provider.name,
                    session_factory=session_factory,
                    tracker=tracker,
                )

            structured_llm = _wrap(PaperRelevanceBatch, "fast", model_tag)
            cvss_llm = _wrap(CVSSInference, "fast", model_tag)
            remediation_llm = _wrap(Remediation, "fast", model_tag)
            smart_llm = _wrap(AttackChainDraft, "smart", smart_model_tag)
            # Day9 门控：非高危/非 KEV 漏洞的攻击链映射改走 fast 模型（同一 schema，不同角色）
            attack_llm_fast = _wrap(AttackChainDraft, "fast", model_tag)
        except LLMError as exc:  # 缺少依赖 / 配置非法 → 降级为无 LLM
            logger.warning(f"LLM 不可用，相关节点走确定性降级路径：{exc}")
            structured_llm = cvss_llm = remediation_llm = smart_llm = attack_llm_fast = None

    return EnrichmentDeps(
        settings=settings,
        paper_search=_paper_search,
        structured_llm=structured_llm,
        smart_llm=smart_llm,
        attack_llm_fast=attack_llm_fast,
        cvss_llm=cvss_llm,
        remediation_llm=remediation_llm,
        http=resolved_http,
        model_tag=model_tag,
        smart_model_tag=smart_model_tag,
    )


async def enrich_vuln(
    vuln: UnifiedVuln,
    *,
    settings: Settings,
    deps: EnrichmentDeps | None = None,
    graph: Any | None = None,
    tracker: TokenUsageTracker | None = None,
    persist: bool = True,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    checkpoint_enabled: bool = False,
    thread_id: str | None = None,
) -> EnrichmentRun:
    """富化单条漏洞（跑完状态图并（可选）落库）。

    Args:
        vuln: 待富化的事实实体。
        settings: 全局配置。
        deps: 注入的依赖；``None`` 时用 :func:`build_deps` 装配。
        graph: 注入的编译图（测试用）；``None`` 时按 ``deps`` 装配。
        tracker: token 计量器（``None`` 时新建并随结果返回）。
        persist: ``True`` 时把 ``EnrichedVuln`` 写入 ``enriched_vuln`` 表。
        max_rounds: 最大回流次数。
        checkpoint_enabled: 图是否挂了 checkpointer（挂上时必须给 ``configurable.thread_id``）。
        thread_id: 断点续跑用的运行 ID；``None`` 时自动生成（每次运行唯一）。

    Returns:
        :class:`EnrichmentRun`（含输出、耗时、错误与 token 计量）。
    """
    resolved_tracker = tracker or TokenUsageTracker()
    resolved_deps = deps or build_deps(settings, tracker=resolved_tracker)
    compiled = graph or build_enrichment_graph(
        resolved_deps, max_rounds=max_rounds, min_confidence=settings.enrich_min_confidence
    )

    started = time.perf_counter()
    config = thread_config(vuln.vuln_id, run_id=thread_id) if checkpoint_enabled else None
    final_state: EnrichmentState = await compiled.ainvoke(
        new_state(vuln, model_used=resolved_deps.model_tag), config=config
    )
    duration = round(time.perf_counter() - started, 3)

    enriched = final_state.get("enriched_vuln")
    remediation: Remediation | None = final_state.get("remediation")
    output: EnrichmentOutput | None = None
    errors = list(final_state.get("errors") or [])
    degraded = False
    if enriched is not None:
        if remediation is not None:
            # Day17 任务 1（PROJECT_PLAN.md §10.3）：修复建议随富化结果落库。
            # EnrichedVuln v1.2 新增 remediation_json，值取 Remediation 的 JSON 快照。
            enriched = enriched.model_copy(update={"remediation_json": remediation.model_dump(mode="json")})
        output = EnrichmentOutput(
            enriched_vuln=enriched,
            agent_steps=list(final_state["agent_steps"]),
            confidence=float(final_state.get("confidence") or 0.0),
            errors=errors,
            remediation=remediation,
            cvss_inferred=list(final_state.get("cvss_inferred") or []),
        )
        # Day18 任务 2：输出必须过 Pydantic 二次校验；3 次未通过即标记 degraded（needs_human）
        output, degraded, validation_notes = validate_and_repair_output(output)
        errors.extend(validation_notes)
        if degraded:
            errors.append(
                f"富化输出二次校验 {OUTPUT_VALIDATION_ATTEMPTS} 次未通过：已标记 degraded"
                "（review_status=needs_human，置信度置 0），请人工复核"
            )
            logger.warning(f"富化输出降级：{vuln.vuln_id}（{'；'.join(validation_notes) or '未知原因'}）")
        enriched = output.enriched_vuln
        if persist:
            async with session_scope(get_engine(settings)) as session:
                await VulnRepository(session).upsert_enriched(enriched)
    else:
        errors.append("未产出 EnrichedVuln（二次校验失败或置信度不足被拒）")

    # Day17 任务 3.2 / 3.3：富化指标 + 失败率/LLM 连续失败告警评估（旁路）
    record_enrich(ok=output is not None, duration_s=duration)
    emit_alerts_safely()

    return EnrichmentRun(
        cve_id=vuln.vuln_id,
        output=output,
        duration_s=duration,
        errors=errors,
        usage=resolved_tracker.summary(),
        state=final_state,
        degraded=degraded,
    )


def is_high_risk(vuln: UnifiedVuln) -> bool:
    """判断事实层条目是否属于「高危」（纯函数）。

    口径与仪表盘 / P4 报告一致：命中 CISA KEV，或事实层 ``severity`` ∈ ``{HIGH, CRITICAL}``。
    不引入任何推断（富化层结论不参与筛选，避免「用结论筛输入」）。

    Args:
        vuln: 归一化后的漏洞实体。

    Returns:
        高危返回 ``True``。
    """
    if vuln.kev:
        return True
    severity = (vuln.severity or "").strip().upper()
    return severity in HIGH_RISK_LEVELS


async def load_unified_vulns(
    settings: Settings,
    *,
    cve_id: str | None = None,
    limit: int = 1,
    only_missing: bool = False,
    only_high_risk: bool = False,
) -> list[UnifiedVuln]:
    """读取待富化的 ``UnifiedVuln``（``--cve`` 优先，否则按发布时间取最近若干条）。

    Args:
        settings: 全局配置。
        cve_id: 指定漏洞主键；``None`` 时按时间倒序取。
        limit: 取数上限（``cve_id`` 非空时忽略）。
        only_missing: 仅返回尚未有富化结果的行。
        only_high_risk: 仅返回高危条目（KEV 或 ``severity∈{HIGH,CRITICAL}``，见 :func:`is_high_risk`）。

    Returns:
        ``UnifiedVuln`` 列表（``cve_id`` 指定但不存在时为空列表）。
    """
    async with session_scope(get_engine(settings)) as session:
        repo = VulnRepository(session)
        if cve_id:
            found = await repo.get_by_cve(cve_id)
            if found is None or (only_high_risk and not is_high_risk(found)):
                return []
            return [found]
        rows = await repo.list_recent(limit=max(1, limit) * (4 if only_missing else 1))
        if only_high_risk:
            rows = [vuln for vuln in rows if is_high_risk(vuln)]
        if not only_missing:
            return rows[: max(1, limit)]

        missing: list[UnifiedVuln] = []
        for vuln in rows:
            if await repo.get_enriched(vuln.vuln_id) is None:
                missing.append(vuln)
            if len(missing) >= max(1, limit):
                break
        return missing


async def enrich_batch(
    settings: Settings,
    *,
    cve_id: str | None = None,
    limit: int = 1,
    only_missing: bool = False,
    only_high_risk: bool = False,
    use_llm: bool | None = None,
    persist: bool = True,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    checkpoint: bool = False,
) -> list[EnrichmentRun]:
    """批量富化（读取 → 逐条跑图 → 落库），返回逐条结果。

    Args:
        settings: 全局配置。
        cve_id: 指定单条 CVE。
        limit: 条数上限。
        only_missing: 只处理未富化过的行。
        only_high_risk: 只处理高危条目（KEV 或 ``severity∈{HIGH,CRITICAL}``）。
        use_llm: 是否启用 LLM；``None`` 时自动判断。
        persist: 是否落库。
        max_rounds: 最大回流次数。
        checkpoint: ``True`` 时给图挂 ``InMemorySaver``（每条约会产生独立 thread_id，
            便于演示「运行时状态可查询」；生产切 PostgreSQL Saver）。

    Returns:
        :class:`EnrichmentRun` 列表（顺序与读取顺序一致）。
    """
    vulns = await load_unified_vulns(
        settings,
        cve_id=cve_id,
        limit=limit,
        only_missing=only_missing,
        only_high_risk=only_high_risk,
    )
    if not vulns:
        return []

    tracker = TokenUsageTracker()
    http = HttpClient(timeout=30.0)
    runs: list[EnrichmentRun] = []
    try:
        for vuln in vulns:
            deps = build_deps(settings, http=http, use_llm=use_llm, tracker=tracker)
            graph = None
            if checkpoint:
                from langgraph.checkpoint.memory import InMemorySaver

                graph = build_enrichment_graph(
                    deps,
                    checkpointer=InMemorySaver(),
                    max_rounds=max_rounds,
                    min_confidence=settings.enrich_min_confidence,
                )
            runs.append(
                await enrich_vuln(
                    vuln,
                    settings=settings,
                    deps=deps,
                    graph=graph,
                    tracker=tracker,
                    persist=persist,
                    max_rounds=max_rounds,
                    checkpoint_enabled=checkpoint,
                )
            )
    finally:
        await http.aclose()
    return runs


# ============================================================================
# 失败重试队列（Day23 任务 2：让「富化降级 → 人工」这条链路自动自愈）
# ============================================================================
RETRY_AGENT_NAME: str = "auto_retry"
"""``agent_trace`` 中重试节点的名字（已重试次数即按该名字的条目数统计）。"""

QUEUE_REVIEW_STATUS: str = "needs_human"
"""进入重试队列的复核状态：输出二次校验 3 次未通过时的降级状态（Day18 任务 2）。"""

PERMANENT_FAILURE_STATUS: str = "permanently_failed"
"""重试耗尽后的终态复核状态（``EnrichedVuln`` v1.3 新增取值，见 PROJECT_PLAN.md §12.19）。"""

MAX_RETRY_ATTEMPTS: int = 3
"""失败重试队列的最大重试次数；用尽即标记 :data:`PERMANENT_FAILURE_STATUS`。"""

DEFAULT_RETRY_BATCH_SIZE: int = 50
"""单轮重试最多处理的条数（保护 LLM 额度，避免一次重试打爆预算）。"""


def count_retry_attempts(enriched: EnrichedVuln) -> int:
    """统计某条富化结论已执行过的重试次数（纯函数）。

    Args:
        enriched: 富化实体（只读 ``agent_trace``）。

    Returns:
        ``agent_trace`` 中 agent 名为 :data:`RETRY_AGENT_NAME` 的条目数。
    """
    return sum(1 for step in enriched.agent_trace if step.agent == RETRY_AGENT_NAME)


def as_unified(enriched: EnrichedVuln) -> UnifiedVuln:
    """把富化实体还原为事实层视图（纯函数；重试时需要 ``UnifiedVuln`` 作为图输入）。

    Note:
        ``EnrichedVuln`` 继承自 ``UnifiedVuln``，此处**只取父契约字段**，
        保证不会把 L3 结论（资产 / 论文 / 攻击链）当作事实回喂给图（§10.2 不变式）。

    Args:
        enriched: 富化实体。

    Returns:
        仅含父契约字段的 ``UnifiedVuln``。
    """
    return UnifiedVuln.model_validate({name: getattr(enriched, name) for name in UnifiedVuln.model_fields})


def append_retry_step(
    enriched: EnrichedVuln,
    *,
    attempt: int,
    status: str,
    digest: str,
    error: str | None = None,
    latency_ms: int = 0,
    model_used: str = "retry-queue",
    confidence: float | None = None,
    notes: Sequence[str] = (),
) -> EnrichedVuln:
    """把一次重试写入 ``agent_trace`` / ``review_notes``（纯函数，不改写富化结论）。

    Args:
        enriched: 待追加轨迹的实体。
        attempt: 第几次重试（从 1 开始）。
        status: ``recovered`` / ``retry_failed`` / ``permanently_failed``。
        digest: 输出摘要（审计可读，超长自动截断）。
        error: 失败原因；成功时为 ``None``。
        latency_ms: 本次重试耗时（毫秒）。
        model_used: 本次重试使用的模型标识。
        confidence: 本次重试的置信度；``None`` 时沿用实体原值。
        notes: 追加到 ``review_notes`` 的说明。

    Returns:
        追加轨迹后的新实体（``schema_version`` 由契约校验器保证不低于 v1.3）。
    """
    step = AgentStep(
        agent=RETRY_AGENT_NAME,
        round=max(1, attempt),
        confidence=0.0 if confidence is None else confidence,
        latency_ms=max(0, latency_ms),
        model_used=model_used,
        output_digest=f"[{status}] {digest}"[:240],
        error=error,
    )
    return enriched.model_copy(
        update={
            "agent_trace": [*enriched.agent_trace, step],
            "review_notes": [*enriched.review_notes, *notes],
        }
    )


def mark_permanently_failed(
    enriched: EnrichedVuln,
    *,
    reason: str,
    attempts: int,
    latency_ms: int = 0,
) -> EnrichedVuln:
    """标记「重试耗尽 · 永久失败」终态（纯函数，**不删除任何既有结论**）。

    Args:
        enriched: 待标记的实体（保留既有富化结论，只改复核状态与留痕）。
        reason: 失败原因（写入轨迹与 ``review_notes``）。
        attempts: 已耗尽的重试次数。
        latency_ms: 最后一次重试耗时（毫秒）。

    Returns:
        ``review_status=permanently_failed`` 且置信度归零的新实体（下游据此不再当真）。
    """
    note = f"自动重试 {attempts} 次仍未通过复核，已标记 permanently_failed，等待人工处理：{reason}"
    marked = append_retry_step(
        enriched,
        attempt=attempts,
        status=PERMANENT_FAILURE_STATUS,
        digest=reason,
        error=reason,
        latency_ms=latency_ms,
        notes=[note],
    )
    return marked.model_copy(update={"review_status": PERMANENT_FAILURE_STATUS, "confidence": 0.0})


def carry_retry_history(previous: EnrichedVuln, fresh: EnrichedVuln) -> EnrichedVuln:
    """把旧实体的「重试留痕」并入本轮新结果（纯函数）。

    Note:
        重跑富化图会产出**全新的** ``agent_trace``（只含本轮业务节点），若不把历史的
        ``auto_retry`` 条目并回来，重试次数就会被重置为 0 ——
        「3 次用尽 → ``permanently_failed``」这条终态将永远无法到达（Day23 实测踩坑）。

    Args:
        previous: 重试前库中的实体（携带历史重试次数）。
        fresh: 本轮重跑图得到的新实体。

    Returns:
        轨迹 = 历史重试条目 + 本轮业务轨迹；``review_notes`` 同样保留历史「自动重试…」说明。
    """
    retry_steps = [step for step in previous.agent_trace if step.agent == RETRY_AGENT_NAME]
    retry_notes = [note for note in previous.review_notes if note.startswith("自动重试")]
    business_notes = [note for note in fresh.review_notes if not note.startswith("自动重试")]
    return fresh.model_copy(
        update={
            "agent_trace": [*retry_steps, *fresh.agent_trace],
            "review_notes": [*retry_notes, *business_notes],
        }
    )


@dataclass(slots=True)
class RetryOutcome:
    """单条富化结论的重试结果。

    Attributes:
        cve_id: 漏洞主键。
        attempts_before: 本次重试前的已重试次数。
        attempts_after: 本次重试后的已重试次数。
        status: ``recovered`` / ``retry_failed`` / ``permanently_failed``。
        review_status: 落库后的 ``review_status``。
        error: 失败原因；恢复时为 ``None``。
    """

    cve_id: str
    attempts_before: int
    attempts_after: int
    status: str
    review_status: str
    error: str | None = None


@dataclass(slots=True)
class RetryReport:
    """一轮失败重试的汇总结果。

    Attributes:
        scanned: 扫描到的候选条数（``review_status='needs_human'``）。
        recovered: 重试后通过复核的条数。
        retry_failed: 本次仍失败但还有重试机会的条数。
        permanently_failed: 重试耗尽、标记永久失败的条数。
        duration_s: 本轮耗时（秒）。
        outcomes: 逐条明细。
    """

    scanned: int = 0
    recovered: int = 0
    retry_failed: int = 0
    permanently_failed: int = 0
    duration_s: float = 0.0
    outcomes: list[RetryOutcome] = field(default_factory=list)

    def summary(self) -> str:
        """返回一行中文摘要（日志 / CLI 复用）。

        Returns:
            形如 ``扫描 3 条，恢复 1 条，仍失败 1 条，永久失败 1 条，耗时 12.34s``。
        """
        return (
            f"扫描 {self.scanned} 条，恢复 {self.recovered} 条，仍失败 {self.retry_failed} 条，"
            f"永久失败 {self.permanently_failed} 条，耗时 {self.duration_s:.2f}s"
        )


def bump_contract_version(enriched: EnrichedVuln) -> EnrichedVuln:
    """把实体重新过一遍契约校验，使 ``schema_version`` 不低于当前版本（纯函数）。

    Note:
        ``model_copy(update=...)`` **不触发**校验器，历史 v1.2 行被重试后若直接写回，
        会出现「v1.2 + ``permanently_failed``」的不一致组合；此处按 §10.3 只升不降。

    Args:
        enriched: 待规范化的实体。

    Returns:
        ``schema_version >= ENRICHED_VULN_SCHEMA_VERSION`` 的实体。
    """
    return EnrichedVuln.model_validate(enriched.model_dump())


async def _persist_retry(settings: Settings, enriched: EnrichedVuln, *, persist: bool) -> EnrichedVuln:
    """写回重试结果（``persist=False`` 时仅返回实体，供离线 / 单测使用）。

    Args:
        settings: 全局配置。
        enriched: 待写回的富化实体。
        persist: 是否真正落库。

    Returns:
        写回后的实体（契约版本已抬到当前值）。
    """
    normalized = bump_contract_version(enriched)
    if not persist:
        return normalized
    async with session_scope(get_engine(settings)) as session:
        return await VulnRepository(session).upsert_enriched(normalized)


async def load_retry_candidates(
    settings: Settings,
    *,
    limit: int = DEFAULT_RETRY_BATCH_SIZE,
    status: str = QUEUE_REVIEW_STATUS,
) -> list[EnrichedVuln]:
    """读取重试队列候选（``review_status='needs_human'``，最久未处理的优先）。

    Args:
        settings: 全局配置。
        limit: 取数上限。
        status: 队列状态（默认 :data:`QUEUE_REVIEW_STATUS`）。

    Returns:
        富化实体列表（含父表字段，可直接还原为 ``UnifiedVuln`` 重跑图）。
    """
    async with session_scope(get_engine(settings)) as session:
        repo = VulnRepository(session)
        ids = await repo.list_enriched_ids_by_review_status(status, limit=max(1, limit))
        entities: list[EnrichedVuln] = []
        for cve_id in ids:
            found = await repo.get_enriched(cve_id)
            if found is not None:
                entities.append(found)
        return entities


async def _retry_one(
    candidate: EnrichedVuln,
    *,
    settings: Settings,
    http: HttpClient,
    tracker: TokenUsageTracker,
    use_llm: bool | None,
    max_attempts: int,
    persist: bool,
) -> RetryOutcome:
    """重试单条富化结论（单条逻辑；异常隔离由调用方 :func:`retry_failed` 负责）。

    Args:
        candidate: 队列中的富化实体（``review_status='needs_human'``）。
        settings: 全局配置。
        http: 复用的 HTTP 客户端（论文 / PoC 检索）。
        tracker: token 计量器。
        use_llm: 是否启用 LLM；``None`` 时自动判断。
        max_attempts: 最大重试次数。
        persist: 是否写回库。

    Returns:
        :class:`RetryOutcome`（含状态、重试次数与失败原因）。
    """
    cve_id = candidate.vuln_id
    attempts_before = count_retry_attempts(candidate)

    if attempts_before >= max_attempts:
        reason = f"已达最大重试次数 {max_attempts}"
        updated = mark_permanently_failed(candidate, reason=reason, attempts=attempts_before)
        await _persist_retry(settings, updated, persist=persist)
        logger.warning(f"[retry] {cve_id} 重试次数已耗尽（{attempts_before}/{max_attempts}），补齐永久失败标记")
        log_self_heal(
            SelfHealEvent(
                component=COMPONENT_ENRICH,
                action=ACTION_EXHAUSTED,
                reason=reason,
                label=cve_id,
                attempt=attempts_before,
                details={"max_attempts": max_attempts},
            )
        )
        return RetryOutcome(cve_id, attempts_before, attempts_before, PERMANENT_FAILURE_STATUS,
                            PERMANENT_FAILURE_STATUS, reason)

    attempt_no = attempts_before + 1
    log_self_heal(
        SelfHealEvent(
            component=COMPONENT_ENRICH,
            action=ACTION_RETRY,
            reason="复核状态为 needs_human，进入自动重试",
            label=cve_id,
            attempt=attempt_no,
            details={"max_attempts": max_attempts},
        )
    )
    logger.info(f"[retry] {cve_id} 第 {attempt_no}/{max_attempts} 次自动重试开始")
    deps = build_deps(settings, http=http, use_llm=use_llm, tracker=tracker)
    run = await enrich_vuln(as_unified(candidate), settings=settings, deps=deps, tracker=tracker, persist=False)
    latency_ms = int(run.duration_s * 1000)
    fresh = run.output.enriched_vuln if run.output is not None else None
    reason = run.errors[-1] if run.errors else "重试仍未通过复核"

    if fresh is not None and fresh.review_status != QUEUE_REVIEW_STATUS:
        recovered = append_retry_step(
            carry_retry_history(candidate, fresh),
            attempt=attempt_no,
            status="recovered",
            digest=f"第 {attempt_no}/{max_attempts} 次重试通过复核（{fresh.review_status}）",
            latency_ms=latency_ms,
            model_used=fresh.model_used,
            confidence=fresh.confidence,
            notes=[f"自动重试第 {attempt_no}/{max_attempts} 次成功：复核状态 {fresh.review_status}"],
        )
        await _persist_retry(settings, recovered, persist=persist)
        logger.info(f"[retry] {cve_id} 第 {attempt_no}/{max_attempts} 次重试成功：{recovered.review_status}")
        log_self_heal(
            SelfHealEvent(
                component=COMPONENT_ENRICH,
                action=ACTION_RECOVERED,
                reason="重试后通过复核",
                label=cve_id,
                attempt=attempt_no,
                details={"review_status": recovered.review_status},
            )
        )
        return RetryOutcome(cve_id, attempts_before, attempt_no, "recovered", recovered.review_status)

    entity = carry_retry_history(candidate, fresh) if fresh is not None else candidate
    if attempt_no >= max_attempts:
        updated = mark_permanently_failed(entity, reason=reason, attempts=attempt_no, latency_ms=latency_ms)
        await _persist_retry(settings, updated, persist=persist)
        logger.warning(
            f"[retry] {cve_id} 已重试 {attempt_no}/{max_attempts} 次仍失败，标记 {PERMANENT_FAILURE_STATUS}：{reason}"
        )
        log_self_heal(
            SelfHealEvent(
                component=COMPONENT_ENRICH,
                action=ACTION_EXHAUSTED,
                reason=reason,
                label=cve_id,
                attempt=attempt_no,
                details={"max_attempts": max_attempts},
            )
        )
        return RetryOutcome(cve_id, attempts_before, attempt_no, PERMANENT_FAILURE_STATUS,
                            PERMANENT_FAILURE_STATUS, reason)

    updated = append_retry_step(
        entity,
        attempt=attempt_no,
        status="retry_failed",
        digest=reason,
        error=reason,
        latency_ms=latency_ms,
        model_used=entity.model_used,
        notes=[f"自动重试第 {attempt_no}/{max_attempts} 次仍失败：{reason}"],
    )
    await _persist_retry(settings, updated, persist=persist)
    logger.warning(f"[retry] {cve_id} 第 {attempt_no}/{max_attempts} 次重试仍失败：{reason}")
    return RetryOutcome(cve_id, attempts_before, attempt_no, "retry_failed", updated.review_status, reason)


async def load_retry_candidate(settings: Settings, cve_id: str) -> EnrichedVuln | None:
    """按主键读取单条富化实体（不校验 ``review_status``，供人工定向重试）。

    Args:
        settings: 全局配置。
        cve_id: 漏洞主键（大小写不敏感）。

    Returns:
        命中时返回实体，否则 ``None``。
    """
    async with session_scope(get_engine(settings)) as session:
        return await VulnRepository(session).get_enriched(cve_id)


async def retry_failed(
    settings: Settings,
    *,
    limit: int = DEFAULT_RETRY_BATCH_SIZE,
    max_attempts: int = MAX_RETRY_ATTEMPTS,
    cve_id: str | None = None,
    use_llm: bool | None = None,
    persist: bool = True,
) -> RetryReport:
    """失败重试队列主流程：重试 ``needs_human`` 的富化结论，最多 ``max_attempts`` 次。

    行为（自愈链路，由调度器每日 02:00 触发；也可用 ``python -m scripts.retry_failed`` 手动跑）：

    1. 扫描 ``review_status='needs_human'`` 的 ``enriched_vuln``（``enriched_at`` 升序，最久未处理优先）；
    2. 已重试次数取 ``agent_trace`` 中 :data:`RETRY_AGENT_NAME` 的条目数（上限 ``max_attempts``）；
    3. 再次跑富化图：通过复核 → 写回并把状态改为 ``auto_pass``/``revised``（``recovered``）；
       仍失败 → 留痕并保持 ``needs_human``（``retry_failed``）；
       次数用尽 → 标记 :data:`PERMANENT_FAILURE_STATUS`（``permanently_failed``，不再自动重试）；
    4. 每次重试写结构化日志 + 自愈事件（``logs/selfheal.log`` 与
       ``aisec_self_heal_total{component="enrich",action=...}`` 指标）。

    Note:
        单条失败不影响整轮（失败隔离）；``persist=False`` 用于离线演练与单测。

    Args:
        settings: 全局配置。
        limit: 本轮最多处理条数。
        max_attempts: 最大重试次数。
        cve_id: 指定单条漏洞（人工定向重试，忽略队列扫描顺序；``None`` 表示整队列）。
        use_llm: 是否启用 LLM；``None`` 时按 :func:`llm_available` 自动判断。
        persist: 是否写回库。

    Returns:
        :class:`RetryReport` 汇总（扫描 / 恢复 / 仍失败 / 永久失败 + 逐条明细）。
    """
    started = time.perf_counter()
    configure_self_heal_log(settings)
    if cve_id:
        targeted = await load_retry_candidate(settings, cve_id)
        candidates = [targeted] if targeted is not None else []
        if not candidates:
            logger.warning(f"[retry] 指定条目 {cve_id} 无富化结果，跳过本轮")
    else:
        candidates = await load_retry_candidates(settings, limit=limit)
    report = RetryReport(scanned=len(candidates))
    if not candidates:
        report.duration_s = round(time.perf_counter() - started, 3)
        logger.info("[retry] 失败重试队列为空（无 review_status=needs_human 的富化行）")
        return report

    logger.info(f"[retry] 失败重试队列开始：候选 {len(candidates)} 条，最大重试次数 {max_attempts}")
    tracker = TokenUsageTracker()
    http = HttpClient(timeout=30.0)
    try:
        for candidate in candidates:
            try:
                outcome = await _retry_one(
                    candidate,
                    settings=settings,
                    http=http,
                    tracker=tracker,
                    use_llm=use_llm,
                    max_attempts=max_attempts,
                    persist=persist,
                )
            except Exception as exc:  # noqa: BLE001 - 单条失败不影响整轮（失败隔离）
                logger.error(f"[retry] {candidate.vuln_id} 重试过程异常：{type(exc).__name__}: {exc}")
                log_self_heal(
                    SelfHealEvent(
                        component=COMPONENT_ENRICH,
                        action=ACTION_RETRY,
                        reason=f"重试异常：{type(exc).__name__}: {exc}",
                        label=candidate.vuln_id,
                        attempt=count_retry_attempts(candidate) + 1,
                        details={"isolated": True},
                    )
                )
                continue
            report.outcomes.append(outcome)
            if outcome.status == "recovered":
                report.recovered += 1
            elif outcome.status == "retry_failed":
                report.retry_failed += 1
            else:
                report.permanently_failed += 1
    finally:
        await http.aclose()

    report.duration_s = round(time.perf_counter() - started, 3)
    emit_alerts_safely()
    logger.info(f"[retry] 失败重试队列结束：{report.summary()}")
    return report
