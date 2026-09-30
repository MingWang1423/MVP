"""富化编排服务（PROJECT_PLAN.md §5.6 ``services/enrich_service.py``）。

职责：把「一条 ``UnifiedVuln``」喂给富化状态图，并把结果落库：

1. 从 ``unified_vuln`` 读取待富化事实（``--only-missing`` 时跳过已有富化结果的行）；
2. 装配依赖（只读论文检索、PoC 检索器、HTTP 客户端、可选 LLM）；
3. ``graph.ainvoke(new_state(vuln))`` → ``EnrichedVuln``；
4. ``VulnRepository.upsert_enriched`` 落库（**只追加**，不覆写事实层，§10.2 不变式 4）；
5. 返回 :class:`EnrichmentRun`（含 ``EnrichmentOutput``、token 计量、耗时）。

**离线可用**：当 ``LLM_API_KEY`` 未配置（占位值）或 ``use_llm=False`` 时，PaperLinker 走
检索折算降级路径，整条链路仍可产出 ``EnrichedVuln``（``model_used`` 会标明 ``retrieval-only``）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

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
from aisec_intel.llm.provider import LLMError, build_provider
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import EnrichmentOutput, PaperRelevanceBatch
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.storage.database import get_engine, session_scope
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
    """

    cve_id: str
    output: EnrichmentOutput | None
    duration_s: float
    errors: list[str] = field(default_factory=list)
    usage: list[dict[str, Any]] = field(default_factory=list)
    state: EnrichmentState | None = None

    @property
    def enriched(self) -> EnrichedVuln | None:
        """富化实体（``output`` 为空时为 ``None``）。"""
        return None if self.output is None else self.output.enriched_vuln


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
    model_tag = "retrieval-only"
    if resolved_use_llm:
        try:
            provider = build_provider(settings)
            model_tag = provider.model_for("fast")
            # include_raw=True → 可统计真实 token 用量（§3.4 成本保护）
            structured = getattr(provider, "structured_with_usage", None)
            runnable = (
                structured(PaperRelevanceBatch, role="fast")
                if callable(structured)
                else provider.structured(PaperRelevanceBatch, role="fast")
            )
            structured_llm = wrap_with_cache(
                runnable,
                schema=PaperRelevanceBatch,
                model=model_tag,
                provider=provider.name,
                session_factory=lambda: session_scope(get_engine(settings)),
                tracker=tracker,
            )
        except LLMError as exc:  # 缺少依赖 / 配置非法 → 降级为无 LLM
            logger.warning(f"LLM 不可用，PaperLinker 走检索折算降级：{exc}")

    return EnrichmentDeps(
        settings=settings,
        paper_search=_paper_search,
        structured_llm=structured_llm,
        http=resolved_http,
        model_tag=model_tag,
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
    output: EnrichmentOutput | None = None
    errors = list(final_state.get("errors") or [])
    if enriched is not None:
        output = EnrichmentOutput(
            enriched_vuln=enriched,
            agent_steps=list(final_state["agent_steps"]),
            confidence=float(final_state.get("confidence") or 0.0),
            errors=errors,
        )
        if persist:
            async with session_scope(get_engine(settings)) as session:
                await VulnRepository(session).upsert_enriched(enriched)
    else:
        errors.append("未产出 EnrichedVuln（二次校验失败或置信度不足被拒）")

    return EnrichmentRun(
        cve_id=vuln.vuln_id,
        output=output,
        duration_s=duration,
        errors=errors,
        usage=resolved_tracker.summary(),
        state=final_state,
    )


async def load_unified_vulns(
    settings: Settings,
    *,
    cve_id: str | None = None,
    limit: int = 1,
    only_missing: bool = False,
) -> list[UnifiedVuln]:
    """读取待富化的 ``UnifiedVuln``（``--cve`` 优先，否则按发布时间取最近若干条）。

    Args:
        settings: 全局配置。
        cve_id: 指定漏洞主键；``None`` 时按时间倒序取。
        limit: 取数上限（``cve_id`` 非空时忽略）。
        only_missing: 仅返回尚未有富化结果的行。

    Returns:
        ``UnifiedVuln`` 列表（``cve_id`` 指定但不存在时为空列表）。
    """
    async with session_scope(get_engine(settings)) as session:
        repo = VulnRepository(session)
        if cve_id:
            found = await repo.get_by_cve(cve_id)
            return [found] if found is not None else []
        rows = await repo.list_recent(limit=max(1, limit) * (4 if only_missing else 1))
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
        use_llm: 是否启用 LLM；``None`` 时自动判断。
        persist: 是否落库。
        max_rounds: 最大回流次数。
        checkpoint: ``True`` 时给图挂 ``InMemorySaver``（每条约会产生独立 thread_id，
            便于演示「运行时状态可查询」；生产切 PostgreSQL Saver）。

    Returns:
        :class:`EnrichmentRun` 列表（顺序与读取顺序一致）。
    """
    vulns = await load_unified_vulns(settings, cve_id=cve_id, limit=limit, only_missing=only_missing)
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
