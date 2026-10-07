"""问答路由（Day11 任务 5；PROJECT_PLAN.md §5.8 ``api/routers/qa.py``）。

端点：

===========================  ================================================
``POST /qa/ask``             接收 :class:`~aisec_intel.api.schemas.qa.AskRequest`，
                             跑完整问答图，返回冻结契约 :class:`QAResponse`
``GET  /qa/health``          问答链路探活（配置快照 + 主干节点 + 限流额度）
===========================  ================================================

限流：**每分钟 60 次/调用方**（:func:`~aisec_intel.api.deps.rate_limit`，超出返回 429）。

依赖全部走 ``Depends``，测试可用 ``app.dependency_overrides`` 注入桩检索服务与降级配置，
因此**不需要真实 PG / Neo4j / LLM** 即可跑通。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from aisec_intel.api.deps import (
    RATE_LIMIT_PER_MINUTE,
    get_qa_checkpointer,
    get_qa_session_factory,
    get_rate_limiter,
    get_retrieval_service,
    get_settings_dep,
    get_use_llm,
    rate_limit,
)
from aisec_intel.api.schemas.qa import AskRequest, QAHealthResponse
from aisec_intel.config import Settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.agent_io import QAResponse
from aisec_intel.qa.graph import build_qa_deps, build_qa_graph, node_sequence
from aisec_intel.security.prompt_guard import PromptInjectionError
from aisec_intel.services.alert_service import emit_alerts_safely
from aisec_intel.services.metrics_service import record_qa
from aisec_intel.services.retrieval_service import RetrievalService

logger = get_logger(__name__)

router = APIRouter(prefix="/qa", tags=["qa"])
"""问答路由（挂载后路径为 ``/api/v1/qa/...``）。"""


@router.post(
    "/ask",
    response_model=QAResponse,
    status_code=status.HTTP_200_OK,
    summary="自然语言问答（Supervisor→Reasoner→Synthesizer）",
    dependencies=[Depends(rate_limit)],
)
async def ask(
    payload: AskRequest,
    service: RetrievalService = Depends(get_retrieval_service),
    settings: Settings = Depends(get_settings_dep),
    use_llm: bool = Depends(get_use_llm),
    checkpointer: Any = Depends(get_qa_checkpointer),
    session_factory: Callable[[], Any] = Depends(get_qa_session_factory),
) -> QAResponse:
    """执行一次完整问答并返回带引用的结构化回答。

    Args:
        payload: 请求体（问题 / 会话 ID / 召回条数 / 多跳上限 / 会话历史 / trace_id）。
        service: 混合检索服务（请求级会话）。
        settings: 全局配置。
        use_llm: 是否启用 LLM。
        checkpointer: 会话检查点（同一 ``session_id`` 多轮对话用，Day12 任务 6）。
        session_factory: 外部证据落库会话工厂（Day25 受控外部检索）。

    Returns:
        :class:`QAResponse`（``answer`` + ``citations`` + ``reasoning_chain`` + ``confidence``）。
    """
    deps = build_qa_deps(
        service,
        settings=settings,
        use_llm=use_llm,
        top_k=payload.top_k,
        max_hops=payload.max_hops,
        session_factory=session_factory,
    )
    graph = build_qa_graph(
        deps, checkpointer=checkpointer, top_k=payload.top_k, max_hops=payload.max_hops
    )
    started = time.perf_counter()
    try:
        response, state = await graph.ainvoke(
            payload.query,
            thread_id=payload.session_id,
            session_context=payload.session_context or None,
        )
    except PromptInjectionError as exc:
        # Day18 任务 1/2：兜底拦截（请求体校验已拦一次；此处覆盖更深层的注入检测）
        record_qa(ok=False, duration_s=time.perf_counter() - started)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"查询被安全策略拦截：{', '.join(exc.verdict.rule_names) or 'empty_input'}",
        ) from exc
    except Exception:
        # Day17 任务 3.2：失败也计入指标（成功率口径），随后原样抛出交给统一异常处理
        record_qa(ok=False, duration_s=time.perf_counter() - started)
        emit_alerts_safely()
        raise
    duration_s = time.perf_counter() - started
    record_qa(ok=True, duration_s=duration_s, degraded=response.degraded)
    emit_alerts_safely()
    logger.info(
        f"问答完成：query={payload.query!r} 引用={len(response.citations)} "
        f"推理步={len(response.reasoning_chain)} session={payload.session_id} "
        f"会话历史={len(state.get('session_context') or [])} "
        f"degraded={response.degraded} trace={payload.trace_id} 耗时={duration_s:.2f}s"
    )
    if state.get("errors"):
        logger.warning(f"问答降级留痕：{state['errors'][:3]}")
    return response


@router.get(
    "/health",
    response_model=QAHealthResponse,
    summary="问答链路探活",
)
async def health(
    settings: Settings = Depends(get_settings_dep),
    use_llm: bool = Depends(get_use_llm),
    limiter=Depends(get_rate_limiter),
) -> QAHealthResponse:
    """返回问答链路配置快照（轻量，不触发外部调用）。

    Args:
        settings: 全局配置。
        use_llm: 是否启用 LLM。
        limiter: 限流器（读取额度用于展示）。

    Returns:
        :class:`QAHealthResponse`。
    """
    degraded = settings.degraded_mode or not use_llm
    return QAHealthResponse(
        status="degraded" if degraded else "ok",
        llm_enabled=use_llm,
        degraded_mode=settings.degraded_mode,
        vector_backend=settings.effective_vector_backend,
        neo4j_enabled=settings.neo4j_enabled,
        plan=list(node_sequence()),
        rate_limit_per_minute=limiter.limit if limiter.limit > 0 else RATE_LIMIT_PER_MINUTE,
    )
