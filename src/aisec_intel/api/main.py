"""FastAPI 应用入口（Day11 任务 5；PROJECT_PLAN.md §5.8 ``api/main.py``）。

职责：
    1. 创建应用与统一前缀（``/api/v1``）；
    2. 挂载各路由：``qa`` / ``vulnerabilities`` / ``stats`` / ``graph`` / ``data-quality`` /
       ``papers``（Day17 任务 2）；
    3. 运维端点：``/healthz``（进程 + 组件健康）、``/readyz``（就绪探针）、
       ``/metrics``（Prometheus 文本格式，Day17 任务 3）；
    4. 统一异常处理（未捕获异常返回结构化 500，便于前端提示）；
    5. 启动时初始化结构化日志（JSON + ``logs/app.log`` 滚动，Day17 任务 3.1）。

启动::

    uvicorn aisec_intel.api.main:app --port 8000
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, PlainTextResponse

from aisec_intel.api.routers import graph, papers, qa, quality, stats, vulns
from aisec_intel.config import get_settings
from aisec_intel.logging_config import configure_logging, get_logger, trace_context
from aisec_intel.models.base import iso_z, utc_now
from aisec_intel.services.health_service import check_all, overall_status
from aisec_intel.services.metrics_service import METRICS

logger = get_logger(__name__)

API_PREFIX: str = "/api/v1"
"""统一路由前缀（与 ``.env`` 的 ``API_BASE_URL`` 保持一致）。"""

TRACE_ID_HEADER: str = "X-Trace-Id"
"""请求 / 响应头中的追踪 ID 名（缺失时自动生成，并在响应头回传）。"""


def _components_payload(components: list[Any]) -> dict[str, dict[str, object]]:
    """把组件健康列表装为 ``{组件名: 状态}``（纯函数，``/healthz`` 与 ``/readyz`` 共用）。

    Args:
        components: :class:`~aisec_intel.services.health_service.ComponentHealth` 列表。

    Returns:
        组件名 → 状态字典。
    """
    return {component.name: component.as_dict() for component in components}


def create_app() -> FastAPI:
    """创建 FastAPI 应用（工厂函数，便于测试与多实例）。

    Returns:
        配置完成的 :class:`fastapi.FastAPI` 实例。
    """
    settings = get_settings()
    # Day17 任务 3.1：统一 JSON 日志格式 + 滚动写入 logs/app.log（按 trace_id 串联全链路）
    configure_logging(settings.log_level, json_output=settings.log_json, log_file=settings.log_file_path)
    app = FastAPI(
        title="智能体驱动的 AI 安全知识情报系统",
        version="0.1.0",
        description="L4 问答层 API（Supervisor → Reasoner → Synthesizer，引用可回溯）",
    )
    app.include_router(qa.router, prefix=API_PREFIX)
    app.include_router(vulns.router, prefix=API_PREFIX)
    app.include_router(stats.router, prefix=API_PREFIX)
    app.include_router(graph.router, prefix=API_PREFIX)
    app.include_router(quality.router, prefix=API_PREFIX)
    app.include_router(papers.router, prefix=API_PREFIX)

    @app.middleware("http")
    async def trace_id_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """为每个请求绑定 ``trace_id``（Day17 任务 3.1：按 ``trace_id`` 串联全链路）。

        取值优先级：``X-Trace-Id`` 请求头（前端 / 网关注入）→ 自动生成；
        处理期间该请求的所有日志都会带上同一个 ``trace_id``，并把值回写到响应头，
        便于前端把「一次点击」与后端日志精确对齐。

        Args:
            request: 当前请求。
            call_next: 下游 ASGI 处理链。

        Returns:
            下游响应（附加 ``X-Trace-Id`` 响应头）。
        """
        incoming = request.headers.get(TRACE_ID_HEADER, "").strip()
        with trace_context(incoming or None) as trace_id:
            response = await call_next(request)
        response.headers[TRACE_ID_HEADER] = trace_id
        return response

    logger.info(
        f"API 已装配：prefix={API_PREFIX} "
        f"routes=/qa/ask,/qa/health,/vulnerabilities,/vulnerabilities/{{cve_id}},/stats,"
        f"/graph,/graph/{{cve_id}},/data-quality,/papers/{{paper_id}} "
        f"| ops=/healthz,/readyz,/metrics | env={settings.app_env}"
    )

    @app.get("/healthz", tags=["ops"], summary="进程探活 + 组件健康（PG/Neo4j/Chroma/LLM）")
    async def healthz() -> dict[str, Any]:
        """进程级探活 + 依赖组件健康（Day17 任务 3.4）。

        Returns:
            形如 ``{"status": "ok|degraded|error", "components": {...}, "checked_at": "..."}``；
            ``status`` 为 ``error`` 表示硬依赖（PostgreSQL）不可用。
        """
        components = await check_all(settings)
        return {
            "status": overall_status(components),
            "components": _components_payload(components),
            "checked_at": iso_z(utc_now()),
        }

    @app.get("/readyz", tags=["ops"], summary="就绪探针（硬依赖不可用时 503）")
    async def readyz(response: Response) -> dict[str, Any]:
        """就绪探针：PostgreSQL（硬依赖）不可用时返回 503，供编排层限流 / 摘流。

        Args:
            response: 用于按需改写状态码的响应对象。

        Returns:
            ``{"status": "ready"|"not_ready", "components": {...}, "checked_at": "..."}``。
        """
        components = await check_all(settings)
        verdict = overall_status(components)
        ready = verdict != "error"
        if not ready:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "ready" if ready else "not_ready",
            "components": _components_payload(components),
            "checked_at": iso_z(utc_now()),
        }

    @app.get("/metrics", tags=["ops"], summary="Prometheus 指标（文本格式）", response_class=PlainTextResponse)
    async def metrics() -> PlainTextResponse:
        """导出 Prometheus 文本指标（Day17 任务 3.2）。

        Returns:
            ``text/plain; version=0.0.4`` 格式的指标文本。
        """
        return PlainTextResponse(METRICS.render_prometheus(), media_type="text/plain; version=0.0.4")

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """统一兜底异常处理（不泄露堆栈细节，但留痕到日志）。

        Args:
            request: 当前请求。
            exc: 未捕获异常。

        Returns:
            结构化 500 响应。
        """
        logger.error(f"未捕获异常：{request.method} {request.url.path} → {type(exc).__name__}: {exc}")
        return JSONResponse(
            status_code=500,
            content={"detail": f"服务内部错误（{type(exc).__name__}），请查看服务端日志"},
        )

    return app


app = create_app()
"""ASGI 应用实例（``uvicorn aisec_intel.api.main:app``）。"""
