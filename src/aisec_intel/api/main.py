"""FastAPI 应用入口（Day11 任务 5；PROJECT_PLAN.md §5.8 ``api/main.py``）。

职责：
    1. 创建应用与统一前缀（``/api/v1``）；
    2. 挂载各路由（当前：``qa``；P7 后续补 ``intel`` / ``cve`` / ``paper`` / ``exploit`` / ``graph``）；
    3. 统一异常处理（未捕获异常返回结构化 500，便于前端提示）。

启动::

    uvicorn aisec_intel.api.main:app --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aisec_intel.api.routers import qa, vulns
from aisec_intel.config import get_settings
from aisec_intel.logging_config import get_logger

logger = get_logger(__name__)

API_PREFIX: str = "/api/v1"
"""统一路由前缀（与 ``.env`` 的 ``API_BASE_URL`` 保持一致）。"""


def create_app() -> FastAPI:
    """创建 FastAPI 应用（工厂函数，便于测试与多实例）。

    Returns:
        配置完成的 :class:`fastapi.FastAPI` 实例。
    """
    settings = get_settings()
    app = FastAPI(
        title="智能体驱动的 AI 安全知识情报系统",
        version="0.1.0",
        description="L4 问答层 API（Supervisor → Reasoner → Synthesizer，引用可回溯）",
    )
    app.include_router(qa.router, prefix=API_PREFIX)
    app.include_router(vulns.router, prefix=API_PREFIX)
    logger.info(
        f"API 已装配：prefix={API_PREFIX} "
        f"routes=/qa/ask,/qa/health,/vulnerabilities,/vulnerabilities/{{cve_id}} | env={settings.app_env}"
    )

    @app.get("/healthz", tags=["ops"], summary="进程探活")
    async def healthz() -> dict[str, str]:
        """进程级探活（不依赖任何中间件）。

        Returns:
            形如 ``{"status": "ok"}``。
        """
        return {"status": "ok"}

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
