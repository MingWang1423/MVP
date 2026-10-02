"""后端 API 客户端（PROJECT_PLAN.md §5.9 ``frontend/api_client.py``，Day12 任务 4）。

前端只消费 API（§2.1：``frontend/`` 层禁止 LLM、禁止直连库），本模块是**唯一出口**：

- 统一 ``API_BASE_URL``（默认 ``http://localhost:8000/api/v1``，可用环境变量覆盖）；
- 统一超时与错误提示（:class:`ApiError`，前端捕获后 ``st.error``）；
- 只做「请求 + JSON 解析」，不含业务判断。

Note:
    不 import ``aisec_intel``——前端镜像只装 ``requirements.txt`` 里的依赖，
    保证 ``streamlit run frontend/app.py`` 在独立环境也能跑。
"""

from __future__ import annotations

import os
from typing import Any

import requests

DEFAULT_BASE_URL: str = "http://localhost:8000/api/v1"
"""默认 API 前缀（与 ``.env`` 的 ``API_BASE_URL`` 一致）。"""

DEFAULT_TIMEOUT_S: float = 30.0
"""单请求超时（秒）；问答链路含多跳推理，给到 30s。"""


class ApiError(RuntimeError):
    """API 调用失败（网络 / 超时 / 非 2xx），携带可直接展示给用户的文案。"""


def base_url() -> str:
    """返回当前 API 前缀（环境变量 ``API_BASE_URL`` 优先）。

    Returns:
        形如 ``http://localhost:8000/api/v1`` 的地址（末尾无斜杠）。
    """
    return os.getenv("API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    """执行 GET 请求并解析 JSON。

    Args:
        path: 相对路径（如 ``/vulnerabilities``）。
        params: 查询参数（``None`` 值会被丢弃）。

    Returns:
        解析后的 JSON（dict / list）。

    Raises:
        ApiError: 网络异常、超时或非 2xx 响应。
    """
    clean = {key: value for key, value in (params or {}).items() if value not in (None, "", [])}
    url = f"{base_url()}{path}"
    try:
        response = requests.get(url, params=clean, timeout=DEFAULT_TIMEOUT_S)
    except requests.RequestException as exc:  # 网络/超时统一转为可读错误
        raise ApiError(f"无法连接后端 {url}：{type(exc).__name__}（请确认 API 已启动）") from exc
    if response.status_code >= 400:
        raise ApiError(f"后端返回 {response.status_code}：{_detail(response)}")
    return response.json()


def _post(path: str, payload: dict[str, Any]) -> Any:
    """执行 POST 请求并解析 JSON。

    Args:
        path: 相对路径（如 ``/qa/ask``）。
        payload: JSON 请求体。

    Returns:
        解析后的 JSON 字典。

    Raises:
        ApiError: 网络异常、超时或非 2xx 响应。
    """
    url = f"{base_url()}{path}"
    try:
        response = requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT_S)
    except requests.RequestException as exc:
        raise ApiError(f"无法连接后端 {url}：{type(exc).__name__}") from exc
    if response.status_code >= 400:
        raise ApiError(f"后端返回 {response.status_code}：{_detail(response)}")
    return response.json()


def _detail(response: requests.Response) -> str:
    """从错误响应中提取可展示的 ``detail`` 字段。

    Args:
        response: 错误响应。

    Returns:
        后端 ``detail`` 文本；解析失败时回退为响应文本前 200 字。
    """
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    detail = body.get("detail") if isinstance(body, dict) else None
    return str(detail) if detail else str(body)[:200]


def health() -> dict[str, Any]:
    """探活问答链路（``GET /qa/health``）。

    Returns:
        链路快照（``status`` / ``llm_enabled`` / ``plan`` …）。
    """
    return _get("/qa/health")


def list_vulnerabilities(
    *,
    severity: str | None = None,
    source: str | None = None,
    days: int | None = None,
    kev_only: bool = False,
    limit: int = 20,
    offset: int = 0,
) -> dict[str, Any]:
    """查询漏洞列表（``GET /vulnerabilities``）。

    Args:
        severity: 严重度过滤（CRITICAL/HIGH/MEDIUM/LOW）。
        source: 数据源过滤（nvd/osv/ghsa/kev/epss...）。
        days: 最近 N 天。
        kev_only: 仅 CISA KEV 条目。
        limit: 单页条数。
        offset: 分页偏移。

    Returns:
        ``{"items": [...], "total": int, "limit": int, "offset": int}``。
    """
    return _get(
        "/vulnerabilities",
        {
            "severity": severity,
            "source": source,
            "days": days,
            "kev_only": kev_only,
            "limit": limit,
            "offset": offset,
        },
    )


def get_vulnerability(cve_id: str) -> dict[str, Any]:
    """查询漏洞详情（``GET /vulnerabilities/{cve_id}``）。

    Args:
        cve_id: 漏洞主键（大小写不敏感）。

    Returns:
        ``{"unified": {...}, "enriched": {...} | None}``。
    """
    return _get(f"/vulnerabilities/{cve_id.strip()}")


def ask(
    query: str,
    *,
    session_id: str | None = None,
    session_context: list[str] | None = None,
    top_k: int = 8,
    max_hops: int = 2,
) -> dict[str, Any]:
    """发起问答（``POST /qa/ask``）。

    Args:
        query: 自然语言问题。
        session_id: 多轮会话 ID；传同一值即多轮对话（Day12 任务 6）。
        session_context: 显式会话历史（一般留空，由服务端按 ``session_id`` 还原）。
        top_k: 单路召回条数。
        max_hops: 多跳上限。

    Returns:
        ``{"answer": ..., "citations": [...], "reasoning_chain": [...], "confidence": ...}``。
    """
    payload: dict[str, Any] = {"query": query, "top_k": top_k, "max_hops": max_hops}
    if session_id:
        payload["session_id"] = session_id
    if session_context:
        payload["session_context"] = session_context
    return _post("/qa/ask", payload)
