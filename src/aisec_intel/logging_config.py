"""结构化日志与 ``trace_id`` 上下文（PROJECT_PLAN.md §1.3 可观测性）。

设计要点：
    1. ``trace_id`` 通过 ``contextvars`` 传递，异步任务与 LangGraph 节点间自动继承；
    2. 所有日志记录自动带上 ``trace_id`` 字段，便于前端「采集运维」页按链路检索；
    3. 默认输出 JSON 单行日志（``configure_logging`(json_output=True)``），便于采集与检索；
    4. **禁止在日志中输出密钥**：配置对象统一走 ``Settings.masked()``。
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Final

from aisec_intel.models.base import iso_z, new_trace_id, utc_now

_TRACE_ID: ContextVar[str] = ContextVar("aisec_trace_id", default="-")
"""当前上下文的 ``trace_id``；未显式绑定时为 ``"-"``。"""

TRACE_ID_FIELD: Final[str] = "trace_id"
"""日志记录中承载 ``trace_id`` 的字段名。"""

_DEFAULT_FORMAT: Final[str] = "%(asctime)s %(levelname)-7s [%(trace_id)s] %(name)s: %(message)s"


def get_trace_id() -> str:
    """读取当前上下文的 ``trace_id``。

    Returns:
        当前 ``trace_id``；未绑定时返回 ``"-"``。
    """
    return _TRACE_ID.get()


def bind_trace_id(trace_id: str) -> Token[str]:
    """绑定 ``trace_id`` 到当前上下文。

    Args:
        trace_id: 待绑定的追踪 ID。

    Returns:
        ``contextvars.Token``，可用于 ``_TRACE_ID.reset(token)`` 恢复现场。
    """
    return _TRACE_ID.set(trace_id)


def create_trace_id() -> str:
    """生成并绑定一个新的 ``trace_id``。

    Returns:
        新生成的 ``trace_id``。
    """
    trace_id = new_trace_id()
    bind_trace_id(trace_id)
    return trace_id


@contextmanager
def trace_context(trace_id: str | None = None) -> Iterator[str]:
    """在上下文管理器中绑定 ``trace_id``（退出时自动恢复）。

    Args:
        trace_id: 指定追踪 ID；为 ``None`` 时自动生成。

    Yields:
        本次上下文生效的 ``trace_id``。

    Examples:
        >>> with trace_context("abc123") as tid:
        ...     assert tid == "abc123"
        ...     assert get_trace_id() == "abc123"
    """
    resolved = trace_id or new_trace_id()
    token = bind_trace_id(resolved)
    try:
        yield resolved
    finally:
        _TRACE_ID.reset(token)


class TraceIdFilter(logging.Filter):
    """为每条日志记录注入 ``trace_id`` 字段。"""

    def filter(self, record: logging.LogRecord) -> bool:
        """填充 ``record.trace_id``。

        Args:
            record: 待处理的日志记录。

        Returns:
            恒为 ``True``（不过滤任何记录）。
        """
        record.trace_id = get_trace_id()
        return True


class JsonFormatter(logging.Formatter):
    """把日志记录格式化为单行 JSON。"""

    def format(self, record: logging.LogRecord) -> str:
        """序列化日志记录。

        Args:
            record: 待格式化的日志记录。

        Returns:
            单行 JSON 字符串，字段：``ts`` / ``level`` / ``logger`` / ``trace_id`` / ``msg``。
        """
        payload: dict[str, Any] = {
            "ts": iso_z(utc_now()),
            "level": record.levelname,
            "logger": record.name,
            "trace_id": getattr(record, TRACE_ID_FIELD, "-"),
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(
    level: str = "INFO",
    *,
    json_output: bool = True,
    stream: Any = None,
    force: bool = False,
) -> None:
    """初始化根 logger（幂等）。

    Args:
        level: 日志级别名（``DEBUG`` / ``INFO`` / ``WARNING`` / ...）。
        json_output: ``True`` 输出 JSON 单行日志，``False`` 输出人读格式。
        stream: 输出流，默认 ``sys.stdout``。
        force: ``True`` 时移除既有 handler 重新配置（测试用）。
    """
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.addFilter(TraceIdFilter())
    handler.setFormatter(
        JsonFormatter() if json_output else logging.Formatter(_DEFAULT_FORMAT, datefmt="%Y-%m-%dT%H:%M:%SZ")
    )

    root = logging.getLogger()
    if force:
        for existing in list(root.handlers):
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    """获取带 ``trace_id`` 过滤能力的 logger。

    Args:
        name: logger 名称，约定使用 ``__name__``。

    Returns:
        已挂载 ``TraceIdFilter`` 的 logger（若根 logger 尚未配置，则先按默认参数配置）。
    """
    if not logging.getLogger().handlers:
        configure_logging()
    logger = logging.getLogger(name)
    if not any(isinstance(f, TraceIdFilter) for f in logger.filters):
        logger.addFilter(TraceIdFilter())
    return logger
