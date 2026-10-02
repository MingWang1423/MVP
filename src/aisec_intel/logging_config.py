"""结构化日志与 ``trace_id`` 上下文（PROJECT_PLAN.md §1.3 可观测性）。

设计要点：
    1. ``trace_id`` 通过 ``contextvars`` 传递，异步任务与 LangGraph 节点间自动继承；
    2. 所有日志记录自动带上 ``trace_id`` 字段，便于前端「采集运维」页按链路检索；
    3. 默认输出 JSON 单行日志（``configure_logging`(json_output=True)``），便于采集与检索；
    4. **禁止在日志中输出密钥**：配置对象统一走 ``Settings.masked()``。

Day17 任务 3.1（日志聚合）扩展：
    1. 统一 JSON 字段集 —— ``ts`` / ``level`` / ``logger`` / ``trace_id`` / ``msg`` /
       可选 ``event``（事件名）/ ``details``（结构化上下文）；
    2. 支持**滚动文件**输出（``logs/app.log``，:class:`~logging.handlers.RotatingFileHandler`）；
    3. :func:`attach_file_handler` 供「告警日志」「自愈日志」挂独立滚动文件；
    4. :func:`log_event` 统一事件日志写法（采集 / 富化 / 问答 / 自愈 / 告警共用）。
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Any, Final

from aisec_intel.models.base import iso_z, new_trace_id, utc_now

_TRACE_ID: ContextVar[str] = ContextVar("aisec_trace_id", default="-")
"""当前上下文的 ``trace_id``；未显式绑定时为 ``"-"``。"""

TRACE_ID_FIELD: Final[str] = "trace_id"
"""日志记录中承载 ``trace_id`` 的字段名。"""

EVENT_FIELD: Final[str] = "event"
"""日志记录中承载「事件名」的字段名（如 ``collect.retry`` / ``alert.fired``）。"""

DETAILS_FIELD: Final[str] = "details"
"""日志记录中承载结构化上下文的字段名（JSON 对象）。"""

DEFAULT_LOG_MAX_BYTES: int = 5_000_000
"""单个日志文件滚动阈值（字节，默认约 5 MB）。"""

DEFAULT_LOG_BACKUP_COUNT: int = 5
"""滚动日志保留的备份份数。"""

_DEFAULT_FORMAT: Final[str] = "%(asctime)s %(levelname)-7s [%(trace_id)s] %(name)s: %(message)s"


def _is_our_handler(handler: logging.Handler, *, target: str | None) -> bool:
    """判断 handler 是否由本模块创建且指向同一个目标文件（幂等配置用）。

    Args:
        handler: 待判断的 handler。
        target: 目标文件绝对路径；``None`` 表示匹配标准输出 handler。

    Returns:
        命中返回 ``True``。
    """
    if target is None:
        return isinstance(handler, logging.StreamHandler) and not isinstance(
            handler, logging.FileHandler
        )
    return isinstance(handler, logging.FileHandler) and getattr(handler, "baseFilename", "") == target


def make_formatter(*, json_output: bool = True) -> logging.Formatter:
    """构造统一日志格式化器（JSON 或人读格式）。

    Args:
        json_output: ``True`` 返回 :class:`JsonFormatter`，否则返回带 ``trace_id`` 的文本格式。

    Returns:
        可直接挂到 handler 上的格式化器。
    """
    if json_output:
        return JsonFormatter()
    return logging.Formatter(_DEFAULT_FORMAT, datefmt="%Y-%m-%dT%H:%M:%SZ")



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
        event = getattr(record, EVENT_FIELD, None)
        if event:
            payload[EVENT_FIELD] = str(event)
        details = getattr(record, DETAILS_FIELD, None)
        if isinstance(details, dict) and details:
            payload[DETAILS_FIELD] = details
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    message: str | None = None,
    **details: Any,
) -> None:
    """输出一条「事件日志」（统一带 ``event`` 与 ``details`` 字段）。

    Args:
        logger: 目标 logger。
        event: 事件名，约定 ``<域>.<动作>``（如 ``collect.retry`` / ``qa.degrade``）。
        level: 日志级别（默认 ``INFO``）。
        message: 人类可读文案；``None`` 时使用 ``event``。
        **details: 结构化上下文（仅放可 JSON 序列化的标量 / 列表 / 字典）。
    """
    logger.log(level, message or event, extra={EVENT_FIELD: event, DETAILS_FIELD: details})


def attach_file_handler(
    logger_name: str,
    path: str | Path,
    *,
    json_output: bool = True,
    level: str = "INFO",
    max_bytes: int = DEFAULT_LOG_MAX_BYTES,
    backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
) -> logging.handlers.RotatingFileHandler | None:
    """给指定 logger 挂一个滚动文件 handler（幂等；路径不可写时降级）。

    Args:
        logger_name: logger 名称（如 ``aisec_intel.alerts``）。
        path: 日志文件路径（父目录自动创建）。
        json_output: 是否输出 JSON 单行日志。
        level: 该 handler 与 logger 的级别。
        max_bytes: 单文件滚动阈值（字节）。
        backup_count: 保留的备份份数。

    Returns:
        挂载成功的 handler；路径不可写时返回 ``None``（仅控制台输出，不影响主流程）。
    """
    target = os.path.abspath(str(path))
    logger = logging.getLogger(logger_name)
    for existing in logger.handlers:
        if _is_our_handler(existing, target=target):
            return existing  # type: ignore[return-value]
    try:
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            target, maxBytes=max(1, max_bytes), backupCount=max(0, backup_count), encoding="utf-8", delay=True
        )
    except OSError as exc:  # pragma: no cover - 只读文件系统 / 权限不足
        logger.warning(f"日志文件不可写，已降级为仅控制台输出：{target}（{type(exc).__name__}: {exc}）")
        return None
    handler.setLevel(level.upper())
    handler.addFilter(TraceIdFilter())
    handler.setFormatter(make_formatter(json_output=json_output))
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    # 专属文件 logger 不再向 root 传播：避免同一条记录既写文件又写控制台
    logger.propagate = False
    return handler


def configure_logging(
    level: str = "INFO",
    *,
    json_output: bool = True,
    stream: Any = None,
    force: bool = False,
    log_file: str | Path | None = None,
    max_bytes: int = DEFAULT_LOG_MAX_BYTES,
    backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
) -> None:
    """初始化根 logger（幂等）。

    Args:
        level: 日志级别名（``DEBUG`` / ``INFO`` / ``WARNING`` / ...）。
        json_output: ``True`` 输出 JSON 单行日志，``False`` 输出人读格式。
        stream: 输出流，默认 ``sys.stdout``。
        force: ``True`` 时移除既有 handler 重新配置（测试用）。
        log_file: 滚动日志文件路径（Day17 任务 3.1 日志聚合）；``None`` 时仅输出到 ``stream``。
        max_bytes: 单文件滚动阈值（字节）。
        backup_count: 保留的备份份数。
    """
    root = logging.getLogger()
    if force:
        for existing in list(root.handlers):
            root.removeHandler(existing)

    if not any(_is_our_handler(handler, target=None) for handler in root.handlers):
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.addFilter(TraceIdFilter())
        handler.setFormatter(make_formatter(json_output=json_output))
        root.addHandler(handler)

    if log_file is not None:
        target = os.path.abspath(str(log_file))
        if not any(_is_our_handler(handler, target=target) for handler in root.handlers):
            try:
                Path(target).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.handlers.RotatingFileHandler(
                    target,
                    maxBytes=max(1, max_bytes),
                    backupCount=max(0, backup_count),
                    encoding="utf-8",
                    delay=True,
                )
            except OSError as exc:  # pragma: no cover - 只读文件系统 / 权限不足
                logging.getLogger(__name__).warning(
                    f"日志文件不可写，已降级为仅控制台输出：{target}（{type(exc).__name__}: {exc}）"
                )
            else:
                file_handler.addFilter(TraceIdFilter())
                file_handler.setFormatter(make_formatter(json_output=json_output))
                root.addHandler(file_handler)

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
