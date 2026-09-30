"""时间归一化纯函数（PROJECT_PLAN.md §2 normalize 层 · §10.2 不变式 3）。

L2 归一化层为**纯函数层**：无 IO、无全局状态、可离线单测。本模块是全项目时间的
唯一解析入口（L1 采集器的 ``BaseConnector.to_utc_datetime`` 亦委托到这里，避免口径分叉）。
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from aisec_intel.models.base import iso_z, to_utc

__all__ = [
    "days_ago",
    "ensure_utc",
    "isoformat_z",
    "parse_datetime",
    "to_date_str",
    "to_utc",
]


def ensure_utc(value: datetime) -> datetime:
    """把 ``datetime`` 归一化为 UTC（naive 视为已是 UTC）。

    Args:
        value: 任意 ``datetime``。

    Returns:
        带 UTC 时区的 ``datetime``。
    """
    return to_utc(value)


def parse_datetime(value: datetime | date | str | int | float | None) -> datetime | None:
    """把多种时间表示解析为 UTC ``datetime``（纯函数，绝不抛异常）。

    支持：``datetime``（含 naive，视为 UTC）、``date``（当日 00:00:00Z）、
    ISO8601 字符串（含 ``Z`` 后缀与 ``+08:00`` 偏移）、Unix 时间戳（秒）。

    Args:
        value: 待解析值。

    Returns:
        UTC ``datetime``；无法解析或入参为 ``None`` 时返回 ``None``。
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    if isinstance(value, bool):  # bool 是 int 的子类，需先排除
        return None
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = value.strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        # 兜底：``YYYY/MM/DD`` 等非标准分隔符
        try:
            parsed = datetime.fromisoformat(normalized.replace("/", "-"))
        except ValueError:
            return None
    return to_utc(parsed)


def isoformat_z(value: datetime | None) -> str | None:
    """序列化为 ISO8601 UTC 字符串（``Z`` 结尾）。

    Args:
        value: 任意 ``datetime``。

    Returns:
        形如 ``2026-09-30T00:48:00Z`` 的字符串；``None`` 原样返回。
    """
    return None if value is None else iso_z(value)


def to_date_str(value: datetime | None) -> str | None:
    """取 UTC 日期部分（``YYYY-MM-DD``），供按日查询的接口使用。

    Args:
        value: 任意 ``datetime``。

    Returns:
        日期字符串；``None`` 原样返回。
    """
    return None if value is None else to_utc(value).date().isoformat()


def days_ago(days: int, *, now: datetime | None = None) -> datetime:
    """计算 ``now - days``（UTC）。

    Args:
        days: 回看天数。
        now: 基准时间；``None`` 时使用当前 UTC 时间。

    Returns:
        UTC ``datetime``。
    """
    base = to_utc(now) if now is not None else datetime.now(UTC)
    return to_utc(base - timedelta(days=days))
