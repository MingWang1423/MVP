"""模型基类与时间工具（PROJECT_PLAN.md §10.2 不变式 3 / 6）。

本模块是 ``models`` 包内所有 Pydantic 模型的公共底座，提供：

1. ``IntelBaseModel``：统一 ``extra="forbid"``（禁止未声明字段，防止 LLM 自由字段污染库）。
2. ``UTCDateTime`` / ``OptionalUTCDateTime``：时间字段统一 UTC 语义，并序列化为 ISO8601 ``Z`` 结尾。
3. ``utc_now`` / ``new_trace_id``：全项目唯一的时间与追踪 ID 来源。
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, PlainSerializer

SCHEMA_VERSION: str = "1.0"
"""当前接口契约版本；任何字段变更都必须遵循 §10.3 流程并递增该版本。"""


def utc_now() -> datetime:
    """返回带 UTC 时区的当前时间。

    Returns:
        带 ``datetime.UTC`` 时区的 ``datetime``，作为全项目统一时间来源。

    Examples:
        >>> utc_now().tzinfo is not None
        True
    """
    return datetime.now(UTC)


def to_utc(value: datetime) -> datetime:
    """把任意 ``datetime`` 归一化为 UTC。

    naive 时间视为「其本身即 UTC」（时区缺失由上游数据源决定，最终修正责任在 L2 归一化层）。

    Args:
        value: 待归一化的时间。

    Returns:
        带 UTC 时区的时间。
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _to_utc_optional(value: datetime | None) -> datetime | None:
    """``to_utc`` 的可空版本。"""
    return None if value is None else to_utc(value)


def iso_z(value: datetime) -> str:
    """序列化为 ISO8601 UTC 字符串（以 ``Z`` 结尾）。

    Args:
        value: 任意时间。

    Returns:
        形如 ``2026-09-30T00:48:00Z`` 的字符串（§10.2 不变式 3）。
    """
    return to_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _iso_z_optional(value: datetime | None) -> str | None:
    """``iso_z`` 的可空版本。"""
    return None if value is None else iso_z(value)


def new_trace_id() -> str:
    """生成全链路追踪 ID。

    Returns:
        uuid4 的 32 位十六进制字符串，写入 ``RawItem.trace_id`` 后贯穿全链路（§10.2 不变式 5）。
    """
    return uuid.uuid4().hex


UTCDateTime = Annotated[
    datetime,
    AfterValidator(to_utc),
    PlainSerializer(iso_z, return_type=str, when_used="json"),
]
"""必填 UTC 时间字段：输入自动归一化为 UTC，JSON 输出为 ISO8601 ``Z``。"""


OptionalUTCDateTime = Annotated[
    datetime | None,
    AfterValidator(_to_utc_optional),
    PlainSerializer(_iso_z_optional, return_type=str | None, when_used="json"),
]
"""可空 UTC 时间字段：语义同 ``UTCDateTime``，允许 ``None``。"""


class IntelBaseModel(BaseModel):
    """全项目 Pydantic 模型基类。

    统一开启严格字段校验（``extra="forbid"``），确保任何未声明字段在实例化时立即失败；
    子类如需更强约束（如 ``frozen=True``）可在自身 ``model_config`` 中覆盖。
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        populate_by_name=True,
        arbitrary_types_allowed=False,
    )
