"""采集层原始件契约（PROJECT_PLAN.md §10.1 ①，Day1 冻结）。

冻结不变式（§10.2）：字段名 / 类型 / 语义不得修改；新增字段必须带默认值并递增
``schema_version``。修改前必须走 §10.3 变更流程。
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ConfigDict, Field

from aisec_intel.models.base import (
    SCHEMA_VERSION,
    IntelBaseModel,
    OptionalUTCDateTime,
    UTCDateTime,
)


class RawItem(IntelBaseModel):
    """L1 采集层输出的原始情报件。

    由 ``BaseConnector`` 子类产出，是 L1 交付给 L2 归一化层的**唯一**格式。
    本模型只承载「事实」，不包含任何推断或补全结论。

    Attributes:
        schema_version: 契约版本号，变更必须 bump。
        trace_id: 全链路追踪 ID（uuid4），贯穿归一化 / 富化 / 问答。
        source: 源标识，如 ``nvd`` / ``osv`` / ``ghsa`` / ``kev`` / ``epss`` / ``arxiv``。
        source_id: 源内唯一 ID（CVE ID / GHSA ID / arXiv ID）。
        url: 原文链接，引用回溯的最终依据。
        title: 标题（RSS / 厂商公告类），可为空。
        raw_text: 原文正文或描述，保真保存，不做语义裁剪。
        lang: 语言标识（``zh`` / ``en``）。
        published_at: 源发布时间（UTC），源未提供时为空。
        fetched_at: 采集时间（UTC）。
        sha256: ``raw_text`` 的内容指纹，用于幂等 upsert 与去重。
        meta: 源特有附加字段（扁平字符串键值对，如 ``nvd_status``）。
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=SCHEMA_VERSION, description="契约版本号，变更必须 bump")
    trace_id: str = Field(min_length=1, description="全链路追踪 ID（uuid4）")
    source: str = Field(min_length=1, description="源标识：nvd/osv/ghsa/kev/epss/arxiv/...")
    source_id: str = Field(min_length=1, description="源内唯一 ID（CVE ID / GHSA ID / arXiv ID）")
    url: str = Field(min_length=1, description="原文链接，引用回溯的最终依据")
    title: str | None = Field(default=None, description="标题（RSS / 厂商公告类）")
    raw_text: str = Field(description="原文正文/描述，保真保存，不做语义裁剪")
    lang: str | None = Field(default=None, description="语言标识：zh / en / ...")
    published_at: OptionalUTCDateTime = Field(default=None, description="源发布时间（UTC）")
    fetched_at: UTCDateTime = Field(description="采集时间（UTC）")
    sha256: str = Field(description="raw_text 的内容指纹，用于幂等 upsert 与去重")
    meta: dict[str, str] = Field(default_factory=dict, description="源特有附加字段（扁平字符串）")

    @property
    def payload(self) -> dict[str, Any] | None:
        """把 ``raw_text`` 解析为 JSON 对象（便捷访问器，**非契约字段**）。

        多数源（NVD/OSV/GHSA/KEV/EPSS）的 ``raw_text`` 是条目级保真 JSON，
        L2 归一化层需要一个统一入口把它取回为 dict。

        Returns:
            ``raw_text`` 为 JSON 对象时返回解析结果；否则返回 ``None``。
        """
        try:
            parsed = json.loads(self.raw_text)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    @property
    def source_key(self) -> str:
        """源内主键的规范化写法（``source:source_id``），便于日志与图节点命名。"""
        return f"{self.source}:{self.source_id}"
