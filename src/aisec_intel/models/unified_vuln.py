"""归一化层统一漏洞实体契约（PROJECT_PLAN.md §10.1 ②，Day1 冻结）。

本模块定义 L2 归一化层的输出结构。归一化层为**纯函数、禁止 LLM**（§0 约束 1 / 5），
因此本模块中的任何字段都必须来自源数据的事实抽取，不含推断性结论。
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from aisec_intel.models.base import (
    SCHEMA_VERSION,
    IntelBaseModel,
    OptionalUTCDateTime,
    UTCDateTime,
)

Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
"""CVSS 严重度等级（v2 为 LOW/MEDIUM/HIGH；v3+ 增加 NONE/CRITICAL）。"""


class CVSSVector(IntelBaseModel):
    """单个 CVSS 评分向量。

    Attributes:
        version: CVSS 版本，取值 ``2.0`` / ``3.0`` / ``3.1`` / ``4.0``。
        vector: 完整向量串，如 ``CVSS:3.1/AV:N/AC:L/...``。
        base_score: 基础分，取值区间 ``[0.0, 10.0]``。
        severity: 严重度等级。
    """

    model_config = ConfigDict(extra="forbid")

    version: Literal["2.0", "3.0", "3.1", "4.0"] = Field(description="CVSS 版本")
    vector: str = Field(description="完整向量串")
    base_score: float = Field(ge=0.0, le=10.0, description="基础分")
    severity: Severity = Field(description="严重度等级")


class CpeMatch(IntelBaseModel):
    """CPE 2.3 匹配条目（受影响版本区间）。

    Attributes:
        vendor: 厂商（CPE 第 3 段）。
        product: 产品（CPE 第 4 段）。
        version_start_incl: 受影响区间起始版本（含）。
        version_start_excl: 受影响区间起始版本（不含）。
        version_end_incl: 受影响区间结束版本（含）。
        version_end_excl: 受影响区间结束版本（不含）。
        vulnerable: 该区间是否为「受影响」。
    """

    model_config = ConfigDict(extra="forbid")

    vendor: str
    product: str
    version_start_incl: str | None = None
    version_start_excl: str | None = None
    version_end_incl: str | None = None
    version_end_excl: str | None = None
    vulnerable: bool = True


class Reference(IntelBaseModel):
    """外部参考链接。

    Attributes:
        url: 链接地址。
        source: 链接来源（``nvd`` / ``ghsa`` / ``vendor`` / ...）。
        tags: 标签，如 ``patch`` / ``exploit`` / ``vendor-advisory``。
    """

    model_config = ConfigDict(extra="forbid")

    url: str
    source: str = Field(description="链接来源：nvd/ghsa/vendor/...")
    tags: list[str] = Field(default_factory=list, description="如 patch / exploit / vendor-advisory")


class UnifiedVuln(IntelBaseModel):
    """L2 归一化输出：多源合并后的统一漏洞实体。

    不含任何推断性结论（推断属于 L3 富化层职责，见 ``EnrichedVuln``）。

    Attributes:
        schema_version: 契约版本号。
        vuln_id: 规范主键，形如 ``CVE-2024-3400``（大小写与连字符已规范化）。
        aliases: 跨源别名（GHSA / OSV / CNVD 等）。
        trace_ids: 贡献该实体的 ``RawItem.trace_id`` 列表（§10.2 不变式 5）。
        title: 标题，源未提供时为空。
        description: 清洗后的描述文本。
        lang: 描述语言。
        cvss: CVSS 向量列表，按版本升序。
        cwe_ids: CWE 编号列表，如 ``CWE-78``。
        cpe_matches: 受影响 CPE 区间列表。
        ecosystem_packages: OSV 生态包标识，如 ``PyPI:django``。
        references: 外部参考链接。
        kev: 是否进入 CISA KEV 已知被利用目录。
        epss_score: FIRST EPSS 利用概率，区间 ``[0.0, 1.0]``。
        epss_percentile: FIRST EPSS 百分位，区间 ``[0.0, 1.0]``。
        published_at: 公开发布时间（UTC）。
        modified_at: 最近修改时间（UTC）。
        sources: 贡献该实体的源列表（并集）。
        normalized_at: 归一化完成时间（UTC）。
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default=SCHEMA_VERSION)
    vuln_id: str = Field(min_length=1, description="规范主键，形如 CVE-2024-3400（大写、连字符）")
    aliases: list[str] = Field(default_factory=list, description="GHSA/OSV/CNVD 等别名")
    trace_ids: list[str] = Field(default_factory=list, description="关联的 RawItem.trace_id 列表")
    title: str | None = None
    description: str = Field(description="清洗后的描述文本（英文原样或中英并存）")
    lang: str | None = None
    cvss: list[CVSSVector] = Field(default_factory=list, description="按版本升序排列")
    cwe_ids: list[str] = Field(default_factory=list, description="如 CWE-78")
    cpe_matches: list[CpeMatch] = Field(default_factory=list)
    ecosystem_packages: list[str] = Field(default_factory=list, description="OSV 生态包，如 PyPI:django")
    references: list[Reference] = Field(default_factory=list)
    kev: bool = Field(default=False, description="是否进入 CISA KEV 已知被利用目录")
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0, description="FIRST EPSS 概率")
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    published_at: OptionalUTCDateTime = Field(default=None, description="UTC")
    modified_at: OptionalUTCDateTime = Field(default=None, description="UTC")
    sources: list[str] = Field(default_factory=list, description="贡献该实体的源列表（并集）")
    normalized_at: UTCDateTime = Field(description="归一化时间（UTC）")
