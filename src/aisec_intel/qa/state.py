"""问答图状态与 L4 契约模型（PROJECT_PLAN.md §5.8 ``qa/state.py``）。

本模块定义问答层（L4）的**唯一状态对象与跨 Agent 契约**：

``QAState``（TypedDict）
    LangGraph 在 ``query_understander → supervisor → 三路检索 → reasoner → citation``
    之间传递的共享状态；中间结果显式入状态，便于回溯与断点续跑。

``QueryIntent``
    查询理解 Agent 的结构化输出（§3.2 闸门①：``with_structured_output`` 强制）：
    「意图 + 实体 + 过滤器 + 检索计划」四件套 —— **语义理解交给 LLM，路由口径由本模块常量固定**，
    避免把「走哪几路检索」的自由裁量权交给模型自由文本。

``RetrievalResult``
    三路检索（向量 / 图谱 / 全文 / 多跳）的**统一出参**：不论来自 Chroma、Neo4j 还是 PostgreSQL，
    下游只看这一个结构，融合与引用因此与数据源解耦。

约束（§0 / §10.2）：全部 Pydantic v2（``IntelBaseModel``，``extra="forbid"``）；
``trace_id`` 全程透传，引用必须可回溯到 ``doc_id`` / ``metadata``。
"""

from __future__ import annotations

import operator
from collections.abc import Sequence
from typing import Annotated, Any, Literal, NotRequired, TypedDict

from pydantic import Field

from aisec_intel.models.agent_io import ReasoningStep
from aisec_intel.models.base import IntelBaseModel, new_trace_id
from aisec_intel.models.external_evidence import (
    FACT_LABELS as _FACT_LABELS,
)
from aisec_intel.models.external_evidence import (
    ExternalEvidence,
    ExternalVerification,
)
from aisec_intel.models.unified_vuln import Severity

QAIntent = Literal["vuln_lookup", "asset_lookup", "attack_chain", "remediation", "general"]
"""问答意图：漏洞查询 / 资产查询 / 攻击链查询 / 修复建议 / 综合。"""

INTENT_LABELS: dict[str, str] = {
    "vuln_lookup": "漏洞查询",
    "asset_lookup": "资产查询",
    "attack_chain": "攻击链查询",
    "remediation": "修复建议",
    "general": "综合",
}
"""意图中文标签（前端展示与日志用）。"""

RetrievalRoute = Literal["vector", "graph", "fulltext", "multi_hop"]
"""检索通路：向量语义 / 图谱结构化 / PostgreSQL 全文 / 图谱多跳遍历。"""

RETRIEVAL_ROUTES: tuple[str, ...] = ("vector", "graph", "fulltext", "multi_hop")
"""全部通路（顺序即默认融合顺序）。"""

ROUTE_LABELS: dict[str, str] = {
    "vector": "向量语义检索（Chroma）",
    "graph": "图谱结构化检索（Neo4j）",
    "fulltext": "PostgreSQL 全文检索",
    "multi_hop": "图谱多跳遍历（≤2 跳）",
}
"""通路中文标签。"""

PLAN_BY_INTENT: dict[str, tuple[str, ...]] = {
    "vuln_lookup": ("vector", "fulltext", "graph"),
    "asset_lookup": ("graph", "multi_hop", "fulltext"),
    "attack_chain": ("graph", "multi_hop", "vector"),
    "remediation": ("vector", "fulltext", "graph"),
    "general": ("vector", "fulltext", "graph", "multi_hop"),
}
"""意图 → 默认检索计划（规则兜底与提示词示例共用，**唯一口径**）。"""

TimeRange = Literal["recent_7d", "recent_30d", "recent_90d", "year", "all"]
"""时间范围过滤器取值。"""

TIME_RANGE_DAYS: dict[str, int | None] = {
    "recent_7d": 7,
    "recent_30d": 30,
    "recent_90d": 90,
    "year": 365,
    "all": None,
}
"""时间范围 → 回看天数（``None`` 表示不限）。"""

DEFAULT_TOP_K: int = 8
"""单路检索默认召回条数。"""

DEFAULT_RRF_K: int = 60
"""RRF（Reciprocal Rank Fusion）平滑常数，经验值 60（§5.8 混合检索）。"""


class QueryEntities(IntelBaseModel):
    """查询中识别出的实体（全部可选，缺失即空列表）。

    Attributes:
        cve_ids: CVE 编号（规范大写，如 ``CVE-2024-3400``）。
        components: 组件 / 产品名（如 ``PAN-OS``、``PHP``）。
        vendors: 厂商名（如 ``Palo Alto Networks``）。
        techniques: MITRE ATT&CK 技术 ID（如 ``T1190``）。
        keywords: 其它检索关键词（主题词，非实体）。
    """

    cve_ids: list[str] = Field(default_factory=list, description="CVE 编号（大写规范）")
    components: list[str] = Field(default_factory=list, description="组件/产品名")
    vendors: list[str] = Field(default_factory=list, description="厂商名")
    techniques: list[str] = Field(default_factory=list, description="ATT&CK 技术 ID，如 T1190")
    keywords: list[str] = Field(default_factory=list, description="其它检索关键词")

    @property
    def is_empty(self) -> bool:
        """是否未识别出任何实体。"""
        return not any((self.cve_ids, self.components, self.vendors, self.techniques, self.keywords))


class QueryFilters(IntelBaseModel):
    """查询的确定性过滤器（只做筛选，不做语义判断）。

    Attributes:
        time_range: 时间范围。
        severity: 严重度白名单（空表示不限）。
        sources: 来源白名单（``nvd`` / ``osv`` / ``kev`` / ...；空表示不限）。
        kev_only: 是否只看 CISA KEV（已知被利用）。
    """

    time_range: TimeRange = Field(default="all", description="时间范围")
    severity: list[Severity] = Field(default_factory=list, description="严重度白名单")
    sources: list[str] = Field(default_factory=list, description="来源白名单")
    kev_only: bool = Field(default=False, description="仅 CISA KEV 已知被利用")


class QueryIntent(IntelBaseModel):
    """查询理解结果（L4 唯一的「问题解析」契约）。

    Attributes:
        query: 原始自然语言问题。
        intent: 意图分类。
        entities: 识别出的实体。
        filters: 确定性过滤器。
        retrieval_plan: 该走哪几路检索（去重保序，取值见 :data:`RETRIEVAL_ROUTES`）。
        rewritten_query: 归一化后的检索用 query（去掉口语化措辞，保留关键词）。
        confidence: 解析置信度，区间 ``[0.0, 1.0]``。
        rationale: 解析依据（LLM 简短说明；规则路径为 ``None``）。
        parser: 产出方（``llm`` 或 ``rules``），便于评测区分两条路径。
    """

    query: str = Field(min_length=1, description="原始问题")
    intent: str = Field(default="general", description="意图分类")
    entities: QueryEntities = Field(default_factory=QueryEntities, description="识别出的实体")
    filters: QueryFilters = Field(default_factory=QueryFilters, description="确定性过滤器")
    retrieval_plan: list[str] = Field(default_factory=list, description="检索计划（去重保序）")
    rewritten_query: str = Field(default="", description="归一化检索用 query")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="解析置信度")
    rationale: str | None = Field(default=None, description="解析依据")
    parser: Literal["llm", "rules"] = Field(default="rules", description="产出方")

    def resolved_plan(self) -> list[RetrievalRoute]:
        """返回最终检索计划（计划为空时回退到意图默认值，再兜底 ``general``）。

        Returns:
            去重保序的通路列表。
        """
        plan = normalize_plan(self.retrieval_plan)
        if plan:
            return plan
        return normalize_plan(list(PLAN_BY_INTENT.get(self.intent, PLAN_BY_INTENT["general"])))


class RetrievalResult(IntelBaseModel):
    """三路检索的统一出参（融合与引用只依赖本结构）。

    Attributes:
        source: 命中通路。
        doc_id: 文档标识（可回溯：``vuln_descriptions:CVE-2024-3400`` / ``graph:CVE-2024-3400``）。
        content: 供回答引用与展示的文本片段。
        score: 得分（单路为相似度 / 命中分；融合后为 RRF 得分）。
        rank: 排名（1 起；单路检索为路内排名，0 表示未排名）。
        metadata: 元数据（``cve_id`` / ``severity`` / ``url`` 等）。
        route_scores: 融合时各路贡献的归一化得分（键为通路名）。
    """

    source: str = Field(description="命中通路（vector/graph/fulltext/multi_hop）")
    doc_id: str = Field(min_length=1, description="文档标识")
    content: str = Field(default="", description="可引用文本片段")
    score: float = Field(default=0.0, description="得分（单路或 RRF）")
    rank: int = Field(default=0, ge=0, description="排名（1 起；0 表示未排名）")
    metadata: dict[str, Any] = Field(default_factory=dict, description="元数据")
    route_scores: dict[str, float] = Field(default_factory=dict, description="各路贡献得分")


class Citation(IntelBaseModel):
    """引用条目（P7 Citation Agent 的契约；Day10 先定义以稳定下游接口）。

    Attributes:
        claim: 该引用支撑的断言。
        doc_id: 命中的文档标识（必须来自 :class:`RetrievalResult`）。
        source: 来源通路。
        url: 原始链接（可能为空）。
        quote: 原文片段（引用回溯依据）。
    """

    claim: str = Field(default="", description="被支撑的断言")
    doc_id: str = Field(min_length=1, description="命中文档标识")
    source: str = Field(description="来源通路")
    url: str | None = Field(default=None, description="原始链接")
    quote: str = Field(default="", description="原文片段")


class GapReport(IntelBaseModel):
    """一次证据缺口检测的结果（Day25 阶段 1；由 :mod:`aisec_intel.qa.evidence_gap` 产出）。

    Attributes:
        required_facts: 本次问题必须具备的事实标签（按 ``evidence_gap.FACT_ORDER`` 排序）。
        satisfied: 本地证据已具备的事实标签。
        missing: 本地证据缺失的事实标签（**驱动条件边**）。
        has_enough: 是否已足够作答（``not missing``）。
        evidence_count: 参与判定的本地证据条数。
        rationale: 一句话说明（日志 / CLI / 答案用）。
    """

    required_facts: list[str] = Field(default_factory=list, description="必须具备的事实")
    satisfied: list[str] = Field(default_factory=list, description="已具备的事实")
    missing: list[str] = Field(default_factory=list, description="缺失的事实")
    has_enough: bool = Field(default=True, description="是否已足够作答")
    evidence_count: int = Field(default=0, ge=0, description="参与判定的证据条数")
    rationale: str = Field(default="", description="一句话说明")

    @property
    def missing_labels(self) -> list[str]:
        """缺失事实的中文标签（展示用）。

        Returns:
            形如 ``["修复版本", "厂商公告/补丁"]``。
        """
        return [_FACT_LABELS.get(item, item) for item in self.missing]

    @property
    def lacks_fixed_version(self) -> bool:
        """是否缺少「修复版本」事实（Synthesizer 强制缺口声明的依据）。

        Returns:
            缺 ``fixed_version`` 返回 ``True``。
        """
        return "fixed_version" in self.missing


class QAState(TypedDict):
    """问答图的共享状态（TypedDict，LangGraph 通道）。

    Note:
        ``errors`` / ``results`` 声明 ``operator.add`` 归约器：节点只返回增量即自动累积。

    Attributes:
        question: 用户原始问题。
        trace_id: 全链路追踪 ID（§10.2 不变式 5）。
        session_context: **多轮会话上下文**（Day12 任务 6）：按时间正序排列的历史
            「问题 / 答案」文本；仅注入查询理解提示词，不改写当前问题与检索口径。
        intent: 查询理解结果。
        results: 三路检索原始结果（未融合）。
        fused: 融合排序后的结果（RRF）。
        citations: 引用列表。
        answer: 最终回答文本。
        errors: 非致命错误 / 降级说明。
        degraded: 是否处于降级路径（无 LLM / 无 Neo4j 等）。
        partial_retrieval: 检索面是否不完备（计划中有通路 0 命中或失败；Day24 置信度折扣依据）。
        gap_report: 证据缺口报告（Day25 阶段 1；``has_enough=False`` 触发受控外部检索）。
        external_evidence: 受控外部证据（Day25 阶段 2；复核通过的条目，``untrusted=True``）。
        external_verification: 外部证据复核汇总（来源 / 多源冲突裁决 / 可提升事实）。
    """

    question: str
    trace_id: str
    session_context: NotRequired[list[str]]
    intent: NotRequired[QueryIntent | None]
    results: Annotated[list[RetrievalResult], operator.add]
    fused: NotRequired[list[RetrievalResult]]
    reasoning_chain: NotRequired[list[ReasoningStep]]
    citations: NotRequired[list[Citation]]
    answer: NotRequired[str]
    errors: Annotated[list[str], operator.add]
    degraded: NotRequired[bool]
    partial_retrieval: NotRequired[bool]
    gap_report: NotRequired[GapReport | None]
    external_evidence: NotRequired[list[ExternalEvidence]]
    external_verification: NotRequired[ExternalVerification | None]


def new_qa_state(
    question: str,
    *,
    trace_id: str | None = None,
    session_context: Sequence[str] | None = None,
) -> QAState:
    """构造问答图初始状态（所有键显式赋值，避免 LangGraph 通道缺省歧义）。

    Args:
        question: 用户原始问题。
        trace_id: 追踪 ID；``None`` 时自动生成。
        session_context: 多轮会话上下文（历史「问题 / 答案」文本，时间正序）。

    Returns:
        可直接交给 ``graph.ainvoke`` 的初始状态。
    """
    return QAState(
        question=question,
        trace_id=trace_id or new_trace_id(),
        session_context=[str(item) for item in (session_context or []) if str(item).strip()],
        intent=None,
        results=[],
        fused=[],
        citations=[],
        answer="",
        errors=[],
        degraded=False,
        partial_retrieval=False,
        gap_report=None,
        external_evidence=[],
        external_verification=None,
    )


def normalize_plan(routes: list[str] | tuple[str, ...]) -> list[RetrievalRoute]:
    """规范化检索计划（去重、剔非法通路、保持首次出现顺序，纯函数）。

    Args:
        routes: 原始通路名列表（可能含大小写混杂或非法值）。

    Returns:
        合法的通路列表（全部非法时返回空列表）。
    """
    seen: set[str] = set()
    plan: list[RetrievalRoute] = []
    for route in routes:
        name = str(route).strip().lower()
        if name in RETRIEVAL_ROUTES and name not in seen:
            seen.add(name)
            plan.append(name)  # type: ignore[arg-type]
    return plan
