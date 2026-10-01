"""查询理解 Agent（Day10 P6 收尾；PROJECT_PLAN.md §5.8 Supervisor / Router 前置）。

职责：把用户自然语言问题解析为 :class:`~aisec_intel.qa.state.QueryIntent`
（意图 / 实体 / 过滤器 / 检索计划），是问答层**唯一**的语义理解入口（L4 允许 LLM，§0 约束 2）。

两条路径（§3.2 闸门 + §3.3 降级，**永不中断问答链路**）：

1. **LLM 路径**：``provider.structured(QueryIntent, role="fast")``（deepseek-chat +
   ``function_calling``）+ :func:`aisec_intel.llm.schemas.invoke_structured` 二次校验（闸门①+②）；
2. **规则路径**：:func:`parse_intent_rules`（正则 + 关键词，纯函数、零依赖），
   用于「无 Key / 断网 / 结构化解析失败 / ``DEGRADED_MODE=true``」。

**混合策略**：即便 LLM 成功，也会用规则结果补齐 CVE 编号 / ATT&CK 技术 ID 等
**强格式实体**（LLM 偶发漏抽，规则近乎零成本且确定），实体取并集、过滤器取「LLM 优先 + 规则兜底」。
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, cast

from langchain_core.messages import HumanMessage, SystemMessage

from aisec_intel.config import Settings, get_settings
from aisec_intel.llm.cache import wrap_with_cache
from aisec_intel.llm.provider import LLMError, build_provider
from aisec_intel.llm.schemas import DEFAULT_MAX_RETRIES, StructuredOutputError, invoke_structured
from aisec_intel.logging_config import get_logger
from aisec_intel.models.unified_vuln import Severity
from aisec_intel.qa.state import (
    PLAN_BY_INTENT,
    QAState,
    QueryEntities,
    QueryFilters,
    QueryIntent,
    TimeRange,
    normalize_plan,
)

logger = get_logger(__name__)

AGENT_NAME: str = "query_understander"
"""节点名（写入日志与评测报告）。"""

DEFAULT_MIN_CONFIDENCE: float = 0.3
"""规则解析的最低置信度（低于该值也不阻断，仅作为可观测信号）。"""

MAX_KEYWORDS: int = 8
"""关键词条数上限。"""

MAX_ENTITIES: int = 6
"""每类实体条数上限。"""

INTENT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "remediation": (
        "修复建议",
        "如何修复",
        "怎么修",
        "补丁",
        "缓解",
        "处置",
        "升级到",
        "remediat",
        "patch",
        "mitigat",
        "workaround",
        "fix",
    ),
    "attack_chain": (
        "攻击链",
        "攻击路径",
        "利用链",
        "利用步骤",
        "如何利用",
        "横向移动",
        "attack chain",
        "kill chain",
        "exploit chain",
    ),
    "asset_lookup": (
        "资产",
        "哪些系统",
        "哪些设备",
        "安装在",
        "装了",
        "影响面",
        "asset",
        "installed",
        "inventory",
        "affected systems",
    ),
    "vuln_lookup": ("漏洞", "影响版本", "严重", "cvss", "cve-", "vulnerab", "severity", "risk score"),
}
"""意图关键词（按此顺序判定：修复 > 攻击链 > 资产 > 漏洞）。"""

SEVERITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "CRITICAL": ("严重", "极危", "critical", "9.0 以上"),
    "HIGH": ("高危", "高风", "high"),
    "MEDIUM": ("中危", "中风险", "medium"),
    "LOW": ("低危", "low"),
    "NONE": ("无风险", "none"),
}
"""严重度关键词 → CVSS 严重度取值。"""

SEVERITY_ORDER: dict[str, int] = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
"""严重度排序权重（用于过滤器输出的确定性排序）。"""

TIME_KEYWORDS: dict[str, tuple[str, ...]] = {
    "recent_7d": ("最近7天", "近7天", "最近一周", "近一周", "本周", "last 7 days"),
    "recent_30d": ("最近30天", "近30天", "最近一个月", "近一个月", "近一月", "last 30 days"),
    "recent_90d": ("最近90天", "近90天", "最近三个月", "近三个月", "近三月"),
    "year": ("今年", "近一年", "最近一年", "近12个月", "last year"),
}
"""时间范围关键词 → ``QueryFilters.time_range``。"""

KEV_KEYWORDS: tuple[str, ...] = ("kev", "已知被利用", "在野", "已被利用", "exploited in the wild")
"""CISA KEV 关键词（命中即 ``kev_only=True``）。"""

SOURCE_KEYWORDS: tuple[str, ...] = ("nvd", "osv", "ghsa", "kev", "epss", "arxiv", "openalex")
"""可识别的数据来源标识。"""

STOPWORDS: frozenset[str] = frozenset(
    {
        "cve",
        "cwe",
        "cvss",
        "poc",
        "api",
        "the",
        "and",
        "for",
        "with",
        "from",
        "this",
        "that",
        "these",
        "those",
        "what",
        "which",
        "when",
        "where",
        "why",
        "who",
        "how",
        "show",
        "list",
        "give",
        "tell",
        "explain",
        "summarize",
        "summary",
        "analyze",
        "analysis",
        "please",
        "all",
        "top",
        "any",
        "some",
        "more",
        "most",
        "best",
        "new",
        "old",
        "info",
        "information",
        "detail",
        "details",
        "report",
        "data",
        "query",
        "help",
        "about",
        "related",
        "same",
        "other",
        "also",
        "need",
        "want",
        "find",
        "know",
        "use",
        "used",
        "using",
        "affect",
        "affected",
        "affects",
        "vulnerability",
        "vulnerabilities",
        "patch",
        "fix",
        "asset",
        "assets",
        "attack",
        "chain",
        "technique",
        "techniques",
        "severity",
        "critical",
        "high",
        "medium",
        "low",
        "risk",
        "score",
        "level",
        "version",
        "versions",
        "product",
        "products",
        "vendor",
        "vendors",
        "component",
        "components",
        "system",
        "systems",
        "recent",
        "last",
        "days",
        "day",
        "week",
        "month",
        "year",
        "mitre",
        "att",
        "ck",
        "tactic",
        "json",
        "nvd",
        "osv",
        "ghsa",
        "kev",
        "epss",
        "arxiv",
        "openalex",
    }
)
"""英文停用词与检索噪音词（不参与组件 / 关键词抽取）。"""

_CVE_PATTERN: re.Pattern[str] = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
"""CVE 编号（强格式实体，规则必抽）。"""

_TECHNIQUE_PATTERN: re.Pattern[str] = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
"""MITRE ATT&CK 技术 ID（如 ``T1190`` / ``T1059.004``）。"""

_VENDOR_PATTERN: re.Pattern[str] = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b")
"""多词大写序列（如 ``Palo Alto Networks``）——厂商名的高精度线索。"""

_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*")
"""英文 / 型号 token（组件名候选来源）。"""

_CJK_PATTERN: re.Pattern[str] = re.compile(r"[\u3400-\u9fff]{2,}")
"""连续中文片段（关键词来源；不含单字，避免噪音）。"""

SYSTEM_PROMPT: str = (
    "你是安全情报系统的查询理解模块。把用户的自然语言问题解析为**结构化检索计划**，"
    "只做理解与分类，不回答问题、不做技术推断。\n"
    "要求：\n"
    "1. intent 取其一：vuln_lookup（漏洞查询）/ asset_lookup（资产查询）/ attack_chain（攻击链查询）"
    "/ remediation（修复建议）/ general（综合）；\n"
    "2. entities：抽取 CVE 编号（大写规范）、组件/产品名、厂商名、ATT&CK 技术 ID、其它关键词；"
    "没有就留空数组，禁止编造；\n"
    "3. filters：time_range 取 all/recent_7d/recent_30d/recent_90d/year；severity 取"
    " NONE/LOW/MEDIUM/HIGH/CRITICAL；sources 取数据源标识（nvd/osv/ghsa/kev/epss/arxiv）；"
    "kev_only 表示只要已知被利用漏洞；\n"
    "4. retrieval_plan：从 vector（语义）/ graph（图谱结构化）/ fulltext（全文）/ multi_hop（多跳图遍历）"
    " 中选 1~4 项，按优先级排序；\n"
    "5. rewritten_query：去掉口语化措辞后的检索语句；confidence：0~1 的解析置信度。\n"
    "只输出 JSON 对象，不要输出解释文字或 Markdown 代码块。"
)
"""查询理解系统提示词。

Note:
    结尾的「只输出 JSON」不是装饰：当结构化方式为 ``json_mode``（``LLM_STRUCTURED_METHOD=auto``
    且模型为思考型时）时，提示词必须含 ``json`` 字样，否则部分端点返回 400。
"""


def build_prompt(question: str) -> str:
    """构造查询理解的用户提示（确定性拼装，含字段取值域与输出示例）。

    Args:
        question: 用户原始问题。

    Returns:
        提示文本。
    """
    intents = " / ".join(sorted(PLAN_BY_INTENT))
    plans = "、".join(f"{intent}={'>'.join(routes)}" for intent, routes in PLAN_BY_INTENT.items())
    return "\n".join(
        [
            f"用户问题：{question}",
            "",
            f"可选 intent：{intents}",
            f"各意图的推荐 retrieval_plan：{plans}",
            "",
            "输出 JSON（严格符合下列结构，不要额外字段）：",
            '{"intent": "vuln_lookup", "entities": {"cve_ids": [], "components": [], "vendors": [],',
            ' "techniques": [], "keywords": []}, "filters": {"time_range": "all", "severity": [],',
            ' "sources": [], "kev_only": false}, "retrieval_plan": ["vector", "fulltext"],',
            ' "rewritten_query": "<检索语句>", "confidence": 0.8, "rationale": "<一句话依据>"}',
        ]
    )


def looks_like_component(token: str) -> bool:
    """判断 token 是否像「组件 / 产品名」（纯函数，确定性启发式）。

    命中条件（任一）：非首字母的大写、含数字、含 ``-_.``、首字母大写且长度 ≥ 4；
    同时排除 :data:`STOPWORDS`、``CVE-`` 前缀与纯数字。

    Args:
        token: 英文 / 型号 token。

    Returns:
        像组件名返回 ``True``。
    """
    if len(token) < 3:
        return False
    lowered = token.lower()
    if lowered in STOPWORDS or lowered.startswith("cve") or lowered.isdigit():
        return False
    if any(char.isupper() for char in token[1:]):
        return True
    if any(char.isdigit() for char in token) or any(char in token for char in "-_."):
        return True
    return token[0].isupper() and len(token) >= 4


def unique_in_order(items: list[str], *, limit: int = MAX_ENTITIES) -> list[str]:
    """去重保序并截断（纯函数，大小写不敏感去重）。

    Args:
        items: 原始字符串列表。
        limit: 条数上限。

    Returns:
        去重后的列表。
    """
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        cleaned = str(item).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(cleaned)
    return result[: max(0, limit)]


def contains_any(text: str, keywords: tuple[str, ...] | list[str]) -> bool:
    """判断文本是否含任一关键词（大小写与空白不敏感，纯函数）。

    Args:
        text: 待匹配文本。
        keywords: 关键词列表。

    Returns:
        命中任一关键词返回 ``True``。
    """
    lowered = text.lower()
    compact = lowered.replace(" ", "")
    for keyword in keywords:
        probe = keyword.lower()
        if probe in lowered or probe.replace(" ", "") in compact:
            return True
    return False


def match_intent(question: str) -> str:
    """按关键词判定意图（纯函数；顺序即优先级：修复 > 攻击链 > 资产 > 漏洞）。

    Args:
        question: 用户问题。

    Returns:
        意图标识（无命中时 ``general``）。
    """
    for intent, keywords in INTENT_KEYWORDS.items():
        if contains_any(question, keywords):
            return intent
    return "general"


def parse_filters(question: str) -> QueryFilters:
    """从问题中解析确定性过滤器（纯函数；未提及的维度保持默认值，不做猜测）。

    Args:
        question: 用户问题。

    Returns:
        :class:`QueryFilters`。
    """
    time_range: TimeRange = "all"
    for candidate, keywords in TIME_KEYWORDS.items():
        if contains_any(question, keywords):
            time_range = cast("TimeRange", candidate)
            break
    severity = [
        cast("Severity", level) for level, keywords in SEVERITY_KEYWORDS.items() if contains_any(question, keywords)
    ]
    severity.sort(key=lambda item: SEVERITY_ORDER[item])
    lowered = question.lower()
    sources = [name for name in SOURCE_KEYWORDS if name in lowered]
    return QueryFilters(
        time_range=time_range,
        severity=severity,
        sources=unique_in_order(sources),
        kev_only=contains_any(question, KEV_KEYWORDS),
    )


def rule_confidence(entities: QueryEntities, filters: QueryFilters, intent: str) -> float:
    """按「命中信号数」折算规则解析置信度（纯函数，区间 ``[0.3, 0.85]``）。

    Args:
        entities: 规则抽出的实体。
        filters: 规则抽出的过滤器。
        intent: 规则判定的意图。

    Returns:
        置信度。
    """
    score = 0.3
    if entities.cve_ids:
        score += 0.2
    if entities.techniques:
        score += 0.1
    if entities.components:
        score += 0.1
    if intent != "general":
        score += 0.1
    if filters.time_range != "all" or filters.severity or filters.sources or filters.kev_only:
        score += 0.1
    return round(min(0.85, max(DEFAULT_MIN_CONFIDENCE, score)), 3)


def parse_intent_rules(question: str) -> QueryIntent:
    """规则解析查询意图（纯函数、零依赖、可离线复现）。

    抽取口径：
        - CVE 编号 / ATT&CK 技术 ID：正则（强格式，规则近乎零漏抽）；
        - 厂商：多词大写序列（如 ``Palo Alto Networks``）；
        - 组件：:func:`looks_like_component` 命中的英文 / 型号 token；
        - 过滤器：时间范围 / 严重度 / 来源 / KEV 关键词；
        - 检索计划：:data:`~aisec_intel.qa.state.PLAN_BY_INTENT`（与提示词示例同源）。

    Args:
        question: 用户问题。

    Returns:
        :class:`QueryIntent`（``parser="rules"``）。
    """
    resolved_question = question.strip() or "(空查询)"
    cve_ids = unique_in_order([match.upper() for match in _CVE_PATTERN.findall(resolved_question)])
    techniques = unique_in_order([match.upper() for match in _TECHNIQUE_PATTERN.findall(resolved_question)])
    vendors = unique_in_order(_VENDOR_PATTERN.findall(resolved_question))
    components = [
        token
        for token in _TOKEN_PATTERN.findall(resolved_question)
        if looks_like_component(token) and not token.lower().startswith("cve")
    ]
    components = [token for token in unique_in_order(components) if token.upper() not in techniques]
    latin_keywords = [
        token
        for token in _TOKEN_PATTERN.findall(resolved_question)
        if not _CVE_PATTERN.fullmatch(token)
        and (token.lower() in STOPWORDS or not looks_like_component(token))
    ]
    keywords = unique_in_order(
        [run[:10] for run in _CJK_PATTERN.findall(resolved_question)] + latin_keywords,
        limit=MAX_KEYWORDS,
    )
    intent = match_intent(resolved_question)
    filters = parse_filters(resolved_question)
    entities = QueryEntities(
        cve_ids=cve_ids,
        components=components,
        vendors=vendors,
        techniques=techniques,
        keywords=keywords,
    )
    rewritten = " ".join(unique_in_order([*cve_ids, *techniques, *components, *vendors], limit=MAX_ENTITIES * 2))
    return QueryIntent(
        query=resolved_question,
        intent=intent,
        entities=entities,
        filters=filters,
        retrieval_plan=list(PLAN_BY_INTENT[intent]),
        rewritten_query=rewritten or resolved_question,
        confidence=rule_confidence(entities, filters, intent),
        rationale=None,
        parser="rules",
    )


def normalize_intent(intent: QueryIntent, question: str) -> QueryIntent:
    """把 LLM 输出与规则结果合并为最终 :class:`QueryIntent`（纯函数）。

    合并策略（确定性，**不把路由与强格式实体的自由裁量交给模型文本**）：
        - 实体：取并集（LLM 在前，规则补齐 CVE / 技术 ID / 组件）；
        - 过滤器：LLM 显式给出优先，规则兜底；
        - ``intent``：不在白名单内时回退规则判定；
        - ``retrieval_plan``：规范化去重（白名单）；为空时用意图默认计划；
        - ``confidence``：取两者较大值（有任一强信号即视为可解释）。

    Args:
        intent: LLM 输出的查询意图。
        question: 用户原始问题。

    Returns:
        合并后的 :class:`QueryIntent`（``parser="llm"``）。
    """
    rules = parse_intent_rules(question)
    merged = intent.model_copy(
        update={
            "query": question.strip() or "(空查询)",
            "intent": intent.intent if intent.intent in PLAN_BY_INTENT else rules.intent,
            "entities": QueryEntities(
                cve_ids=unique_in_order([*intent.entities.cve_ids, *rules.entities.cve_ids]),
                components=unique_in_order([*intent.entities.components, *rules.entities.components]),
                vendors=unique_in_order([*intent.entities.vendors, *rules.entities.vendors]),
                techniques=unique_in_order([*intent.entities.techniques, *rules.entities.techniques]),
                keywords=unique_in_order([*intent.entities.keywords, *rules.entities.keywords], limit=MAX_KEYWORDS),
            ),
            "filters": QueryFilters(
                time_range=(
                    intent.filters.time_range if intent.filters.time_range != "all" else rules.filters.time_range
                ),
                severity=intent.filters.severity or rules.filters.severity,
                sources=intent.filters.sources or rules.filters.sources,
                kev_only=intent.filters.kev_only or rules.filters.kev_only,
            ),
            "rewritten_query": intent.rewritten_query.strip() or rules.rewritten_query,
            "confidence": round(max(float(intent.confidence), rules.confidence), 3),
            "parser": "llm",
        }
    )
    plan = normalize_plan(merged.retrieval_plan)
    merged.retrieval_plan = plan or merged.resolved_plan()
    return merged


class QueryUnderstander:
    """查询理解 Agent（LLM 优先 + 规则兜底 + 实体并集）。

    Attributes:
        last_error: 最近一次 LLM 失败 / 回退原因（``None`` 表示 LLM 成功）。
    """

    def __init__(
        self,
        *,
        structured_llm: Any | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        use_llm: bool = True,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    ) -> None:
        """初始化。

        Args:
            structured_llm: ``provider.structured(QueryIntent)``（或带缓存的 runner）；
                ``None`` 时只能走规则路径。
            max_retries: 结构化输出失败重试次数（§3.2 闸门②）。
            use_llm: 是否允许调用 LLM（``False`` 时强制规则路径）。
            min_confidence: 采纳 LLM 结果的最低置信度（低于该值回退规则，保持可解释性）。
        """
        self._llm = structured_llm
        self._max_retries = max(0, max_retries)
        self._use_llm = bool(use_llm and structured_llm is not None)
        self._min_confidence = min_confidence
        self.last_error: str | None = None

    @property
    def llm_enabled(self) -> bool:
        """是否启用 LLM 路径。"""
        return self._use_llm

    async def understand(self, question: str) -> QueryIntent:
        """解析用户问题（LLM 优先，失败或低置信度时回退规则路径）。

        Args:
            question: 用户自然语言问题。

        Returns:
            :class:`QueryIntent`（``parser`` 标明产出路径，便于评测区分）。

        Note:
            **任何** LLM 异常（网络 / 超时 / 校验失败）都不会向上抛出，
            保证问答链路在断网时仍可走通（§3.3）。
        """
        self.last_error = None
        if not self._use_llm or not question.strip():
            return parse_intent_rules(question)
        messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=build_prompt(question))]
        try:
            raw: QueryIntent = await invoke_structured(
                self._llm, QueryIntent, messages, max_retries=self._max_retries
            )
        except StructuredOutputError as exc:
            self.last_error = f"结构化输出失败：{exc}"
            logger.warning(f"查询理解结构化输出失败，回退规则路径：{exc}")
            return parse_intent_rules(question)
        except Exception as exc:  # noqa: BLE001 - 网络/超时同样回退，绝不中断问答
            self.last_error = f"LLM 调用失败：{type(exc).__name__}: {exc}"
            logger.warning(f"查询理解 LLM 调用失败，回退规则路径：{self.last_error}")
            return parse_intent_rules(question)

        merged = normalize_intent(raw, question)
        if merged.confidence < self._min_confidence:
            self.last_error = f"LLM 置信度过低（{merged.confidence} < {self._min_confidence}）"
            logger.warning(f"查询理解置信度不足，回退规则路径：{self.last_error}")
            return parse_intent_rules(question)
        return merged

    async def __call__(self, state: QAState) -> dict[str, Any]:
        """LangGraph 节点入口：读取状态中的 ``question``，返回状态增量。

        Args:
            state: 问答图状态。

        Returns:
            含 ``intent`` / ``degraded``（必要时含 ``errors``）的增量字典。
        """
        question = str(state.get("question") or "")
        intent = await self.understand(question)
        payload: dict[str, Any] = {"intent": intent, "degraded": intent.parser == "rules"}
        if self.last_error:
            payload["errors"] = [f"{AGENT_NAME}: {self.last_error}"]
        return payload


def build_query_understander(
    settings: Settings | None = None,
    *,
    use_llm: bool | None = None,
    session_factory: Callable[[], Any] | None = None,
) -> QueryUnderstander:
    """按配置构建查询理解 Agent（唯一工厂）。

    启用条件：``use_llm`` 显式为真；或（默认）``DEGRADED_MODE=false`` 且已配置真实 API Key。
    传入 ``session_factory`` 时自动挂 :func:`~aisec_intel.llm.cache.wrap_with_cache`，
    让重复问题命中 ``llm_cache``（§3.4 额度保护）。

    Args:
        settings: 全局配置；``None`` 时使用进程级单例。
        use_llm: 显式开关；``None`` 时按配置推断。
        session_factory: 缓存表会话工厂；``None`` 时不挂缓存（仅计量）。

    Returns:
        可用的 :class:`QueryUnderstander`（构造过程**不发起网络请求**）。
    """
    resolved = settings or get_settings()
    enabled = (not resolved.degraded_mode and resolved.has_llm_api_key) if use_llm is None else use_llm
    if not enabled:
        logger.info("查询理解走规则路径（未启用 LLM 或处于降级模式）")
        return QueryUnderstander(structured_llm=None, use_llm=False, max_retries=resolved.llm_max_retries)
    try:
        provider = build_provider(resolved)
        runnable: Any = provider.structured(QueryIntent, role="fast")
        if session_factory is not None:
            runnable = wrap_with_cache(
                runnable,
                schema=QueryIntent,
                model=provider.model_for("fast"),
                provider=provider.name,
                session_factory=session_factory,
            )
    except LLMError as exc:
        logger.warning(f"LLM 不可用，查询理解走规则路径：{exc}")
        return QueryUnderstander(structured_llm=None, use_llm=False, max_retries=resolved.llm_max_retries)
    return QueryUnderstander(structured_llm=runnable, max_retries=resolved.llm_max_retries)
