"""混合检索服务（Day10 P6 收尾；PROJECT_PLAN.md §5.8 三路检索 / §5.7 向量 + 图谱）。

四路检索统一入口（前三路为 §5.8 要求，第四路为 P6 多跳原型接入）：

============  ==========================================================================
通路           实现
============  ==========================================================================
``vector``    Chroma 语义检索（:mod:`aisec_intel.storage.vector_store`，bge 本地嵌入）
``graph``     Neo4j 结构化邻居查询（组件 / 资产 / 攻击技术 / 论文；PG 降级为 JSON 展平）
``fulltext``  PostgreSQL 全文检索（``to_tsvector`` + ``plainto_tsquery`` + ``ts_rank``；
              SQLite / 降级模式退化为 Python 词元打分，跨库口径一致）
``multi_hop`` 2 跳图遍历（:mod:`aisec_intel.qa.multi_hop`，Neo4j 或 PG JSON）
============  ==========================================================================

结果融合：**RRF（Reciprocal Rank Fusion）** ``score = Σ w_r / (k + rank_r)``（``k`` 默认
:data:`~aisec_intel.qa.state.DEFAULT_RRF_K`）。RRF 只看排名不看原始分数，天然解决
「余弦相似度 / ts_rank / 图命中数」量纲不可比的问题；同时保留各路贡献得分便于评测与调试。

降级与容错：
    - 任一路检索抛异常 → 记入 :class:`FusionOutcome` 的 ``errors`` 并继续，**单路失败不影响回答**；
    - Chroma 不可用 → 该路返回空并留痕；Neo4j 不可用 → ``graph`` / ``multi_hop`` 自动走 PG JSON；
    - 所有检索均**不含 LLM 调用**（语义理解由 ``qa/agents/query_understander`` 负责）。
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import iso_z, utc_now
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.qa.multi_hop import MultiHopTraversal, collect_technique_rows, extract_cve_ids
from aisec_intel.qa.state import (
    DEFAULT_RRF_K,
    DEFAULT_TOP_K,
    RETRIEVAL_ROUTES,
    TIME_RANGE_DAYS,
    QueryFilters,
    RetrievalResult,
    normalize_plan,
)
from aisec_intel.services.self_heal import (
    ACTION_DEGRADED,
    ACTION_FALLBACK,
    COMPONENT_QA,
    SelfHealEvent,
    log_self_heal,
)
from aisec_intel.storage.embeddings import hashing_tokens
from aisec_intel.storage.models.vuln import UnifiedVulnRow
from aisec_intel.storage.neo4j_client import Neo4jClient, Neo4jUnavailableError
from aisec_intel.storage.repositories.graph_repo import GraphRepository
from aisec_intel.storage.vector_store import (
    COLLECTION_VULN_DESCRIPTIONS,
    COLLECTIONS,
    VectorStore,
)

logger = get_logger(__name__)

DEFAULT_WEIGHTS: dict[str, float] = {route: 1.0 for route in RETRIEVAL_ROUTES}
"""各路融合权重（默认等权；可按评测结果调整，如 ``{"graph": 1.2}``）。"""

DEFAULT_ENTITY_BONUS: float = 0.5
"""实体精确匹配加成（融合后追加）。

量级说明：RRF 单条得分约 ``1/61 ≈ 0.016``，故 ``0.5`` 足以把「查询直接指向的 CVE」
稳定提到最前，同时保留其余结果的原有相对顺序。
"""

MAX_SCAN_ROWS: int = 2000
"""PG 侧扫描上限（全文降级与结构化展平共用，防止大表拖垮查询）。"""

MAX_TARGETS: int = 3
"""单次查询最多处理的 CVE / 组件实体数（多实体问题拆分处理，避免放大耗时）。"""

ROUTE_FALLBACKS: dict[str, str] = {
    "vector": "fulltext（PostgreSQL 全文检索，自动补齐）",
    "graph": "PG JSON（postgres 降级推导）",
    "multi_hop": "PG JSON（postgres 降级推导）",
    "fulltext": "Python 词元打分（SQLite / 无 FTS 时）",
}
"""检索通路不可用时的降级路径描述（自愈日志用，Day17 任务 4.3）。"""


def _fallback_of(route: str) -> str:
    """返回某检索通路不可用时的降级路径描述（纯函数）。

    Args:
        route: 通路名（``vector`` / ``graph`` / ``fulltext`` / ``multi_hop``）。

    Returns:
        降级路径描述；未登记的通路返回「无（该路直接跳过）」。
    """
    return ROUTE_FALLBACKS.get(route, "无（该路直接跳过）")

PG_FULLTEXT_SQL: str = """
SELECT vuln_id, title, description, severity,
       ts_rank(
           to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '')),
           to_tsquery('simple', :tsquery)
       ) AS score
FROM unified_vuln
WHERE to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, ''))
      @@ to_tsquery('simple', :tsquery)
ORDER BY score DESC, published_at DESC NULLS LAST
LIMIT :limit
"""
"""PostgreSQL 全文检索 SQL（``simple`` 配置 + **OR 语义** tsquery；参数化绑定）。

设计取舍（与 SQLite 降级路径口径对齐）：
    ``plainto_tsquery`` 会把整个查询按 **AND** 解析——长自然语言问题（如
    「PAN-OS 命令注入漏洞的 PoC」）几乎不可能同时命中全部词元，实测会出现「明明有数据却 0 命中」。
    因此这里改由 :func:`build_tsquery` 在 Python 侧切词并拼成 ``a | b | c`` 的 OR 查询，
    再由 ``ts_rank`` 按命中程度排序，行为与 :func:`python_fulltext_score` 一致。

Note:
    ``migrations/versions/0006_qa_indexes.py`` 可为该表达式建立 GIN 表达式索引；
    未建索引时仍可工作，只是退化为顺序扫描（当前数据量可接受）。
"""

CYPHER_TECHNIQUE_CVES: str = (
    "MATCH (t:AttackTechnique)<-[:EXPLOITS]-(v:Vulnerability) "
    "WHERE t.technique_id IN $techniques "
    "RETURN DISTINCT t.technique_id AS technique_id, v.cve_id AS cve_id, v.title AS title, "
    "v.risk_score AS risk_score, v.risk_level AS risk_level, v.kev AS kev "
    "ORDER BY technique_id, risk_score DESC, cve_id LIMIT $limit"
)
"""「技术 → 利用该技术的漏洞」Cypher（标签/关系取自白名单常量，参数化，注入面为零）。

Note:
    与 :mod:`aisec_intel.qa.multi_hop` 的 ``CYPHER_CVE_TECHNIQUES`` 方向相反：
    前者从技术出发（无 CVE 实体的查询），后者从已知 CVE 出发做 2 跳扩展。
"""


class RetrievalError(RuntimeError):
    """检索层错误基类（服务层统一包装后记入 ``FusionOutcome.errors``）。"""


def query_keywords(query: str) -> list[str]:
    """把自然语言查询切成检索词元（英文数字词 + 中文二元组，纯函数）。

    Args:
        query: 用户查询。

    Returns:
        去重保序的词元列表（可能为空）。
    """
    seen: set[str] = set()
    tokens: list[str] = []
    for token in hashing_tokens(query):
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def python_fulltext_score(content: str, keywords: Sequence[str]) -> float:
    """计算文本对关键词的命中得分（纯函数，SQLite / 降级模式的「全文检索」实现）。

    口径：``命中词元数 / 关键词总数``（区间 ``[0,1]``）；按子串匹配以兼容英文派生词。

    Args:
        content: 待打分文本（标题 + 描述）。
        keywords: 查询词元。

    Returns:
        得分，区间 ``[0.0, 1.0]``。
    """
    if not keywords:
        return 0.0
    tokens = hashing_tokens(content)
    if not tokens:
        return 0.0
    hits = sum(1 for keyword in keywords if any(keyword in token for token in tokens))
    return round(hits / len(keywords), 4)


def build_tsquery(keywords: Sequence[str]) -> str:
    """把关键词拼成 PostgreSQL ``to_tsquery`` 的 **OR** 表达式（纯函数）。

    只保留字母 / 数字 / 中文（其余字符替换为空格后切分），避免 tsquery 语法错误；
    词长 ≥ 2 才保留（与 :func:`query_keywords` 口径一致）。

    Args:
        keywords: 关键词 / 词元列表。

    Returns:
        形如 ``pan | os | 注入`` 的表达式；无有效词元时返回空串（调用方应短路返回）。
    """
    cleaned: list[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        for part in re.split(r"[^0-9A-Za-z\u3400-\u9fff]+", str(keyword)):
            if len(part) < 2 or part.lower() in seen:
                continue
            seen.add(part.lower())
            cleaned.append(part)
    return " | ".join(cleaned)


def reciprocal_rank_fusion(
    channels: Mapping[str, Sequence[RetrievalResult]],
    *,
    k: int = DEFAULT_RRF_K,
    weights: Mapping[str, float] | None = None,
    top_k: int | None = None,
) -> list[RetrievalResult]:
    """RRF 融合（纯函数）：把多路结果按排名合并为统一排序。

    公式：``score(d) = Σ_r w_r / (k + rank_r(d))``；同一实体在多路命中时**得分累加**
    （正是 RRF 能提升「多路共同命中」文档排名的原因）。

    Args:
        channels: 通路名 → 该路结果（顺序即排名，各路已按相关度降序）。
        k: 平滑常数（默认 :data:`~aisec_intel.qa.state.DEFAULT_RRF_K`）。
        weights: 通路权重；``None`` 时等权。
        top_k: 返回条数上限；``None`` 表示全部。

    Returns:
        融合后的 :class:`RetrievalResult` 列表（``rank`` 重新编号，``route_scores`` 记录各路贡献）。

    Note:
        结果以 :func:`canonical_key`（CVE / 论文主键）为融合单位，
        因此「向量命中 + 全文命中 + 图谱命中」的同一 CVE 会合并为一条，
        其 ``content`` 取信息量最大者（:func:`prefer_payload`）。
    """
    resolved_weights = dict(weights or DEFAULT_WEIGHTS)
    smooth = max(1, k)
    scores: dict[str, float] = {}
    contributions: dict[str, dict[str, float]] = {}
    payload: dict[str, RetrievalResult] = {}

    for route, results in channels.items():
        weight = float(resolved_weights.get(route, 1.0))
        for rank, result in enumerate(results, start=1):
            key = canonical_key(result)
            scores[key] = scores.get(key, 0.0) + weight / (smooth + rank)
            contributions.setdefault(key, {})[route] = round(weight / (smooth + rank), 6)
            current = payload.get(key)
            if current is None or prefer_payload(result, current):
                payload[key] = result

    fused = [
        payload[key].model_copy(update={"score": round(score, 6), "rank": 0, "route_scores": contributions[key]})
        for key, score in scores.items()
    ]
    fused.sort(key=lambda item: (-item.score, item.source, item.doc_id))
    for index, item in enumerate(fused, start=1):
        item.rank = index
    return fused if top_k is None else fused[: max(0, top_k)]


def boost_entity_matches(
    results: Sequence[RetrievalResult],
    *,
    cve_ids: Sequence[str] = (),
    bonus: float = DEFAULT_ENTITY_BONUS,
) -> list[RetrievalResult]:
    """把与查询实体精确匹配的结果提到最前（纯函数，确定性）。

    动机（Day10 实测）：全文路按 OR 词元匹配（``cve`` / ``2024`` / ``3400``）时会命中大量
    同年度编号，单纯 RRF 可能把「查询直接指向的那条 CVE」挤到第 2 位。
    **实体精确匹配是检索中最强的确定性信号**，因此在融合之后追加一次加成，
    保证「问哪个 CVE 就先给哪个 CVE」，其余结果的相对顺序不变。

    Args:
        results: 融合后的结果列表。
        cve_ids: 查询中识别出的 CVE 编号（大小写不敏感）。
        bonus: 加成值（默认 :data:`DEFAULT_ENTITY_BONUS`）。

    Returns:
        重新排序并重新编号的新列表（命中项 ``route_scores["entity_match"]`` 记录加成）。
    """
    wanted = {str(item).strip().upper() for item in cve_ids if str(item).strip()}
    if not wanted:
        return list(results)
    boosted: list[RetrievalResult] = []
    for item in results:
        matched = str(item.metadata.get("cve_id") or "").strip().upper() in wanted
        if not matched:
            boosted.append(item)
            continue
        route_scores = {**item.route_scores, "entity_match": bonus}
        boosted.append(item.model_copy(update={"score": round(item.score + bonus, 6), "route_scores": route_scores}))
    boosted.sort(key=lambda item: (-item.score, item.source, item.doc_id))
    for index, item in enumerate(boosted, start=1):
        item.rank = index
    return boosted


def render_structured_summary(vuln: UnifiedVuln, enriched: EnrichedVuln | None) -> str:
    """把结构化字段渲染为图谱通路的结果文本（纯函数）。

    Args:
        vuln: 漏洞事实。
        enriched: 富化结果；``None`` 时只渲染事实层字段。

    Returns:
        多行文本（组件 / 受影响版本 / 风险级别 / 攻击技术 / 关联论文）。
    """
    lines = [f"{vuln.vuln_id} {vuln.title or ''}".strip()]
    if vuln.affected_versions:
        lines.append("受影响版本: " + "; ".join(vuln.affected_versions))
    if vuln.severity:
        lines.append(f"严重度: {vuln.severity}")
    if enriched is None:
        return "\n".join(lines)
    if enriched.affected_assets:
        lines.append("受影响资产: " + ", ".join(sorted({asset.name for asset in enriched.affected_assets})))
    if enriched.attack_chain is not None and enriched.attack_chain.steps:
        techniques = ", ".join(f"{step.technique_id}({step.tactic})" for step in enriched.attack_chain.steps[:5])
        lines.append(f"攻击技术: {techniques}")
    if enriched.related_papers:
        lines.append("关联论文: " + ", ".join(link.paper_id for link in enriched.related_papers[:5]))
    lines.append(f"风险级别: {enriched.risk_level}（风险分 {enriched.risk_score}）")
    return "\n".join(lines)


def component_matches(vuln: UnifiedVuln, needle: str) -> bool:
    """判断漏洞是否与某组件相关（纯函数，PG 降级路径的组件匹配口径）。

    匹配面：``cpe_matches`` 的 ``vendor`` / ``product`` 与 ``ecosystem_packages`` 的包名，
    一律小写子串匹配（``pan-os`` 命中 ``paloaltonetworks:pan-os``）。

    Args:
        vuln: 漏洞事实。
        needle: 已小写化的组件查询串。

    Returns:
        命中返回 ``True``。
    """
    if not needle:
        return False
    for match in vuln.cpe_matches:
        if needle in match.product.lower() or needle in match.vendor.lower():
            return True
    return any(needle in package.lower() for package in vuln.ecosystem_packages)


def component_row_text(component: str, row: Mapping[str, Any]) -> str:
    """渲染「组件 → 相关漏洞」的一行文本（纯函数，Neo4j 路径）。

    Args:
        component: 查询组件。
        row: ``GraphRepository.get_related_cves`` 的返回行。

    Returns:
        形如 ``CVE-2024-3400（risk=92 critical）：标题``。
    """
    cve_id = str(row.get("cve_id") or "")
    risk = row.get("risk_score")
    level = row.get("risk_level") or ""
    return f"{cve_id}（组件 {component}｜risk={risk} {level}）：{row.get('title') or ''}".strip()


def technique_row_text(technique: str, row: Mapping[str, Any]) -> str:
    """渲染「ATT&CK 技术 → 相关漏洞」的一行文本（纯函数）。

    Args:
        technique: 查询技术 ID（如 ``T1190``）。
        row: 图谱 / PG 返回行（``cve_id`` / ``risk_score`` / ``title`` 等）。

    Returns:
        形如 ``CVE-2024-3400（技术 T1190｜risk=75.0 high，KEV）：标题``。
    """
    cve_id = str(row.get("cve_id") or "")
    risk = row.get("risk_score")
    level = row.get("risk_level") or ""
    kev = "，KEV" if row.get("kev") else ""
    return f"{cve_id}（技术 {technique}｜risk={risk} {level}{kev}）：{row.get('title') or ''}".strip()


def graph_result_from_neo4j(
    cve_id: str,
    asset_rows: Sequence[Mapping[str, Any]],
    chain_rows: Sequence[Mapping[str, Any]],
    paper_rows: Sequence[Mapping[str, Any]],
) -> RetrievalResult:
    """把 Neo4j 邻居查询结果组装为统一检索结果（纯函数）。

    Args:
        cve_id: 漏洞主键。
        asset_rows: ``get_affected_assets`` 返回行。
        chain_rows: ``get_attack_chain`` 返回行。
        paper_rows: ``get_related_papers`` 返回行。

    Returns:
        :class:`RetrievalResult`（``content`` 为多行结构化摘要）。
    """
    lines = [f"{cve_id} 图谱结构化情报"]
    for row in asset_rows:
        component = str(row.get("component") or row.get("component_key") or "")
        assets = [str(item) for item in (row.get("assets") or []) if item]
        version = row.get("version_range") or "（无区间）"
        lines.append(
            f"组件 {component}（{row.get('vendor') or ''}）受影响版本 {version}"
            + (f"；资产: {', '.join(sorted(assets))}" if assets else "")
        )
    for row in chain_rows:
        lines.append(
            f"攻击技术 {row.get('technique_id')}（{row.get('tactic') or ''}，步骤 {row.get('step_order')}）"
            f"：{row.get('description') or ''}"
        )
    for row in paper_rows:
        lines.append(
            f"关联论文 {row.get('paper_id')}（relation={row.get('relation')}，confidence={row.get('confidence')}）"
        )
    return RetrievalResult(
        source="graph",
        doc_id=f"graph:{cve_id}",
        content="\n".join(lines),
        score=1.0,
        rank=1,
        metadata={
            "cve_id": cve_id,
            "source": "neo4j",
            "hit": "cve-structure",
            "components": len(asset_rows),
            "techniques": len(chain_rows),
            "papers": len(paper_rows),
        },
    )


def fulltext_snippet(vuln: UnifiedVuln, *, limit: int = 400) -> str:
    r"""渲染全文检索结果的引用片段（纯函数）。

    Args:
        vuln: 漏洞事实。
        limit: 描述截断长度。

    Returns:
        形如 ``CVE-2024-3400 标题\n描述前 400 字`` 的文本。
    """
    head = f"{vuln.vuln_id} {vuln.title or ''}".strip()
    return f"{head}\n{vuln.description[: max(0, limit)]}".strip()


def canonical_key(result: RetrievalResult) -> str:
    """返回融合用的实体主键（纯函数）。

    优先级：``metadata.cve_id`` → ``metadata.paper_id`` → ``doc_id``。
    同一 CVE 在向量 / 全文 / 图谱三路命中时会归一到同一条融合结果，
    这正是 RRF「多路共同命中加分」得以生效的前提。

    Args:
        result: 单路检索结果。

    Returns:
        规范化实体键，如 ``cve:CVE-2024-3400``。
    """
    cve_id = str(result.metadata.get("cve_id") or "").strip().upper()
    if cve_id:
        return f"cve:{cve_id}"
    paper_id = str(result.metadata.get("paper_id") or "").strip()
    if paper_id:
        return f"paper:{paper_id}"
    return result.doc_id


def prefer_payload(candidate: RetrievalResult, current: RetrievalResult) -> bool:
    """融合时挑选「信息量更大」的代表结果（纯函数，确定性）。

    规则：内容更长者优先；等长时取 ``doc_id`` 字典序更小者（口径同
    :func:`aisec_intel.normalize.dedupe.merge_for_update` 的「description 取最长」）。

    Args:
        candidate: 新命中的结果。
        current: 已选中的结果。

    Returns:
        应改用 ``candidate`` 时返回 ``True``。
    """
    if len(candidate.content) != len(current.content):
        return len(candidate.content) > len(current.content)
    return candidate.doc_id < current.doc_id


def vector_where_from_filters(filters: Any | None, *, now: datetime | None = None) -> dict[str, Any] | None:
    """把 :class:`QueryFilters` 翻译为 Chroma ``where`` 条件（纯函数）。

    支持三类过滤：
        - ``severity`` → ``{"severity": {"$in": [...]}}``（向量元数据里的严重度）；
        - ``kev_only`` → ``{"kev": "true"}``（索引时以字符串写入，Chroma 不接受布尔外的复杂类型）；
        - ``time_range`` → ``{"published_at": {"$gte": <ISO8601 Z>}}``
          （``published_at`` 存 ISO8601 UTC 字符串，字典序即时间序）。

    Args:
        filters: :class:`QueryFilters` 实例或 ``model_dump()`` 后的字典；``None`` 表示无过滤。
        now: 时间基准（测试可注入固定值）。

    Returns:
        Chroma ``where`` 条件；无有效条件时返回 ``None``。
    """
    payload: dict[str, Any] = filters.model_dump() if isinstance(filters, QueryFilters) else dict(filters or {})
    clauses: list[dict[str, Any]] = []
    severity = [str(item) for item in (payload.get("severity") or []) if str(item).strip()]
    if severity:
        clauses.append({"severity": {"$in": severity}})
    if payload.get("kev_only"):
        clauses.append({"kev": "true"})
    days = TIME_RANGE_DAYS.get(str(payload.get("time_range") or "all"))
    if days:
        cutoff = (now or utc_now()) - timedelta(days=days)
        clauses.append(
            {"published_at": {"$gte": cutoff.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")}}
        )
    if not clauses:
        return None
    return clauses[0] if len(clauses) == 1 else {"$and": clauses}


def with_cve_filter(where: dict[str, Any] | None, cve_ids: Sequence[str]) -> dict[str, Any] | None:
    """在既有 Chroma ``where`` 上追加「CVE 编号 ∈ …」条件（纯函数）。

    Day18 任务 4 增强：问句已明确 CVE 实体时把向量检索收敛到该 CVE，
    避免哈希嵌入（容器降级路径）下的跨 CVE 误召回（``remediation_texts`` 尤其明显）。

    Args:
        where: 由 :func:`vector_where_from_filters` 生成的条件；``None`` 表示无过滤。
        cve_ids: 查询中识别出的 CVE 编号（大小写不敏感，自动去重）。

    Returns:
        合并后的 ``where``；``cve_ids`` 为空时原样返回 ``where``。

    Examples:
        >>> with_cve_filter(None, ["cve-2024-3400"])
        {'cve_id': 'CVE-2024-3400'}
        >>> with_cve_filter({"kev": "true"}, ["CVE-1", "CVE-2"])
        {'$and': [{'kev': 'true'}, {'cve_id': {'$in': ['CVE-1', 'CVE-2']}}]}
    """
    wanted: list[str] = []
    for item in cve_ids:
        key = item.strip().upper()
        if key and key not in wanted:
            wanted.append(key)
    if not wanted:
        return where
    clause: dict[str, Any] = {"cve_id": wanted[0]} if len(wanted) == 1 else {"cve_id": {"$in": wanted}}
    if not where:
        return clause
    return {"$and": [where, clause]}


@dataclass(slots=True)
class FusionOutcome:
    """一次混合检索的完整结果（供问答层与调试台消费）。

    Attributes:
        query: 检索语句。
        results: 融合排序后的结果。
        route_counts: 各路命中条数。
        errors: 非致命错误（单路失败 / 降级说明）。
        elapsed_ms: 总耗时（毫秒）。
        plan: 实际执行的检索计划。
    """

    query: str
    results: list[RetrievalResult] = field(default_factory=list)
    route_counts: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    elapsed_ms: int = 0
    plan: list[str] = field(default_factory=list)

    def top(self, limit: int = 5) -> list[RetrievalResult]:
        """取前 ``limit`` 条结果。

        Args:
            limit: 条数上限。

        Returns:
            结果切片。
        """
        return self.results[: max(0, limit)]


class RetrievalService:
    """混合检索服务（四路统一入口 + RRF 融合）。

    依赖注入（便于单测替换为内存实现）：
        ``session``      PG / SQLite 会话（全文检索 + 结构化展平）；
        ``vector_store`` Chroma 向量库；``None`` 时惰性按配置构建；
        ``graph_client`` Neo4j 客户端；``None`` 时按配置惰性构建（未启用即降级 PG）；
        ``multi_hop``    多跳遍历器；``None`` 时复用同一 ``graph_client`` 惰性构建。

    Attributes:
        session: 当前绑定的异步会话。
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        vector_store: VectorStore | None = None,
        graph_client: Neo4jClient | None = None,
        multi_hop: MultiHopTraversal | None = None,
        weights: Mapping[str, float] | None = None,
    ) -> None:
        """初始化（不建立任何连接，不加载嵌入模型）。

        Args:
            session: 异步会话（由调用方管理生命周期）。
            settings: 全局配置；``None`` 时使用进程级单例。
            vector_store: 向量库实例（可注入内存态）。
            graph_client: Neo4j 客户端（可注入桩）。
            multi_hop: 多跳遍历器（默认自建，复用 ``graph_client``）。
            weights: RRF 通路权重覆盖值。
        """
        self._session = session
        self._settings = settings or get_settings()
        self._vector_store = vector_store
        self._graph_client = graph_client
        self._multi_hop = multi_hop
        self._weights = dict(weights) if weights else dict(DEFAULT_WEIGHTS)

    @property
    def session(self) -> AsyncSession:
        """当前绑定的异步会话。"""
        return self._session

    @property
    def weights(self) -> dict[str, float]:
        """当前 RRF 权重（副本）。"""
        return dict(self._weights)

    @property
    def vector_store(self) -> VectorStore:
        """向量库（惰性构建）。

        Returns:
            :class:`~aisec_intel.storage.vector_store.VectorStore` 实例。
        """
        if self._vector_store is None:
            self._vector_store = VectorStore(settings=self._settings)
        return self._vector_store

    @property
    def multi_hop(self) -> MultiHopTraversal:
        """多跳遍历器（惰性构建，复用同一 Neo4j 客户端）。"""
        if self._multi_hop is None:
            self._multi_hop = MultiHopTraversal(
                self._session,
                settings=self._settings,
                graph_client=self._graph_client,
                prefer_graph=self._settings.neo4j_enabled,
            )
            self._graph_client = self._multi_hop._graph_client  # noqa: SLF001 - 共享同一客户端句柄
        return self._multi_hop

    def _graph_repo(self) -> GraphRepository | None:
        """返回图谱仓储（Neo4j 未启用时返回 ``None``，调用方降级 PG）。

        Returns:
            :class:`GraphRepository` 或 ``None``。
        """
        if not self._settings.neo4j_enabled:
            return None
        if self._graph_client is None:
            self._graph_client = Neo4jClient(self._settings)
        return GraphRepository(self._graph_client)

    async def vector_search(
        self,
        query: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        collections: Sequence[str] | None = None,
        where: Mapping[str, Any] | None = None,
    ) -> list[RetrievalResult]:
        """通路①：Chroma 语义检索。

        Args:
            query: 查询文本。
            top_k: 召回条数上限。
            collections: 目标集合（默认仅 :data:`COLLECTION_VULN_DESCRIPTIONS`）。
            where: 元数据过滤条件。

        Returns:
            统一结果列表（按相似度降序）。

        Raises:
            VectorStoreError: 向量库不可用（由 :meth:`hybrid_search` 捕获并留痕）。
        """
        targets = [name for name in (collections or [COLLECTION_VULN_DESCRIPTIONS]) if name in COLLECTIONS]
        if not targets or not query.strip():
            return []
        results: list[RetrievalResult] = []
        for name in targets:
            hits = await asyncio.to_thread(
                partial(self.vector_store.query, name, query, top_k=top_k, where=where)
            )
            results.extend(
                RetrievalResult(
                    source="vector",
                    doc_id=hit.doc_id,
                    content=hit.content,
                    score=round(float(hit.score), 6),
                    metadata={**hit.metadata, "collection": name},
                )
                for hit in hits
            )
        results.sort(key=lambda item: (-item.score, item.doc_id))
        for index, item in enumerate(results, start=1):
            item.rank = index
        return results[: max(0, top_k)]

    async def load_vuln_entities(self, cve_id: str) -> tuple[UnifiedVuln | None, EnrichedVuln | None]:
        """读取某 CVE 的事实层与富化层实体（图谱通路的 PG 降级入口）。

        Args:
            cve_id: 漏洞主键。

        Returns:
            ``(UnifiedVuln | None, EnrichedVuln | None)``；事实层缺失时两者皆为 ``None``。
        """
        from aisec_intel.storage.models.enriched import EnrichedVulnRow

        key = cve_id.strip().upper()
        row = await self._session.get(UnifiedVulnRow, key)
        if row is None:
            return None, None
        vuln = row.to_domain()
        enriched_row = await self._session.get(EnrichedVulnRow, key)
        return vuln, (enriched_row.to_domain(vuln) if enriched_row is not None else None)

    async def graph_search(
        self,
        query: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        cve_ids: Sequence[str] | None = None,
        components: Sequence[str] | None = None,
        techniques: Sequence[str] | None = None,
    ) -> list[RetrievalResult]:
        """通路②：Neo4j 结构化邻居查询（Neo4j 不可用 / 无数据时降级 PG JSON 展平）。

        命中优先级：CVE 编号 → 组件名 → ATT&CK 技术 ID（实体来自 ``QueryIntent``）。

        Args:
            query: 查询文本（未显式给出 ``cve_ids`` 时从中抽取 CVE 编号）。
            top_k: 返回条数上限。
            cve_ids: 显式指定的 CVE 编号。
            components: 显式指定的组件名。
            techniques: 显式指定的 ATT&CK 技术 ID（如 ``T1190``）。

        Returns:
            统一结果列表（``doc_id`` 形如 ``graph:CVE-2024-3400``）。
        """
        targets = [cve.strip().upper() for cve in (cve_ids or extract_cve_ids(query)) if cve.strip()][:MAX_TARGETS]
        results: list[RetrievalResult] = []
        for cve_id in targets:
            results.extend(await self._graph_by_cve(cve_id))
        if not targets:
            for component in [item.strip() for item in (components or []) if item.strip()][:MAX_TARGETS]:
                results.extend(await self._graph_by_component(component))
        if not results:
            for technique in [item.strip().upper() for item in (techniques or []) if item.strip()][:MAX_TARGETS]:
                results.extend(await self._graph_by_technique(technique, limit=top_k))
        results.sort(key=lambda item: (-item.score, item.doc_id))
        for index, item in enumerate(results, start=1):
            item.rank = index
        return results[: max(0, top_k)]

    async def _graph_by_cve(self, cve_id: str) -> list[RetrievalResult]:
        """按 CVE 取图谱邻居（Neo4j 优先，无数据或失败则降级 PG）。

        Args:
            cve_id: 漏洞主键。

        Returns:
            单条结构化结果（图谱有数据时）或 PG 展平结果。
        """
        repo = self._graph_repo()
        if repo is not None:
            try:
                assets = await repo.get_affected_assets(cve_id)
                chain = await repo.get_attack_chain(cve_id)
                papers = await repo.get_related_papers(cve_id)
            except Neo4jUnavailableError as exc:
                logger.warning(f"Neo4j 结构化查询失败，改走 PG 展平：{exc}")
            else:
                if assets or chain or papers:
                    return [graph_result_from_neo4j(cve_id, assets, chain, papers)]
        vuln, enriched = await self.load_vuln_entities(cve_id)
        if vuln is None:
            return []
        metadata: dict[str, Any] = {
            "cve_id": vuln.vuln_id,
            "source": "postgres",
            "hit": "cve-structure",
        }
        if vuln.severity:
            metadata["severity"] = vuln.severity
        if enriched is not None:
            metadata["risk_level"] = enriched.risk_level
        return [
            RetrievalResult(
                source="graph",
                doc_id=f"graph:{vuln.vuln_id}",
                content=render_structured_summary(vuln, enriched),
                score=1.0,
                rank=1,
                metadata=metadata,
            )
        ]

    async def _graph_by_component(self, component: str) -> list[RetrievalResult]:
        """按组件名取相关漏洞（Neo4j ``get_related_cves`` 优先，PG 扫描降级）。

        Args:
            component: 组件键（``vendor:product``）或产品名。

        Returns:
            每个相关漏洞一条结果。
        """
        repo = self._graph_repo()
        if repo is not None:
            try:
                rows = await repo.get_related_cves(component)
            except Neo4jUnavailableError as exc:
                logger.warning(f"Neo4j 组件查询失败，改走 PG 扫描：{exc}")
            else:
                if rows:
                    return [
                        RetrievalResult(
                            source="graph",
                            doc_id=f"graph:{str(row.get('cve_id'))}",
                            content=component_row_text(component, row),
                            score=round(float(row.get("risk_score") or 0.0) / 100.0, 6),
                            metadata={
                                "cve_id": str(row.get("cve_id") or ""),
                                "source": "neo4j",
                                "hit": "component-related",
                                "component": component,
                            },
                        )
                        for row in rows
                    ]

        needle = component.strip().lower()
        stmt = select(UnifiedVulnRow).order_by(UnifiedVulnRow.normalized_at.desc()).limit(MAX_SCAN_ROWS)
        rows = (await self._session.execute(stmt)).scalars().all()
        results: list[RetrievalResult] = []
        for row in rows:
            vuln = row.to_domain()
            if not component_matches(vuln, needle):
                continue
            results.append(
                RetrievalResult(
                    source="graph",
                    doc_id=f"graph:{vuln.vuln_id}",
                    content=render_structured_summary(vuln, None),
                    score=1.0,
                    metadata={
                        "cve_id": vuln.vuln_id,
                        "source": "postgres",
                        "hit": "component-related",
                        "component": component,
                    },
                )
            )
        return results

    async def _graph_by_technique(self, technique: str, *, limit: int = DEFAULT_TOP_K) -> list[RetrievalResult]:
        """按 ATT&CK 技术 ID 取利用该技术的漏洞（Neo4j ``EXPLOITS`` 反向查询，PG 降级扫描）。

        Args:
            technique: 技术 ID（如 ``T1190``，大小写不敏感）。
            limit: 返回条数上限。

        Returns:
            每个相关漏洞一条结果（``doc_id`` 形如 ``graph:CVE-2024-3400``）。
        """
        key = technique.strip().upper()
        repo = self._graph_repo()
        if repo is not None:
            try:
                rows = await repo.client.run(
                    CYPHER_TECHNIQUE_CVES, {"techniques": [key], "limit": max(1, limit)}
                )
            except Neo4jUnavailableError as exc:
                logger.warning(f"Neo4j 技术维度查询失败，改走 PG 扫描：{exc}")
            else:
                if rows:
                    return [
                        RetrievalResult(
                            source="graph",
                            doc_id=f"graph:{str(row.get('cve_id'))}",
                            content=technique_row_text(key, row),
                            score=round(float(row.get("risk_score") or 0.0) / 100.0, 6),
                            metadata={
                                "cve_id": str(row.get("cve_id") or ""),
                                "source": "neo4j",
                                "hit": "technique-related",
                                "technique_id": str(row.get("technique_id") or key),
                            },
                        )
                        for row in rows
                    ]

        return [
            RetrievalResult(
                source="graph",
                doc_id=f"graph:{row['cve_id']}",
                content=technique_row_text(key, row),
                score=round(float(row.get("risk_score") or 0.0) / 100.0, 6),
                metadata={
                    "cve_id": str(row["cve_id"]),
                    "source": "postgres",
                    "hit": "technique-related",
                    "technique_id": str(row.get("technique_id") or key),
                },
            )
            for row in await collect_technique_rows(self._session, [key], limit=MAX_SCAN_ROWS)
        ]

    async def fulltext_search(
        self,
        query: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        keywords: Sequence[str] | None = None,
    ) -> list[RetrievalResult]:
        """通路③：全文检索（PG 用 ``ts_rank``；SQLite / 降级模式用 Python 词元打分）。

        Args:
            query: 查询文本。
            top_k: 返回条数上限。
            keywords: 追加关键词（与 ``query`` 的切词结果**合并**，避免中文线索丢失）。

        Returns:
            统一结果列表（按得分降序）。
        """
        terms = query_keywords(" ".join([query, *(keywords or [])]).strip())
        if not terms or not query.strip():
            return []
        if self._dialect_name() == "postgresql":
            rows = await self._pg_fulltext(terms, top_k)
        else:
            rows = await self._python_fulltext(terms, top_k)
        results: list[RetrievalResult] = []
        for score, vuln in rows:
            metadata: dict[str, Any] = {"cve_id": vuln.vuln_id, "source": "fulltext", "hit": "fts"}
            if vuln.severity:
                metadata["severity"] = vuln.severity
            if vuln.published_at is not None:
                metadata["published_at"] = iso_z(vuln.published_at)
            results.append(
                RetrievalResult(
                    source="fulltext",
                    doc_id=f"unified_vuln:{vuln.vuln_id}",
                    content=fulltext_snippet(vuln),
                    score=round(float(score), 6),
                    metadata=metadata,
                )
            )
        for index, item in enumerate(results, start=1):
            item.rank = index
        return results

    def _dialect_name(self) -> str:
        """当前会话的数据库方言名（``postgresql`` / ``sqlite``）。

        Returns:
            方言名小写字符串。
        """
        return str(self._session.get_bind().dialect.name)

    async def _pg_fulltext(self, keywords: Sequence[str], top_k: int) -> list[tuple[float, UnifiedVuln]]:
        """PostgreSQL 全文检索（``to_tsquery`` OR 语义 + ``ts_rank``）。

        Args:
            keywords: 查询词元（与 SQLite 降级路径同一套切词口径）。
            top_k: 返回条数上限。

        Returns:
            ``(得分, 漏洞实体)`` 列表（无有效词元时返回空列表）。
        """
        tsquery = build_tsquery(keywords)
        if not tsquery:
            return []
        rows = (
            (await self._session.execute(text(PG_FULLTEXT_SQL), {"tsquery": tsquery, "limit": max(1, top_k)}))
            .mappings()
            .all()
        )
        scored: list[tuple[float, UnifiedVuln]] = []
        for row in rows:
            entity = await self._session.get(UnifiedVulnRow, str(row["vuln_id"]))
            if entity is None:  # pragma: no cover - 同一事务内不可能缺失
                continue
            scored.append((float(row["score"] or 0.0), entity.to_domain()))
        return scored

    async def _python_fulltext(self, keywords: Sequence[str], top_k: int) -> list[tuple[float, UnifiedVuln]]:
        """Python 词元打分（SQLite / 降级模式的全文检索实现，跨库口径一致）。

        Args:
            keywords: 查询词元。
            top_k: 返回条数上限。

        Returns:
            ``(得分, 漏洞实体)`` 列表（按得分降序、CVE 编号升序稳定排序）。
        """
        stmt = (
            select(UnifiedVulnRow)
            .order_by(UnifiedVulnRow.published_at.desc().nullslast(), UnifiedVulnRow.normalized_at.desc())
            .limit(MAX_SCAN_ROWS)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        scored: list[tuple[float, UnifiedVuln]] = []
        for row in rows:
            vuln = row.to_domain()
            score = python_fulltext_score(f"{vuln.title or ''} {vuln.description}", keywords)
            if score > 0.0:
                scored.append((score, vuln))
        scored.sort(key=lambda item: (-item[0], item[1].vuln_id))
        return scored[: max(0, top_k)]

    async def multi_hop_search(
        self,
        query: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        cve_ids: Sequence[str] | None = None,
        patterns: Sequence[str] | None = None,
    ) -> list[RetrievalResult]:
        """通路④：2 跳图遍历（Neo4j 或 PG JSON 降级）。

        Args:
            query: 查询文本（未显式给出 ``cve_ids`` 时从中抽取 CVE 编号）。
            top_k: 返回条数上限。
            cve_ids: 显式指定的 CVE 编号（来自 ``QueryIntent.entities``）。
            patterns: 路径模式白名单；``None`` 表示两条都跑。

        Returns:
            统一结果列表（每个「CVE × 路径模式」一条）。
        """
        targets = [cve.strip().upper() for cve in (cve_ids or extract_cve_ids(query)) if cve.strip()][:MAX_TARGETS]
        if not targets:
            return []
        results: list[RetrievalResult] = []
        for cve_id in targets:
            outcomes = await self.multi_hop.traverse(cve_id, patterns=patterns, limit=max(1, top_k))
            for outcome in outcomes:
                if not outcome.paths:
                    continue
                lines = outcome.render_lines(limit=max(1, top_k))
                has_two_hop = any(path.hops >= 2 for path in outcome.paths)
                results.append(
                    RetrievalResult(
                        source="multi_hop",
                        doc_id=f"multi_hop:{outcome.pattern}:{cve_id}",
                        content=f"{cve_id} {outcome.pattern}（{outcome.source}）：\n" + "\n".join(lines),
                        score=1.0 if has_two_hop else 0.5,
                        metadata={
                            "cve_id": cve_id,
                            "source": outcome.source,
                            "hit": outcome.pattern,
                            "paths": len(outcome.paths),
                            "degraded": outcome.degraded,
                        },
                    )
                )
        results.sort(key=lambda item: (-item.score, item.doc_id))
        for index, item in enumerate(results, start=1):
            item.rank = index
        return results[: max(0, top_k)]

    async def dispatch(
        self,
        route: str,
        query: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        cve_ids: Sequence[str] | None = None,
        components: Sequence[str] | None = None,
        techniques: Sequence[str] | None = None,
        collections: Sequence[str] | None = None,
        where: Mapping[str, Any] | None = None,
        keywords: Sequence[str] | None = None,
    ) -> list[RetrievalResult]:
        """按通路名分发到具体检索方法（Supervisor 与调试台共用的唯一入口）。

        Args:
            route: 通路名（``vector`` / ``graph`` / ``fulltext`` / ``multi_hop``）。
            query: 查询文本。
            top_k: 返回条数上限。
            cve_ids: 显式 CVE 实体。
            components: 显式组件实体。
            techniques: 显式 ATT&CK 技术实体（如 ``T1190``）。
            collections: 向量集合白名单。
            where: 向量元数据过滤条件。
            keywords: 全文检索关键词覆盖值。

        Returns:
            统一结果列表。

        Raises:
            RetrievalError: 未声明的通路名。
        """
        if route == "vector":
            return await self.vector_search(query, top_k=top_k, collections=collections, where=where)
        if route == "graph":
            return await self.graph_search(
                query, top_k=top_k, cve_ids=cve_ids, components=components, techniques=techniques
            )
        if route == "fulltext":
            return await self.fulltext_search(query, top_k=top_k, keywords=keywords)
        if route == "multi_hop":
            return await self.multi_hop_search(query, top_k=top_k, cve_ids=cve_ids)
        raise RetrievalError(f"未声明的检索通路：{route}（可选：{', '.join(RETRIEVAL_ROUTES)}）")

    async def hybrid_search(
        self,
        query: str,
        *,
        plan: Sequence[str] | None = None,
        top_k: int = DEFAULT_TOP_K,
        cve_ids: Sequence[str] | None = None,
        components: Sequence[str] | None = None,
        techniques: Sequence[str] | None = None,
        collections: Sequence[str] | None = None,
        filters: Mapping[str, Any] | None = None,
        keywords: Sequence[str] | None = None,
    ) -> FusionOutcome:
        """混合检索：并发执行计划中的各通路，RRF 融合为统一排序。

        Args:
            query: 查询文本。
            plan: 检索计划（通路名序列）；``None`` 时默认 ``vector + fulltext + graph``。
            top_k: 单路召回与最终返回的条数上限。
            cve_ids: 显式 CVE 实体（来自 ``QueryIntent``）。
            components: 显式组件实体（来自 ``QueryIntent``）。
            techniques: 显式 ATT&CK 技术实体（来自 ``QueryIntent``）。
            collections: 向量集合白名单。
            filters: ``QueryFilters.model_dump()`` 形式的过滤条件（用于构造向量 ``where``）。
            keywords: 全文检索关键词覆盖值。

        Returns:
            :class:`FusionOutcome`（含各路命中数、错误与总耗时）。

        Note:
            ``asyncio.gather(return_exceptions=True)`` 保证**单路失败不影响其它路**，
            失败原因写入 ``errors`` 并在日志留痕。
        """
        started = time.perf_counter()
        routes = normalize_plan(list(plan)) if plan else ["vector", "fulltext", "graph"]
        where = vector_where_from_filters(filters)
        calls = [
            (
                route,
                self.dispatch(
                    route,
                    query,
                    top_k=top_k,
                    cve_ids=cve_ids,
                    components=components,
                    techniques=techniques,
                    collections=collections,
                    where=where,
                    keywords=keywords,
                ),
            )
            for route in routes
        ]
        gathered = await asyncio.gather(*(call for _, call in calls), return_exceptions=True)

        channels: dict[str, list[RetrievalResult]] = {}
        counts: dict[str, int] = {}
        errors: list[str] = []
        failed_routes: list[str] = []
        for (route, _), outcome in zip(calls, gathered, strict=True):
            if isinstance(outcome, BaseException):
                channels[route] = []
                counts[route] = 0
                errors.append(f"{route}: {type(outcome).__name__}: {outcome}")
                failed_routes.append(route)
                logger.warning(f"检索通路失败（已降级继续）：{route} -> {type(outcome).__name__}: {outcome}")
                log_self_heal(
                    SelfHealEvent(
                        component=COMPONENT_QA,
                        action=ACTION_DEGRADED,
                        reason=f"{type(outcome).__name__}: {outcome}",
                        label=route,
                        details={"fallback": _fallback_of(route)},
                    )
                )
                continue
            channels[route] = list(outcome)
            counts[route] = len(outcome)
            if not outcome:
                errors.append(f"{route}: 0 命中（可能缺少实体、索引未建或数据未就绪）")

        # 自愈 ③（Day17 任务 4.3）：向量库不可用 → 自动补一路全文检索，保证「有召回」
        if "vector" in failed_routes and "fulltext" not in channels:
            try:
                fallback_hits = await self.fulltext_search(query, top_k=top_k, keywords=keywords)
            except Exception as exc:  # noqa: BLE001 - 兜底通路失败也不得影响其它路
                errors.append(f"fulltext(兜底): {type(exc).__name__}: {exc}")
            else:
                channels["fulltext"] = list(fallback_hits)
                counts["fulltext"] = len(fallback_hits)
                routes = [*routes, "fulltext"]
                log_self_heal(
                    SelfHealEvent(
                        component=COMPONENT_QA,
                        action=ACTION_FALLBACK,
                        reason="向量检索不可用，自动降级到全文检索",
                        label="vector->fulltext",
                        details={"hits": len(fallback_hits)},
                    )
                )

        fused = reciprocal_rank_fusion(channels, k=DEFAULT_RRF_K, weights=self._weights, top_k=top_k)
        boosted = boost_entity_matches(fused, cve_ids=cve_ids or extract_cve_ids(query))
        return FusionOutcome(
            query=query,
            results=boosted,
            route_counts=counts,
            errors=errors,
            elapsed_ms=max(0, int((time.perf_counter() - started) * 1000)),
            plan=routes,
        )

    async def aclose(self) -> None:
        """释放本服务创建的向量库与 Neo4j 客户端（幂等）。"""
        if self._vector_store is not None:
            self._vector_store.close()
        if self._multi_hop is not None:
            await self._multi_hop.aclose()
            self._graph_client = None
        elif self._graph_client is not None:
            await self._graph_client.aclose()
            self._graph_client = None
