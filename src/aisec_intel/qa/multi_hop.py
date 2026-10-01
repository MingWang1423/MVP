"""多跳图遍历原型（Day10 P6 收尾；PROJECT_PLAN.md §5.8 问答检索前置 / §11.1 图谱降级）。

两条 **2 跳**路径（问答层「关联型」问题的核心能力）：

=======================================  ==================================================
路径                                      说明
=======================================  ==================================================
``CVE → Component → Asset``              漏洞影响哪些组件、这些组件装在哪些资产上
``CVE → AttackTechnique → CVE``          同一攻击技术还被哪些其它漏洞使用（横向扩展）
=======================================  ==================================================

双通道数据源（同一份 ``MultiHopPath`` 输出，下游无感）：

1. **Neo4j**（首选）：Cypher 参数化查询，标签/关系类型取自 :mod:`aisec_intel.graph.schema` 白名单；
2. **PostgreSQL JSON 降级**（§11.1：``NEO4J_ENABLED=false`` 时图谱查询降级为 PG JSON，跳数 ≤2）：
   第 1 跳用 ``unified_vuln.cpe_matches`` / ``enriched_vuln.attack_chain`` 展开，
   第 2 跳在 Python 侧做集合运算（JSON 匹配一律在 Python 完成，跨 PG/SQLite 行为一致）。

确定性约定（禁止 LLM）：
    - ``Component → Asset`` 沿用电网抽取器的「同漏洞共现」口径（``derived_from="cve-cooccurrence"``），
      与 :func:`aisec_intel.graph.extractor.extract_graph` 完全一致，避免图谱与降级路径结论打架；
    - 所有路径输出**排序稳定**，可重复断言。
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from typing import Any, Literal

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.config import Settings, get_settings
from aisec_intel.graph.schema import (
    NODE_ASSET,
    NODE_ATTACK_TECHNIQUE,
    NODE_COMPONENT,
    NODE_VULNERABILITY,
    RELATION_AFFECTS,
    RELATION_EXPLOITS,
    RELATION_INSTALLED_ON,
)
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import IntelBaseModel
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import CpeMatch, UnifiedVuln
from aisec_intel.normalize.pipeline import render_version_range
from aisec_intel.storage.models.enriched import EnrichedVulnRow
from aisec_intel.storage.models.vuln import UnifiedVulnRow
from aisec_intel.storage.neo4j_client import Neo4jClient, Neo4jUnavailableError

logger = get_logger(__name__)

PATTERN_CVE_ASSET: str = "CVE->Component->Asset"
"""路径模式①：漏洞 → 组件 → 资产。"""

PATTERN_CVE_TECHNIQUE: str = "CVE->AttackTechnique->CVE"
"""路径模式②：漏洞 → 攻击技术 → 相关漏洞。"""

COOCCURRENCE_SOURCE: str = "cve-cooccurrence"
"""``Component → Asset`` 边的推断来源标记（与图谱抽取器一致）。"""

DEFAULT_LIMIT: int = 20
"""单次多跳查询返回的路径条数上限。"""

MAX_SCAN_ROWS: int = 2000
"""PG 降级路径的最大扫描行数（防止大表拖垮查询）。"""

CYPHER_CVE_ASSETS: str = (
    f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[r:{RELATION_AFFECTS}]->(c:{NODE_COMPONENT}) "
    f"OPTIONAL MATCH (c)-[i:{RELATION_INSTALLED_ON}]->(a:{NODE_ASSET}) "
    "RETURN c.key AS component_key, c.name AS component, c.vendor AS vendor, "
    "c.ecosystem AS ecosystem, c.version_range AS version_range, r.derived_from AS affects_source, "
    "a.key AS asset_key, a.name AS asset_name, a.asset_type AS asset_type, "
    "i.derived_from AS link_source, i.confidence AS asset_confidence "
    "ORDER BY component_key, asset_key LIMIT $limit"
)
"""``CVE → Component → Asset`` 的 Cypher（标签/关系取自白名单常量，参数化，无拼接注入面）。"""

CYPHER_CVE_TECHNIQUES: str = (
    f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[r:{RELATION_EXPLOITS}]->(t:{NODE_ATTACK_TECHNIQUE}) "
    f"OPTIONAL MATCH (t)<-[o:{RELATION_EXPLOITS}]-(other:{NODE_VULNERABILITY}) "
    "WHERE other.cve_id <> $cve_id "
    "RETURN t.technique_id AS technique_id, t.tactic AS tactic, t.description AS technique_description, "
    "r.order AS step_order, other.cve_id AS cve_id, other.title AS title, "
    "other.risk_score AS risk_score, other.risk_level AS risk_level, other.kev AS kev "
    "ORDER BY technique_id, risk_score DESC LIMIT $limit"
)
"""``CVE → AttackTechnique → CVE`` 的 Cypher。"""

_CVE_PATTERN: re.Pattern[str] = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
"""CVE 编号识别（用于从自然语言中抽取查询目标）。"""


def extract_cve_ids(text: str) -> list[str]:
    """从任意文本中抽取 CVE 编号（大写、去重保序，纯函数）。

    Args:
        text: 任意文本（用户问题 / 查询串）。

    Returns:
        CVE 编号列表。
    """
    seen: set[str] = set()
    result: list[str] = []
    for match in _CVE_PATTERN.findall(text or ""):
        cve_id = match.upper()
        if cve_id not in seen:
            seen.add(cve_id)
            result.append(cve_id)
    return result


class MultiHopStep(IntelBaseModel):
    """路径中的一跳（起点 → 终点）。

    Attributes:
        relation: 关系类型（``AFFECTS`` / ``INSTALLED_ON`` / ``EXPLOITS``）。
        from_label: 起点节点标签。
        from_key: 起点节点键。
        from_name: 起点显示名。
        to_label: 终点节点标签。
        to_key: 终点节点键。
        to_name: 终点显示名。
        properties: 边属性（如 ``derived_from`` / ``order``）。
    """

    relation: str = Field(description="关系类型")
    from_label: str
    from_key: str
    from_name: str = ""
    to_label: str
    to_key: str
    to_name: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)


class MultiHopPath(IntelBaseModel):
    """一条（≤2 跳的）图路径。

    Attributes:
        pattern: 路径模式（见 :data:`PATTERN_CVE_ASSET` / :data:`PATTERN_CVE_TECHNIQUE`）。
        start_key: 起点节点键（通常为 CVE 编号）。
        steps: 逐跳明细（长度即实际跳数）。
        source: 数据来源（``neo4j`` / ``postgres``）。
    """

    pattern: str
    start_key: str
    steps: list[MultiHopStep] = Field(default_factory=list, description="逐跳明细（长度=实际跳数）")
    source: Literal["neo4j", "postgres"] = "postgres"

    @property
    def hops(self) -> int:
        """实际跳数。"""
        return len(self.steps)

    @property
    def end_key(self) -> str:
        """终点节点键（无跳时返回起点键）。"""
        return self.steps[-1].to_key if self.steps else self.start_key

    def render(self) -> str:
        """渲染为可读的一行路径（供检索结果内容与前端展示）。

        Returns:
            形如 ``CVE-2024-3400 -[AFFECTS]-> PAN-OS -[INSTALLED_ON]-> PAN-OS Firewall``。
        """
        if not self.steps:
            return f"{self.start_key}（无路径）"
        parts = [self.start_key]
        for step in self.steps:
            parts.append(f"-[{step.relation}]-> {step.to_name or step.to_key}")
        return " ".join(parts)


class MultiHopResult(IntelBaseModel):
    """一次多跳查询的结果集。

    Attributes:
        cve_id: 查询起点漏洞编号。
        pattern: 路径模式。
        source: 数据来源（``neo4j`` / ``postgres``）。
        paths: 路径列表（排序稳定）。
        elapsed_ms: 耗时（毫秒）。
        degraded: 是否走了 PG 降级路径。
        note: 降级 / 无数据说明。
    """

    cve_id: str
    pattern: str
    source: Literal["neo4j", "postgres"] = "postgres"
    paths: list[MultiHopPath] = Field(default_factory=list)
    elapsed_ms: int = 0
    degraded: bool = False
    note: str | None = None

    def render_lines(self, *, limit: int = DEFAULT_LIMIT) -> list[str]:
        """渲染路径文本行（供 ``RetrievalResult.content`` 使用）。

        Args:
            limit: 最多输出行数。

        Returns:
            文本行列表（无路径时为空列表）。
        """
        return [path.render() for path in self.paths[: max(0, limit)]]


def prune_none(properties: dict[str, Any]) -> dict[str, Any]:
    """剔除值为 ``None`` 的属性（纯函数；Chroma / 前端均不接受 ``None``）。"""
    return {key: value for key, value in properties.items() if value is not None}


def component_key_of(match: CpeMatch) -> str:
    """返回组件的图节点键（``vendor:product``，与图谱抽取器一致，纯函数）。

    Args:
        match: CPE 匹配条目。

    Returns:
        组件键，如 ``paloaltonetworks:pan-os``。
    """
    return f"{match.vendor.strip().lower()}:{match.product.strip().lower()}"


def component_entries(vuln: UnifiedVuln) -> list[tuple[str, str, dict[str, Any]]]:
    """由漏洞事实抽取「组件」条目（纯函数，第 1 跳起点集合）。

    来源：``cpe_matches``（键 ``vendor:product``）+ ``ecosystem_packages``（键为包标识）。

    Args:
        vuln: L2 归一化实体。

    Returns:
        ``(key, name, properties)`` 列表，按 ``key`` 排序去重。
    """
    entries: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for match in vuln.cpe_matches:
        key = component_key_of(match)
        entries.setdefault(
            key,
            (
                key,
                match.product,
                prune_none(
                    {
                        "vendor": match.vendor,
                        "version_range": render_version_range(match),
                        "vulnerable": match.vulnerable,
                    }
                ),
            ),
        )
    for package in vuln.ecosystem_packages:
        name = package.split(":")[-1].strip()
        ecosystem = package.split(":")[0].strip() if ":" in package else None
        if name and package not in entries:
            entries[package] = (package, name, prune_none({"ecosystem": ecosystem}))
    return [entries[key] for key in sorted(entries)]


def asset_entries(enriched: EnrichedVuln | None) -> list[tuple[str, str, dict[str, Any]]]:
    """由富化结果抽取「资产」条目（纯函数，第 2 跳终点集合）。

    Args:
        enriched: L3 富化实体；``None``（未富化）时返回空列表。

    Returns:
        ``(key, name, properties)`` 列表，按 ``key`` 排序去重。
    """
    if enriched is None:
        return []
    entries: dict[str, tuple[str, str, dict[str, Any]]] = {}
    for asset in enriched.affected_assets:
        key = f"{asset.asset_type}:{asset.name}"
        entries.setdefault(
            key,
            (
                key,
                asset.name,
                prune_none(
                    {
                        "asset_type": asset.asset_type,
                        "vendor": asset.vendor,
                        "version_range": asset.version_range,
                        "confidence": asset.confidence,
                    }
                ),
            ),
        )
    return [entries[key] for key in sorted(entries)]


def build_asset_paths(
    cve_id: str,
    components: Sequence[tuple[str, str, dict[str, Any]]],
    assets: Sequence[tuple[str, str, dict[str, Any]]],
    *,
    source: Literal["neo4j", "postgres"] = "postgres",
) -> list[MultiHopPath]:
    """组装 ``CVE → Component → Asset`` 路径（纯函数）。

    ``Component → Asset`` 采用「同漏洞共现」口径（与 :mod:`aisec_intel.graph.extractor` 一致），
    边属性 ``derived_from`` 明示该关系为推断，避免被误读为 SBOM 事实。

    Args:
        cve_id: 漏洞主键。
        components: :func:`component_entries` 的输出。
        assets: :func:`asset_entries` 的输出。
        source: 数据来源标记。

    Returns:
        路径列表（按组件键、资产键稳定排序）。
    """
    paths: list[MultiHopPath] = []
    for component_key, component_name, component_props in components:
        steps = [
            MultiHopStep(
                relation=RELATION_AFFECTS,
                from_label=NODE_VULNERABILITY,
                from_key=cve_id,
                from_name=cve_id,
                to_label=NODE_COMPONENT,
                to_key=component_key,
                to_name=component_name,
                properties=prune_none({"version_range": component_props.get("version_range")}),
            )
        ]
        for asset_key, asset_name, asset_props in assets:
            steps_with_asset = [
                *steps,
                MultiHopStep(
                    relation=RELATION_INSTALLED_ON,
                    from_label=NODE_COMPONENT,
                    from_key=component_key,
                    from_name=component_name,
                    to_label=NODE_ASSET,
                    to_key=asset_key,
                    to_name=asset_name,
                    properties=prune_none(
                        {"derived_from": COOCCURRENCE_SOURCE, "confidence": asset_props.get("confidence")}
                    ),
                ),
            ]
            paths.append(
                MultiHopPath(pattern=PATTERN_CVE_ASSET, start_key=cve_id, steps=steps_with_asset, source=source)
            )
        if not assets:
            paths.append(MultiHopPath(pattern=PATTERN_CVE_ASSET, start_key=cve_id, steps=steps, source=source))
    return paths


def technique_entries(enriched: EnrichedVuln | None) -> list[tuple[str, dict[str, Any]]]:
    """由富化结果抽取「攻击技术」条目（纯函数，第 1 跳终点集合）。

    Args:
        enriched: L3 富化实体；无攻击链时返回空列表。

    Returns:
        ``(technique_id, properties)`` 列表（按技术 ID 排序去重）。
    """
    chain = None if enriched is None else enriched.attack_chain
    if chain is None:
        return []
    entries: dict[str, dict[str, Any]] = {}
    for step in chain.steps:
        technique_id = step.technique_id.strip().upper()
        if technique_id and technique_id not in entries:
            entries[technique_id] = prune_none({"tactic": step.tactic, "stage": step.stage, "order": step.order})
    return [(technique_id, entries[technique_id]) for technique_id in sorted(entries)]


def build_technique_paths(
    cve_id: str,
    techniques: Sequence[tuple[str, dict[str, Any]]],
    related: Sequence[dict[str, Any]],
    *,
    source: Literal["neo4j", "postgres"] = "postgres",
) -> list[MultiHopPath]:
    """组装 ``CVE → AttackTechnique → CVE`` 路径（纯函数）。

    Args:
        cve_id: 起点漏洞主键。
        techniques: :func:`technique_entries` 的输出。
        related: 候选「相关漏洞」行（需含 ``technique_id`` / ``cve_id`` / ``risk_score`` 等键）。
        source: 数据来源标记。

    Returns:
        路径列表（按技术 ID、风险分降序、CVE 编号稳定排序）。
    """
    paths: list[MultiHopPath] = []
    for technique_id, properties in techniques:
        head = MultiHopStep(
            relation=RELATION_EXPLOITS,
            from_label=NODE_VULNERABILITY,
            from_key=cve_id,
            from_name=cve_id,
            to_label=NODE_ATTACK_TECHNIQUE,
            to_key=technique_id,
            to_name=str(properties.get("tactic") or technique_id),
            properties=prune_none({"tactic": properties.get("tactic"), "order": properties.get("order")}),
        )
        matches = [row for row in related if str(row.get("technique_id", "")).strip().upper() == technique_id]
        matches.sort(key=lambda row: (-float(row.get("risk_score") or 0.0), str(row.get("cve_id") or "")))
        for row in matches:
            other = str(row.get("cve_id") or "").strip().upper()
            if not other or other == cve_id:
                continue
            paths.append(
                MultiHopPath(
                    pattern=PATTERN_CVE_TECHNIQUE,
                    start_key=cve_id,
                    steps=[
                        head,
                        MultiHopStep(
                            relation=RELATION_EXPLOITS,
                            from_label=NODE_ATTACK_TECHNIQUE,
                            from_key=technique_id,
                            from_name=str(properties.get("tactic") or technique_id),
                            to_label=NODE_VULNERABILITY,
                            to_key=other,
                            to_name=str(row.get("title") or other),
                            properties=prune_none(
                                {
                                    "risk_score": row.get("risk_score"),
                                    "risk_level": row.get("risk_level"),
                                    "kev": row.get("kev"),
                                }
                            ),
                        ),
                    ],
                    source=source,
                )
            )
        if not matches:
            paths.append(MultiHopPath(pattern=PATTERN_CVE_TECHNIQUE, start_key=cve_id, steps=[head], source=source))
    return paths


def paths_from_graph_asset_rows(
    cve_id: str,
    rows: Sequence[dict[str, Any]],
    *,
    source: Literal["neo4j", "postgres"] = "neo4j",
) -> list[MultiHopPath]:
    """把 ``CYPHER_CVE_ASSETS`` 的返回行解析为路径（纯函数）。

    Args:
        cve_id: 漏洞主键。
        rows: Cypher 返回行（``component_key`` / ``asset_key`` 等；未匹配资产时为 ``None``）。
        source: 数据来源标记。

    Returns:
        路径列表（组件 / 资产均按行序，Cypher 已 ``ORDER BY``）。
    """
    paths: list[MultiHopPath] = []
    for row in rows:
        component_key = str(row.get("component_key") or "").strip()
        if not component_key:
            continue
        component_name = str(row.get("component") or component_key)
        steps = [
            MultiHopStep(
                relation=RELATION_AFFECTS,
                from_label=NODE_VULNERABILITY,
                from_key=cve_id,
                from_name=cve_id,
                to_label=NODE_COMPONENT,
                to_key=component_key,
                to_name=component_name,
                properties=prune_none(
                    {
                        "vendor": row.get("vendor"),
                        "ecosystem": row.get("ecosystem"),
                        "version_range": row.get("version_range"),
                    }
                ),
            )
        ]
        asset_key = row.get("asset_key")
        if asset_key:
            steps.append(
                MultiHopStep(
                    relation=RELATION_INSTALLED_ON,
                    from_label=NODE_COMPONENT,
                    from_key=component_key,
                    from_name=component_name,
                    to_label=NODE_ASSET,
                    to_key=str(asset_key),
                    to_name=str(row.get("asset_name") or asset_key),
                    properties=prune_none(
                        {
                            "derived_from": row.get("link_source") or COOCCURRENCE_SOURCE,
                            "confidence": row.get("asset_confidence"),
                            "asset_type": row.get("asset_type"),
                        }
                    ),
                )
            )
        paths.append(MultiHopPath(pattern=PATTERN_CVE_ASSET, start_key=cve_id, steps=steps, source=source))
    return paths


def paths_from_graph_technique_rows(
    cve_id: str,
    rows: Sequence[dict[str, Any]],
    *,
    source: Literal["neo4j", "postgres"] = "neo4j",
) -> list[MultiHopPath]:
    """把 ``CYPHER_CVE_TECHNIQUES`` 的返回行解析为路径（纯函数）。

    Args:
        cve_id: 漏洞主键。
        rows: Cypher 返回行（``technique_id`` / ``cve_id`` 等；无相关漏洞时为 ``None``）。
        source: 数据来源标记。

    Returns:
        路径列表（技术 ID、风险分降序稳定排序）。
    """
    paths: list[MultiHopPath] = []
    for row in rows:
        technique_id = str(row.get("technique_id") or "").strip().upper()
        if not technique_id:
            continue
        tactic = row.get("tactic")
        steps = [
            MultiHopStep(
                relation=RELATION_EXPLOITS,
                from_label=NODE_VULNERABILITY,
                from_key=cve_id,
                from_name=cve_id,
                to_label=NODE_ATTACK_TECHNIQUE,
                to_key=technique_id,
                to_name=str(tactic or technique_id),
                properties=prune_none({"tactic": tactic, "order": row.get("step_order")}),
            )
        ]
        other = str(row.get("cve_id") or "").strip().upper()
        if other and other != cve_id:
            steps.append(
                MultiHopStep(
                    relation=RELATION_EXPLOITS,
                    from_label=NODE_ATTACK_TECHNIQUE,
                    from_key=technique_id,
                    from_name=str(tactic or technique_id),
                    to_label=NODE_VULNERABILITY,
                    to_key=other,
                    to_name=str(row.get("title") or other),
                    properties=prune_none(
                        {
                            "risk_score": row.get("risk_score"),
                            "risk_level": row.get("risk_level"),
                            "kev": row.get("kev"),
                        }
                    ),
                )
            )
        paths.append(MultiHopPath(pattern=PATTERN_CVE_TECHNIQUE, start_key=cve_id, steps=steps, source=source))
    return paths


class MultiHopTraversal:
    """2 跳图遍历器（Neo4j 优先，PG JSON 降级）。

    Attributes:
        session: PG / SQLite 异步会话（降级路径与实体读取用）。
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        graph_client: Neo4jClient | None = None,
        prefer_graph: bool | None = None,
    ) -> None:
        """初始化遍历器（不建立任何连接）。

        Args:
            session: 异步会话（由调用方管理生命周期）。
            settings: 全局配置；``None`` 时使用进程级单例。
            graph_client: 复用外部 Neo4j 客户端；``None`` 时按需自建（并负责关闭）。
            prefer_graph: 是否优先走 Neo4j；``None`` 时取 ``NEO4J_ENABLED``。
        """
        self._session = session
        self._settings = settings or get_settings()
        self._graph_client = graph_client
        self._owns_client = graph_client is None
        self._prefer_graph = self._settings.neo4j_enabled if prefer_graph is None else prefer_graph
        self._graph_ready: bool | None = None

    @property
    def session(self) -> AsyncSession:
        """当前绑定的异步会话。"""
        return self._session

    async def graph_available(self) -> bool:
        """探活 Neo4j（结果缓存；不可用时整段遍历自动降级为 PG，不抛异常）。

        Returns:
            可用返回 ``True``。
        """
        if not self._prefer_graph:
            return False
        if self._graph_ready is not None:
            return self._graph_ready
        client = self._graph_client or Neo4jClient(self._settings)
        self._graph_client = client
        try:
            self._graph_ready = await client.ping()
        except Exception as exc:  # noqa: BLE001 - 探活失败一律视为不可用（降级）
            logger.warning(f"Neo4j 探活异常，降级为 PG JSON：{type(exc).__name__}: {exc}")
            self._graph_ready = False
        if not self._graph_ready:
            logger.warning("Neo4j 不可用：多跳遍历降级为 PG JSON（跳数 ≤2）")
        return bool(self._graph_ready)

    async def _load_entities(self, cve_id: str) -> tuple[UnifiedVuln | None, EnrichedVuln | None]:
        """从 PG 读取起点漏洞的事实层与富化层（缺失时返回 ``None``）。

        Args:
            cve_id: 漏洞主键。

        Returns:
            ``(UnifiedVuln | None, EnrichedVuln | None)``。
        """
        key = cve_id.strip().upper()
        row = await self._session.get(UnifiedVulnRow, key)
        if row is None:
            return None, None
        vuln = row.to_domain()
        enriched_row = await self._session.get(EnrichedVulnRow, key)
        enriched = enriched_row.to_domain(vuln) if enriched_row is not None else None
        return vuln, enriched

    async def _pg_related_technique_rows(
        self, techniques: Sequence[tuple[str, dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        """扫描 ``enriched_vuln`` 找出使用同一批攻击技术的其它漏洞（PG 降级第 2 跳）。

        Args:
            techniques: :func:`technique_entries` 的输出。

        Returns:
            形如 ``{"technique_id", "cve_id", "title", "risk_score", "risk_level", "kev"}`` 的行列表。
        """
        return await collect_technique_rows(
            self._session,
            [technique_id for technique_id, _ in techniques],
            limit=MAX_SCAN_ROWS,
        )

    async def _run_cypher(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """执行 Cypher（仅在图可用时调用）。

        Args:
            cypher: Cypher 语句（标签/关系取自白名单常量）。
            params: 参数。

        Returns:
            记录字典列表。

        Raises:
            Neo4jUnavailableError: 客户端未就绪或执行失败。
        """
        if self._graph_client is None:
            raise Neo4jUnavailableError("Neo4j 客户端未就绪")
        return await self._graph_client.run(cypher, params)

    async def cve_to_assets(self, cve_id: str, *, limit: int = DEFAULT_LIMIT) -> MultiHopResult:
        """路径①：``CVE → Component → Asset``（2 跳）。

        Args:
            cve_id: 漏洞主键（如 ``CVE-2024-3400``）。
            limit: 返回路径条数上限。

        Returns:
            :class:`MultiHopResult`；起点不存在时 ``paths`` 为空且 ``note`` 说明原因。
        """
        started = time.perf_counter()
        key = cve_id.strip().upper()
        cap = max(1, limit)
        if await self.graph_available():
            rows = await self._run_cypher(CYPHER_CVE_ASSETS, {"cve_id": key, "limit": cap})
            paths = paths_from_graph_asset_rows(key, rows, source="neo4j")[:cap]
            return MultiHopResult(
                cve_id=key,
                pattern=PATTERN_CVE_ASSET,
                source="neo4j",
                paths=paths,
                elapsed_ms=_elapsed_ms(started),
                note=None if paths else "图中暂无该 CVE 的 AFFECTS 边（先跑 scripts/load_graph.py）",
            )

        vuln, enriched = await self._load_entities(key)
        if vuln is None:
            return MultiHopResult(
                cve_id=key,
                pattern=PATTERN_CVE_ASSET,
                source="postgres",
                degraded=True,
                elapsed_ms=_elapsed_ms(started),
                note="unified_vuln 中不存在该 CVE",
            )
        paths = build_asset_paths(
            key, component_entries(vuln), asset_entries(enriched), source="postgres"
        )[:cap]
        return MultiHopResult(
            cve_id=key,
            pattern=PATTERN_CVE_ASSET,
            source="postgres",
            paths=paths,
            elapsed_ms=_elapsed_ms(started),
            degraded=True,
            note=None if enriched is not None else "该 CVE 尚未富化：仅返回 1 跳（组件）路径",
        )

    async def related_cves_by_technique(self, cve_id: str, *, limit: int = DEFAULT_LIMIT) -> MultiHopResult:
        """路径②：``CVE → AttackTechnique → CVE``（2 跳）。

        Args:
            cve_id: 漏洞主键。
            limit: 返回路径条数上限。

        Returns:
            :class:`MultiHopResult`（无攻击链时 ``paths`` 为空并给出 ``note``）。
        """
        started = time.perf_counter()
        key = cve_id.strip().upper()
        cap = max(1, limit)
        if await self.graph_available():
            rows = await self._run_cypher(CYPHER_CVE_TECHNIQUES, {"cve_id": key, "limit": cap})
            paths = paths_from_graph_technique_rows(key, rows, source="neo4j")[:cap]
            return MultiHopResult(
                cve_id=key,
                pattern=PATTERN_CVE_TECHNIQUE,
                source="neo4j",
                paths=paths,
                elapsed_ms=_elapsed_ms(started),
                note=None if paths else "图中暂无该 CVE 的 EXPLOITS 边（先跑 scripts/load_graph.py）",
            )

        _, enriched = await self._load_entities(key)
        techniques = technique_entries(enriched)
        if not techniques:
            return MultiHopResult(
                cve_id=key,
                pattern=PATTERN_CVE_TECHNIQUE,
                source="postgres",
                degraded=True,
                elapsed_ms=_elapsed_ms(started),
                note="未找到攻击链（该 CVE 未富化或 attack_chain 为空）",
            )
        related = await self._pg_related_technique_rows(techniques)
        paths = build_technique_paths(key, techniques, related, source="postgres")[:cap]
        return MultiHopResult(
            cve_id=key,
            pattern=PATTERN_CVE_TECHNIQUE,
            source="postgres",
            paths=paths,
            elapsed_ms=_elapsed_ms(started),
            degraded=True,
        )

    async def traverse(
        self,
        cve_id: str,
        *,
        patterns: Sequence[str] | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> list[MultiHopResult]:
        """按需执行多条路径模式（默认两条都跑）。

        Args:
            cve_id: 漏洞主键。
            patterns: 路径模式白名单（``PATTERN_CVE_ASSET`` / ``PATTERN_CVE_TECHNIQUE``）；``None`` 表示全部。
            limit: 每条模式的返回条数上限。

        Returns:
            结果列表（顺序与请求的模式一致）。
        """
        requested = list(patterns) if patterns else [PATTERN_CVE_ASSET, PATTERN_CVE_TECHNIQUE]
        results: list[MultiHopResult] = []
        for pattern in requested:
            if pattern == PATTERN_CVE_TECHNIQUE:
                results.append(await self.related_cves_by_technique(cve_id, limit=limit))
            elif pattern == PATTERN_CVE_ASSET:
                results.append(await self.cve_to_assets(cve_id, limit=limit))
        return results

    async def aclose(self) -> None:
        """关闭自建的 Neo4j 客户端（外部注入的客户端由调用方负责）。"""
        if self._owns_client and self._graph_client is not None:
            await self._graph_client.aclose()
            self._graph_client = None
            self._graph_ready = None


def _elapsed_ms(started: float) -> int:
    """计算耗时毫秒（纯函数）。

    Args:
        started: ``time.perf_counter()`` 的起点。

    Returns:
        取整后的毫秒数（≥0）。
    """
    return max(0, int((time.perf_counter() - started) * 1000))


async def collect_technique_rows(
    session: AsyncSession,
    techniques: Sequence[str],
    *,
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """在 PG 中找出「使用指定 ATT&CK 技术」的漏洞（PG 降级口径，供多跳与图谱路复用）。

    JSON 匹配在 Python 侧完成（跨 PG / SQLite 行为一致，同 ``paper_repo`` 口径）。

    Args:
        session: 异步会话。
        techniques: 技术 ID 列表（大小写不敏感）。
        limit: 返回行数上限。

    Returns:
        形如 ``{"technique_id", "cve_id", "title", "risk_score", "risk_level", "kev"}`` 的行列表。
    """
    wanted = {str(item).strip().upper() for item in techniques if str(item).strip()}
    if not wanted:
        return []
    stmt = (
        select(EnrichedVulnRow, UnifiedVulnRow)
        .join(UnifiedVulnRow, UnifiedVulnRow.vuln_id == EnrichedVulnRow.vuln_id)
        .order_by(EnrichedVulnRow.risk_score.desc(), EnrichedVulnRow.vuln_id)
        .limit(MAX_SCAN_ROWS)
    )
    rows = (await session.execute(stmt)).all()
    related: list[dict[str, Any]] = []
    for enriched_row, vuln_row in rows:
        payload = enriched_row.attack_chain or {}
        for step in payload.get("steps") or []:
            technique_id = str(step.get("technique_id") or "").strip().upper()
            if technique_id in wanted:
                related.append(
                    {
                        "technique_id": technique_id,
                        "cve_id": vuln_row.vuln_id,
                        "title": vuln_row.title,
                        "risk_score": enriched_row.risk_score,
                        "risk_level": enriched_row.risk_level,
                        "kev": vuln_row.kev,
                    }
                )
        if len(related) >= max(1, limit):
            break
    return related[: max(1, limit)]
