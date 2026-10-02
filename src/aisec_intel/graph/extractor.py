"""图谱关系抽取器（PROJECT_PLAN.md §5.7 P6）：``EnrichedVuln`` → 节点 + 边。

设计约束：

1. **纯函数、零 IO、禁用 LLM**（§0 约束 1：L1/L2 禁用 LLM；图谱抽取与之同级，属确定性转换），
   所有结果仅由入参决定，可重复、可单测；
2. 节点键统一走 :data:`aisec_intel.graph.schema.NODE_KEY_PROPERTIES`，与入库 ``MERGE`` 一致；
3. 输出**排序稳定**（节点按 ``(label, key)``、边按 ``(relation, start, end)``），
   便于断言、便于在报告中给出可复现的节点/边清单。

映射规则（确定性）：

    | 来源字段 | 产出 |
    |---|---|
    | ``vuln_id`` / ``severity`` / ``risk_score`` … | ``Vulnerability`` 节点 |
    | ``cpe_matches`` / ``ecosystem_packages`` | ``Component`` 节点 + ``AFFECTS`` 边（Day12 限流：厂商一致 + top N） |
    | ``affected_assets`` | ``Asset`` 节点 + ``INSTALLED_ON`` 边（同漏洞内组件↔资产） |
    | ``related_papers`` | ``Paper`` 节点 + ``RELATED_TO`` 边（携带 relation / confidence） |
    | ``attack_chain.steps`` | ``AttackTechnique`` 节点 + ``EXPLOITS`` 边（携带 order） |
    | ``references`` 中带 patch/advisory 标记者 | ``Patch`` 节点 + ``FIXED_BY`` 边 |

Note:
    ``INSTALLED_ON`` 目前按「同一漏洞的组件 × 资产」笛卡尔积连接（数据源未提供精确的
    组件-资产映射），边属性 ``derived_from="cve-cooccurrence"`` 明示其为推断关系，
    后续接入 SBOM 后只需替换 :func:`_installed_on_edges` 的匹配逻辑。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from aisec_intel.graph.schema import (
    NODE_ASSET,
    NODE_ATTACK_TECHNIQUE,
    NODE_COMPONENT,
    NODE_PAPER,
    NODE_PATCH,
    NODE_VULNERABILITY,
    RELATION_AFFECTS,
    RELATION_EXPLOITS,
    RELATION_FIXED_BY,
    RELATION_INSTALLED_ON,
    RELATION_RELATED_TO,
)
from aisec_intel.models.enriched_vuln import EnrichedVuln
from aisec_intel.models.unified_vuln import CpeMatch, Reference

PATCH_TAGS: frozenset[str] = frozenset({"patch", "advisory", "vendor-advisory", "fix", "mitigation"})
"""参考链接标签中视为「补丁 / 公告」的关键词（小写比对）。"""

PATCH_URL_MARKERS: tuple[str, ...] = (
    "/security/advisories/",
    "/advisories/",
    "/security-bulletin",
    "/support/security",
    "security.paloaltonetworks.com",
    "msrc.microsoft.com",
    "/patches/",
)
"""URL 特征串：命中即视为补丁 / 厂商公告链接（确定性启发式，非 LLM）。"""

COOCCURRENCE_SOURCE: str = "cve-cooccurrence"
"""``INSTALLED_ON`` 边的来源标记（当前为同漏洞共现推断）。"""

DEFAULT_INSTALLED_ON_MAX_PER_COMPONENT: int = 50
"""单个组件最多连出的 ``INSTALLED_ON`` 边数（Day11 任务 1.2，可用
``INSTALLED_ON_MAX_PER_COMPONENT`` 覆盖）。

背景：``Component × Asset`` 为「同漏洞共现」笛卡尔积，一条含 144 组件、143 资产的漏洞
会生成 ~2 万条边（实测 Log4Shell），图谱随即失去可读性。此处按 ``confidence`` 降序截断。
"""

DEFAULT_COMPONENT_MAX_PER_VULN: int = 5
"""单条漏洞最多保留的 ``Component`` 节点数（Day12 任务 1.1，可用
``COMPONENT_MAX_PER_VULN`` 覆盖）。

背景：Log4Shell 的 NVD ``configurations`` 展开出 144 个组件，即使 ``INSTALLED_ON`` 已限流，
``AFFECTS`` 边与组件节点仍让子图不可读（实测 1582 条边）。因此与资产同口径做**源头限流**：
先按「厂商与 CVE 的 ``cpe_matches`` 一致」过滤，再按 ``confidence`` 降序取 top N。
"""

CPE_COMPONENT_CONFIDENCE: float = 1.0
"""``cpe_matches`` 派生组件的置信度（结构化字段，确定性满分）。"""

ECOSYSTEM_COMPONENT_CONFIDENCE: float = 0.5
"""``ecosystem_packages`` 派生组件的置信度（无版本区间，仅包名级证据）。"""



@dataclass(slots=True)
class GraphNode:
    """一个待写入的图节点（标签 + 唯一键 + 属性）。

    Attributes:
        label: 节点标签（必须在 :data:`aisec_intel.graph.schema.NODE_LABELS` 内）。
        key: 唯一键属性值（对应标签的 ``NODE_KEY_PROPERTIES``）。
        properties: 其余属性（写入时与键属性合并）。
    """

    label: str
    key: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdge:
    """一条待写入的图关系（类型 + 两端节点键 + 属性）。

    Attributes:
        relation: 关系类型（必须在 :data:`aisec_intel.graph.schema.RELATION_TYPES` 内）。
        start_label: 起点节点标签。
        start_key: 起点节点键值。
        end_label: 终点节点标签。
        end_key: 终点节点键值。
        properties: 关系属性（如 ``order`` / ``confidence``）。
    """

    relation: str
    start_label: str
    start_key: str
    end_label: str
    end_key: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExtractionResult:
    """一次抽取的完整结果（节点 + 边）。

    Attributes:
        vuln_id: 来源漏洞主键（便于日志与统计）。
        nodes: 去重并排序后的节点列表。
        edges: 去重并排序后的关系列表。
    """

    vuln_id: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def node_counts(self) -> dict[str, int]:
        """按标签统计节点数。

        Returns:
            形如 ``{"Vulnerability": 1, "Component": 2}`` 的字典（标签字典序）。
        """
        counts: dict[str, int] = {}
        for node in self.nodes:
            counts[node.label] = counts.get(node.label, 0) + 1
        return dict(sorted(counts.items()))

    def edge_counts(self) -> dict[str, int]:
        """按关系类型统计关系数。

        Returns:
            形如 ``{"AFFECTS": 2, "FIXED_BY": 1}`` 的字典（类型字典序）。
        """
        counts: dict[str, int] = {}
        for edge in self.edges:
            counts[edge.relation] = counts.get(edge.relation, 0) + 1
        return dict(sorted(counts.items()))

    def summary(self) -> str:
        """返回「节点/边」统计的一行摘要（日志与报告用）。

        Returns:
            形如 ``节点=7（Component=2, Vulnerability=1…）边=6（AFFECTS=2…）`` 的字符串。
        """
        nodes = ", ".join(f"{label}={count}" for label, count in self.node_counts().items()) or "无"
        edges = ", ".join(f"{relation}={count}" for relation, count in self.edge_counts().items()) or "无"
        return f"节点={len(self.nodes)}（{nodes}）边={len(self.edges)}（{edges}）"


def summarize_properties(properties: dict[str, Any]) -> dict[str, Any]:
    """过滤不可入库的属性值（``None`` 与空容器）。

    Neo4j 不接受 ``None`` 作为属性值（会报 ``Type mismatch``），空列表 / 空字典也没有语义，
    统一在此剔除，保证「抽出来的属性一定能写进去」。

    Args:
        properties: 原始属性字典。

    Returns:
        过滤后的新字典。
    """
    return {
        key: value
        for key, value in properties.items()
        if value is not None and not (isinstance(value, (list, tuple, dict)) and len(value) == 0)
    }


def is_patch_reference(reference: Reference) -> bool:
    """判断参考链接是否为「补丁 / 厂商公告」（纯函数，确定性启发式）。

    Args:
        reference: 参考链接。

    Returns:
        标签命中 :data:`PATCH_TAGS` 或 URL 命中 :data:`PATCH_URL_MARKERS` 时返回 ``True``。
    """
    tags = {tag.strip().lower() for tag in reference.tags}
    if tags & PATCH_TAGS:
        return True
    url = reference.url.strip().lower()
    return any(marker in url for marker in PATCH_URL_MARKERS)


def render_version_range(cpe: CpeMatch) -> str | None:
    """把 CPE 区间渲染为可读字符串（纯函数）。

    Args:
        cpe: CPE 匹配条目。

    Returns:
        形如 ``">=10.2.0, <10.2.9-h1"``；四个边界全空时返回 ``None``。
    """
    parts: list[str] = []
    if cpe.version_start_incl:
        parts.append(f">={cpe.version_start_incl}")
    if cpe.version_start_excl:
        parts.append(f">{cpe.version_start_excl}")
    if cpe.version_end_incl:
        parts.append(f"<={cpe.version_end_incl}")
    if cpe.version_end_excl:
        parts.append(f"<{cpe.version_end_excl}")
    return ", ".join(parts) or None


def split_ecosystem_package(identifier: str) -> tuple[str | None, str]:
    """拆分 ``生态:包名`` 标识（纯函数）。

    Args:
        identifier: 形如 ``"PyPI:ollama"`` 或 ``"ollama"``。

    Returns:
        ``(生态或 None, 包名)``。
    """
    head, sep, tail = identifier.strip().partition(":")
    if sep and head and tail:
        return head, tail
    return None, identifier.strip()


def vulnerability_node(enriched: EnrichedVuln) -> GraphNode:
    """由富化实体构造 ``Vulnerability`` 节点（纯函数）。

    Args:
        enriched: L3 富化输出实体。

    Returns:
        键为 ``cve_id`` 的漏洞节点。
    """
    return GraphNode(
        label=NODE_VULNERABILITY,
        key=enriched.vuln_id,
        properties=summarize_properties(
            {
                "cve_id": enriched.vuln_id,
                "title": enriched.title,
                "severity": enriched.severity,
                "kev": enriched.kev,
                "epss_score": enriched.epss_score,
                "risk_score": enriched.risk_score,
                "risk_level": enriched.risk_level,
                "confidence": enriched.confidence,
                "review_status": enriched.review_status,
                "sources": list(enriched.sources),
                "aliases": list(enriched.aliases),
                "cwe_ids": list(enriched.cwe_ids),
                "affected_versions": list(enriched.affected_versions),
                "trace_ids": list(enriched.trace_ids),
                "published_at": enriched.published_at.isoformat() if enriched.published_at else None,
                "enriched_at": enriched.enriched_at.isoformat() if enriched.enriched_at else None,
                "description": (enriched.description or "")[:600],
            }
        ),
    )


def cpe_vendors(enriched: EnrichedVuln) -> frozenset[str]:
    """收集 CVE 的 ``cpe_matches`` 中出现的全部厂商（纯函数）。

    Args:
        enriched: 富化实体。

    Returns:
        小写去空白的厂商名集合（无 CPE 时为空集合）。
    """
    return frozenset(cpe.vendor.strip().lower() for cpe in enriched.cpe_matches if cpe.vendor.strip())


def vendor_consistent(component: GraphNode, vendors: frozenset[str]) -> bool:
    """判断组件厂商是否与 CVE 的 ``cpe_matches`` 厂商一致（纯函数，Day12 任务 1.1）。

    口径（确定性，无 LLM）：

    1. 组件**未声明厂商**（如 ``ecosystem_packages`` 派生的 ``PyPI:ollama``）→ 不可判定，
       保留（不做有罪推定）；
    2. 组件声明了厂商 → 必须与 CPE 厂商集合**双向包含**匹配（大小写无关）；
    3. CVE 没有任何 CPE 厂商 → 无可比对基准，全部保留。

    Args:
        component: 组件节点。
        vendors: :func:`cpe_vendors` 的结果（小写）。

    Returns:
        一致（或不可判定）返回 ``True``；厂商明确不一致返回 ``False``。
    """
    if not vendors:
        return True
    vendor = str(component.properties.get("vendor") or "").strip().lower()
    if not vendor:
        return True
    return any(vendor == item or vendor in item or item in vendor for item in vendors)


def component_relevance(component: GraphNode, asset_vendors: frozenset[str]) -> tuple[float, int, str]:
    """组件排序键（纯函数）：置信度降序 → 命中资产厂商优先 → 节点键升序。

    Args:
        component: 组件节点。
        asset_vendors: 本漏洞 ``affected_assets`` 中出现过的厂商（小写）。

    Returns:
        可直接交给 ``sorted`` 的元组（数值越小越靠前）。
    """
    confidence = float(component.properties.get("confidence") or 0.0)
    vendor = str(component.properties.get("vendor") or "").strip().lower()
    hits_asset = 0 if vendor and any(vendor in item or item in vendor for item in asset_vendors) else 1
    return (-confidence, hits_asset, component.key)


def select_components(
    components: Sequence[GraphNode],
    *,
    asset_vendors: frozenset[str] = frozenset(),
    limit: int = DEFAULT_COMPONENT_MAX_PER_VULN,
) -> list[GraphNode]:
    """按置信度降序为单条漏洞挑选最多 ``limit`` 个组件（纯函数，确定性）。

    Args:
        components: 已通过厂商一致性过滤的组件节点。
        asset_vendors: 本漏洞资产厂商（用于同分时的相关性排序）。
        limit: 组件上限（``<=0`` 时回退 :data:`DEFAULT_COMPONENT_MAX_PER_VULN`）。

    Returns:
        截断后的组件列表。
    """
    cap = limit if limit > 0 else DEFAULT_COMPONENT_MAX_PER_VULN
    return sorted(components, key=lambda node: component_relevance(node, asset_vendors))[:cap]


def component_nodes(
    enriched: EnrichedVuln,
    *,
    max_components: int = DEFAULT_COMPONENT_MAX_PER_VULN,
    asset_vendors: Sequence[str] = (),
) -> list[GraphNode]:
    """由 ``cpe_matches`` 与 ``ecosystem_packages`` 构造 ``Component`` 节点（纯函数）。

    Day12 任务 1.1（源头限流）：先按「厂商与 CVE 的 ``cpe_matches`` 一致」过滤
    （:func:`vendor_consistent`），再按 ``confidence`` 降序取 top ``max_components``
    （:func:`select_components`）。

    Args:
        enriched: 富化实体。
        max_components: 单条漏洞保留的组件上限（``COMPONENT_MAX_PER_VULN``）。
        asset_vendors: 本漏洞资产厂商（同分时的相关性 tie-break）。

    Returns:
        组件节点列表（键分别为 ``vendor:product`` 与生态包标识）。
    """
    vendors = cpe_vendors(enriched)
    candidates: list[GraphNode] = []
    for cpe in enriched.cpe_matches:
        key = f"{cpe.vendor}:{cpe.product}"
        candidates.append(
            GraphNode(
                label=NODE_COMPONENT,
                key=key,
                properties=summarize_properties(
                    {
                        "key": key,
                        "name": cpe.product,
                        "vendor": cpe.vendor,
                        "version_range": render_version_range(cpe),
                        "vulnerable": cpe.vulnerable,
                        "confidence": CPE_COMPONENT_CONFIDENCE if cpe.vulnerable else ECOSYSTEM_COMPONENT_CONFIDENCE,
                    }
                ),
            )
        )
    for identifier in enriched.ecosystem_packages:
        ecosystem, name = split_ecosystem_package(identifier)
        if not name:
            continue
        candidates.append(
            GraphNode(
                label=NODE_COMPONENT,
                key=identifier,
                properties=summarize_properties(
                    {
                        "key": identifier,
                        "name": name,
                        "ecosystem": ecosystem,
                        "vulnerable": True,
                        "confidence": ECOSYSTEM_COMPONENT_CONFIDENCE,
                    }
                ),
            )
        )
    consistent = [node for node in candidates if vendor_consistent(node, vendors)]
    return select_components(
        consistent,
        asset_vendors=frozenset(item.strip().lower() for item in asset_vendors if item and item.strip()),
        limit=max_components,
    )


def asset_nodes(enriched: EnrichedVuln) -> list[GraphNode]:
    """由 ``affected_assets`` 构造 ``Asset`` 节点（纯函数）。

    Args:
        enriched: 富化实体。

    Returns:
        资产节点列表（键为 ``asset_type:name``）。
    """
    return [
        GraphNode(
            label=NODE_ASSET,
            key=f"{asset.asset_type}:{asset.name}",
            properties=summarize_properties(
                {
                    "key": f"{asset.asset_type}:{asset.name}",
                    "name": asset.name,
                    "asset_type": asset.asset_type,
                    "vendor": asset.vendor,
                    "version_range": asset.version_range,
                    "ecosystem": asset.ecosystem,
                    "confidence": asset.confidence,
                }
            ),
        )
        for asset in enriched.affected_assets
    ]


def paper_nodes(enriched: EnrichedVuln) -> list[GraphNode]:
    """由 ``related_papers`` 构造 ``Paper`` 节点（纯函数）。

    Args:
        enriched: 富化实体。

    Returns:
        论文节点列表（键为 ``paper_id``）。
    """
    return [
        GraphNode(
            label=NODE_PAPER,
            key=link.paper_id,
            properties=summarize_properties({"paper_id": link.paper_id, "relation": link.relation}),
        )
        for link in enriched.related_papers
    ]


def attack_technique_nodes(enriched: EnrichedVuln) -> list[GraphNode]:
    """由 ``attack_chain.steps`` 构造 ``AttackTechnique`` 节点（纯函数）。

    Args:
        enriched: 富化实体（``attack_chain`` 为空时返回空列表）。

    Returns:
        ATT&CK 技术节点列表（键为 ``technique_id``，同一技术保留首次出现的描述）。
    """
    chain = enriched.attack_chain
    if chain is None:
        return []
    return [
        GraphNode(
            label=NODE_ATTACK_TECHNIQUE,
            key=step.technique_id.strip().upper(),
            properties=summarize_properties(
                {
                    "technique_id": step.technique_id.strip().upper(),
                    "tactic": step.tactic,
                    "stage": step.stage,
                    "description": step.description,
                    "order": step.order,
                }
            ),
        )
        for step in chain.steps
    ]


def patch_nodes(enriched: EnrichedVuln) -> list[GraphNode]:
    """由参考链接构造 ``Patch`` 节点（纯函数）。

    Args:
        enriched: 富化实体。

    Returns:
        补丁 / 厂商公告节点列表（键为 ``url``）。
    """
    return [
        GraphNode(
            label=NODE_PATCH,
            key=reference.url,
            properties=summarize_properties(
                {"url": reference.url, "source": reference.source, "tags": list(reference.tags)}
            ),
        )
        for reference in enriched.references
        if reference.url and is_patch_reference(reference)
    ]


def _dedupe_nodes(nodes: list[GraphNode]) -> list[GraphNode]:
    """按 ``(label, key)`` 去重并排序（纯函数，确定性）。

    Args:
        nodes: 原始节点列表（同键重复时保留首次出现者）。

    Returns:
        去重后的节点列表。
    """
    unique: dict[tuple[str, str], GraphNode] = {}
    for node in nodes:
        unique.setdefault((node.label, node.key), node)
    return [unique[key] for key in sorted(unique)]


def _dedupe_edges(edges: list[GraphEdge]) -> list[GraphEdge]:
    """按 ``(关系, 起点标签, 起点键, 终点标签, 终点键)`` 去重并排序（纯函数）。

    Args:
        edges: 原始关系列表。

    Returns:
        去重后的关系列表。
    """
    unique: dict[tuple[str, str, str, str, str], GraphEdge] = {}
    for edge in edges:
        unique.setdefault(
            (edge.relation, edge.start_label, edge.start_key, edge.end_label, edge.end_key), edge
        )
    return [unique[key] for key in sorted(unique)]


def top_assets_for_component(assets: Sequence[GraphNode], *, limit: int) -> list[GraphNode]:
    """按 ``confidence`` 降序为单组件挑选最多 ``limit`` 个资产（纯函数，确定性）。

    Day11 任务 1.2：``INSTALLED_ON`` 是「同漏洞共现」推断边，必须限流，
    否则一条含上百组件/资产的漏洞就会把图谱边数打到 2 万级。

    Args:
        assets: 该漏洞的全部资产节点。
        limit: 单组件上限（``<=0`` 时回退 :data:`DEFAULT_INSTALLED_ON_MAX_PER_COMPONENT`）。

    Returns:
        截断后的资产节点列表（``confidence`` 降序，同分按节点键升序）。
    """
    cap = limit if limit > 0 else DEFAULT_INSTALLED_ON_MAX_PER_COMPONENT
    ordered = sorted(assets, key=lambda node: (-float(node.properties.get("confidence") or 0.0), node.key))
    return ordered[:cap]


def extract_graph(
    enriched: EnrichedVuln,
    *,
    installed_on_max_per_component: int = DEFAULT_INSTALLED_ON_MAX_PER_COMPONENT,
    component_max_per_vuln: int = DEFAULT_COMPONENT_MAX_PER_VULN,
) -> ExtractionResult:
    """把一条富化漏洞抽取为「节点 + 边」（纯函数，本模块主入口）。

    Args:
        enriched: L3 富化输出实体。
        installed_on_max_per_component: 单组件最多连出的 ``INSTALLED_ON`` 边数
            （Day11 容量保护，来自 ``INSTALLED_ON_MAX_PER_COMPONENT``）。
        component_max_per_vuln: 单条漏洞最多保留的 ``Component`` 节点数
            （Day12 任务 1.1 源头限流，来自 ``COMPONENT_MAX_PER_VULN``）。

    Returns:
        :class:`ExtractionResult`（节点/边均已去重并排序；无对应维度的数据时该类节点/边为空）。
    """
    asset_vendors = [asset.vendor for asset in enriched.affected_assets if asset.vendor]
    resolved_nodes = _dedupe_nodes(
        [
            vulnerability_node(enriched),
            *component_nodes(
                enriched, max_components=component_max_per_vuln, asset_vendors=asset_vendors
            ),
            *asset_nodes(enriched),
            *paper_nodes(enriched),
            *attack_technique_nodes(enriched),
            *patch_nodes(enriched),
        ]
    )
    cve_id = enriched.vuln_id
    components = [node for node in resolved_nodes if node.label == NODE_COMPONENT]
    assets = [node for node in resolved_nodes if node.label == NODE_ASSET]
    linked_assets = top_assets_for_component(assets, limit=installed_on_max_per_component)
    edges: list[GraphEdge] = []

    # ① Vulnerability -[AFFECTS]-> Component；② Component -[INSTALLED_ON]-> Asset
    for component in components:
        version_range = component.properties.get("version_range")
        edges.append(
            GraphEdge(
                relation=RELATION_AFFECTS,
                start_label=NODE_VULNERABILITY,
                start_key=cve_id,
                end_label=NODE_COMPONENT,
                end_key=component.key,
                properties=summarize_properties({"version_range": version_range}),
            )
        )
        for asset in linked_assets:
            # 数据源暂无精确 SBOM 映射 → 按「同漏洞共现」连接，边属性明示推断来源
            edges.append(
                GraphEdge(
                    relation=RELATION_INSTALLED_ON,
                    start_label=NODE_COMPONENT,
                    start_key=component.key,
                    end_label=NODE_ASSET,
                    end_key=asset.key,
                    properties=summarize_properties(
                        {
                            "derived_from": COOCCURRENCE_SOURCE,
                            "confidence": asset.properties.get("confidence"),
                        }
                    ),
                )
            )

    # ③ Vulnerability -[RELATED_TO]-> Paper
    for link in enriched.related_papers:
        edges.append(
            GraphEdge(
                relation=RELATION_RELATED_TO,
                start_label=NODE_VULNERABILITY,
                start_key=cve_id,
                end_label=NODE_PAPER,
                end_key=link.paper_id,
                properties=summarize_properties(
                    {
                        "relation": link.relation,
                        "confidence": link.confidence,
                        "evidence_refs": list(link.evidence_refs),
                    }
                ),
            )
        )

    # ④ Vulnerability -[EXPLOITS]-> AttackTechnique
    if enriched.attack_chain is not None:
        for step in enriched.attack_chain.steps:
            edges.append(
                GraphEdge(
                    relation=RELATION_EXPLOITS,
                    start_label=NODE_VULNERABILITY,
                    start_key=cve_id,
                    end_label=NODE_ATTACK_TECHNIQUE,
                    end_key=step.technique_id.strip().upper(),
                    properties=summarize_properties(
                        {
                            "order": step.order,
                            "tactic": step.tactic,
                            "stage": step.stage,
                            "preconditions": list(step.preconditions),
                        }
                    ),
                )
            )

    # ⑤ Vulnerability -[FIXED_BY]-> Patch
    for reference in enriched.references:
        if not reference.url or not is_patch_reference(reference):
            continue
        edges.append(
            GraphEdge(
                relation=RELATION_FIXED_BY,
                start_label=NODE_VULNERABILITY,
                start_key=cve_id,
                end_label=NODE_PATCH,
                end_key=reference.url,
                properties=summarize_properties({"tags": list(reference.tags), "source": reference.source}),
            )
        )

    return ExtractionResult(vuln_id=cve_id, nodes=resolved_nodes, edges=_dedupe_edges(edges))
