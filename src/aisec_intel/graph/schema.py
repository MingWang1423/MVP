"""Neo4j 图谱 schema：节点标签 / 关系类型 / 约束与索引（PROJECT_PLAN.md §5.7 P6）。

本模块是 schema 的**唯一声明处**（纯常量 + 纯函数，无 IO）：仓库层
:mod:`aisec_intel.storage.repositories.graph_repo` 只引用这里的常量拼 Cypher，
避免同一份 schema 在多处漂移。

图谱模型（6 节点 + 5 关系）::

    (Vulnerability) -[AFFECTS]->      (Component)
    (Component)     -[INSTALLED_ON]-> (Asset)
    (Vulnerability) -[RELATED_TO]->   (Paper)
    (Vulnerability) -[EXPLOITS]->     (AttackTechnique)
    (Vulnerability) -[FIXED_BY]->     (Patch)

每个节点都有**唯一键属性**（见 :data:`NODE_KEY_PROPERTIES`），
``MERGE`` 以此幂等 upsert（重复灌图不会产生重复节点）。
"""

from __future__ import annotations

from typing import Final

NODE_VULNERABILITY: Final[str] = "Vulnerability"
"""漏洞节点（键：``cve_id``）。"""

NODE_COMPONENT: Final[str] = "Component"
"""受影响组件 / 包节点（键：``key`` = ``vendor:product`` 或生态包名）。"""

NODE_ASSET: Final[str] = "Asset"
"""资产节点（键：``key`` = ``asset_type:name``）。"""

NODE_PAPER: Final[str] = "Paper"
"""学术论文节点（键：``paper_id``）。"""

NODE_ATTACK_TECHNIQUE: Final[str] = "AttackTechnique"
"""MITRE ATT&CK 技术节点（键：``technique_id``，如 ``T1190``）。"""

NODE_PATCH: Final[str] = "Patch"
"""补丁 / 厂商公告节点（键：``url``）。"""

NODE_LABELS: tuple[str, ...] = (
    NODE_VULNERABILITY,
    NODE_COMPONENT,
    NODE_ASSET,
    NODE_PAPER,
    NODE_ATTACK_TECHNIQUE,
    NODE_PATCH,
)
"""全部节点标签（同时用作 Cypher 注入白名单）。"""

RELATION_AFFECTS: Final[str] = "AFFECTS"
"""``Vulnerability -[AFFECTS]-> Component``：漏洞影响哪些组件。"""

RELATION_INSTALLED_ON: Final[str] = "INSTALLED_ON"
"""``Component -[INSTALLED_ON]-> Asset``：组件安装在哪些资产上。"""

RELATION_RELATED_TO: Final[str] = "RELATED_TO"
"""``Vulnerability -[RELATED_TO]-> Paper``：漏洞与论文的关联。"""

RELATION_EXPLOITS: Final[str] = "EXPLOITS"
"""``Vulnerability -[EXPLOITS]-> AttackTechnique``：漏洞利用到哪些 ATT&CK 技术。"""

RELATION_FIXED_BY: Final[str] = "FIXED_BY"
"""``Vulnerability -[FIXED_BY]-> Patch``：漏洞由哪些补丁 / 公告修复。"""

RELATION_TYPES: tuple[str, ...] = (
    RELATION_AFFECTS,
    RELATION_INSTALLED_ON,
    RELATION_RELATED_TO,
    RELATION_EXPLOITS,
    RELATION_FIXED_BY,
)
"""全部关系类型（同时用作 Cypher 注入白名单）。"""

NODE_KEY_PROPERTIES: dict[str, str] = {
    NODE_VULNERABILITY: "cve_id",
    NODE_COMPONENT: "key",
    NODE_ASSET: "key",
    NODE_PAPER: "paper_id",
    NODE_ATTACK_TECHNIQUE: "technique_id",
    NODE_PATCH: "url",
}
"""节点标签 → 唯一键属性名（``MERGE`` 依据）。"""

EDGE_MATRIX: dict[str, tuple[str, str]] = {
    RELATION_AFFECTS: (NODE_VULNERABILITY, NODE_COMPONENT),
    RELATION_INSTALLED_ON: (NODE_COMPONENT, NODE_ASSET),
    RELATION_RELATED_TO: (NODE_VULNERABILITY, NODE_PAPER),
    RELATION_EXPLOITS: (NODE_VULNERABILITY, NODE_ATTACK_TECHNIQUE),
    RELATION_FIXED_BY: (NODE_VULNERABILITY, NODE_PATCH),
}
"""关系类型 → ``(起点标签, 终点标签)``；写入前用于校验端点合法性。"""

CONSTRAINTS: tuple[str, ...] = (
    "CREATE CONSTRAINT vulnerability_cve_id IF NOT EXISTS "
    "FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE",
    "CREATE CONSTRAINT component_key IF NOT EXISTS FOR (n:Component) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT asset_key IF NOT EXISTS FOR (n:Asset) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT paper_paper_id IF NOT EXISTS FOR (n:Paper) REQUIRE n.paper_id IS UNIQUE",
    "CREATE CONSTRAINT attack_technique_id IF NOT EXISTS "
    "FOR (n:AttackTechnique) REQUIRE n.technique_id IS UNIQUE",
    "CREATE CONSTRAINT patch_url IF NOT EXISTS FOR (n:Patch) REQUIRE n.url IS UNIQUE",
)
"""唯一性约束（节点键）：保证 ``MERGE`` 幂等，重复灌图不产生重复节点。"""

INDEXES: tuple[str, ...] = (
    "CREATE INDEX component_name IF NOT EXISTS FOR (n:Component) ON (n.name)",
    "CREATE INDEX component_vendor IF NOT EXISTS FOR (n:Component) ON (n.vendor)",
    "CREATE INDEX component_ecosystem IF NOT EXISTS FOR (n:Component) ON (n.ecosystem)",
    "CREATE INDEX asset_name IF NOT EXISTS FOR (n:Asset) ON (n.name)",
    "CREATE INDEX asset_type IF NOT EXISTS FOR (n:Asset) ON (n.asset_type)",
    "CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (n:Vulnerability) ON (n.severity)",
    "CREATE INDEX vulnerability_risk_level IF NOT EXISTS FOR (n:Vulnerability) ON (n.risk_level)",
    "CREATE INDEX vulnerability_kev IF NOT EXISTS FOR (n:Vulnerability) ON (n.kev)",
    "CREATE INDEX paper_title IF NOT EXISTS FOR (n:Paper) ON (n.title)",
    "CREATE INDEX attack_technique_tactic IF NOT EXISTS FOR (n:AttackTechnique) ON (n.tactic)",
)
"""非唯一索引：支撑「按组件/资产/级别/战术」的检索型查询（``get_related_cves`` 等）。"""


def schema_statements() -> tuple[str, ...]:
    """返回全部 schema 语句（约束在前、索引在后）。

    Returns:
        可直接逐条执行的 Cypher 语句元组（均带 ``IF NOT EXISTS``，重复执行安全）。
    """
    return (*CONSTRAINTS, *INDEXES)


def is_known_label(label: str) -> bool:
    """判断是否为已声明节点标签（Cypher 注入白名单）。

    Args:
        label: 待判定标签。

    Returns:
        在白名单内返回 ``True``。
    """
    return label in NODE_LABELS


def is_known_relation(relation: str) -> bool:
    """判断是否为已声明关系类型（Cypher 注入白名单）。

    Args:
        relation: 待判定关系类型。

    Returns:
        在白名单内返回 ``True``。
    """
    return relation in RELATION_TYPES


def key_property_of(label: str) -> str:
    """返回节点标签的唯一键属性名。

    Args:
        label: 节点标签。

    Returns:
        唯一键属性名（如 ``Vulnerability`` → ``cve_id``）。

    Raises:
        ValueError: 标签未在 :data:`NODE_KEY_PROPERTIES` 中声明。
    """
    try:
        return NODE_KEY_PROPERTIES[label]
    except KeyError as exc:  # pragma: no cover - 由调用方的白名单校验先挡住
        raise ValueError(f"未声明的节点标签：{label}（可选：{', '.join(NODE_LABELS)}）") from exc
