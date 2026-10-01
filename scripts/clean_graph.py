"""图谱清理脚本（Day11 任务 1.3：修复「边爆炸」遗留的脏边与孤立节点）。

背景：Day9 的抽取器对 ``Component × Asset`` 做「同漏洞共现」笛卡尔积且**没有上限**，
叠加 Log4Shell 的 144 组件 × 143 资产，图谱里累积了 2 万+ 低质量 ``INSTALLED_ON`` 边
（含 ``confidence=0.35`` 的占位资产、以及形如 ``6bk1602-0aa12-0tp0_firmware`` 的噪声名）。
Day11 已在**源头**限流（AssetMapper ≤10 资产/漏洞、单组件 ≤50 边），本脚本负责**清理存量**。

清理动作（幂等，可重复执行）：

1. 删除 ``confidence < --min-confidence``（默认 ``0.3``）的 ``INSTALLED_ON`` 边；
2. 删除清理后不再有任何 ``INSTALLED_ON`` 入边的孤立 ``Asset`` 节点（``DETACH DELETE``）。

用法::

    python -m scripts.clean_graph --dry-run     # 只统计不删除
    python -m scripts.clean_graph               # 执行清理
    python -m scripts.clean_graph --min-confidence 0.5

退出码：``0`` = 成功（含「无需清理」）；``1`` = Neo4j 不可用。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aisec_intel.config import Settings, get_settings  # noqa: E402
from aisec_intel.graph.schema import (  # noqa: E402
    NODE_ASSET,
    NODE_COMPONENT,
    NODE_VULNERABILITY,
    RELATION_AFFECTS,
    RELATION_INSTALLED_ON,
)
from aisec_intel.logging_config import get_logger  # noqa: E402
from aisec_intel.storage.neo4j_client import Neo4jClient, Neo4jUnavailableError  # noqa: E402
from aisec_intel.storage.repositories.graph_repo import GraphRepository  # noqa: E402

logger = get_logger(__name__)

DEFAULT_MIN_CONFIDENCE: float = 0.3
"""``INSTALLED_ON`` 边的最低置信度阈值（低于该值的共现推断边视为噪声）。"""

COUNT_DIRTY_EDGES: str = (
    f"MATCH (:{NODE_COMPONENT})-[r:{RELATION_INSTALLED_ON}]->(:{NODE_ASSET}) "
    "WHERE coalesce(r.confidence, 0.0) < $threshold RETURN count(r) AS c"
)
"""统计待删除的低置信度边。"""

DELETE_DIRTY_EDGES: str = (
    f"MATCH (:{NODE_COMPONENT})-[r:{RELATION_INSTALLED_ON}]->(:{NODE_ASSET}) "
    "WHERE coalesce(r.confidence, 0.0) < $threshold DELETE r RETURN count(*) AS c"
)
"""删除低置信度边（只删关系，不动节点）。"""

COUNT_EXCESS_EDGES: str = (
    f"MATCH (c:{NODE_COMPONENT})-[r:{RELATION_INSTALLED_ON}]->(:{NODE_ASSET}) "
    "WITH c, r ORDER BY coalesce(r.confidence, 0.0) DESC, r.confidence "
    "WITH c, collect(r) AS rels WHERE size(rels) > $keep "
    "RETURN sum(size(rels) - $keep) AS c"
)
"""统计「单组件超出上限」的 ``INSTALLED_ON`` 边数。"""

DELETE_EXCESS_EDGES: str = (
    f"MATCH (c:{NODE_COMPONENT})-[r:{RELATION_INSTALLED_ON}]->(:{NODE_ASSET}) "
    "WITH c, r ORDER BY coalesce(r.confidence, 0.0) DESC, r.confidence "
    "WITH c, collect(r) AS rels WITH c, rels[$keep..] AS excess "
    "UNWIND excess AS relation DELETE relation RETURN count(*) AS c"
)
"""按「单组件保留置信度最高的 ``keep`` 条」裁撤超限边（Day11 任务 1.2 的存量清理）。"""

COUNT_ORPHAN_ASSETS: str = (
    f"MATCH (a:{NODE_ASSET}) WHERE NOT (a)<-[:{RELATION_INSTALLED_ON}]-() RETURN count(a) AS c"
)
"""统计清理后不再被任何组件引用的孤立资产节点。"""

DELETE_ORPHAN_ASSETS: str = (
    f"MATCH (a:{NODE_ASSET}) WHERE NOT (a)<-[:{RELATION_INSTALLED_ON}]-() DETACH DELETE a RETURN count(*) AS c"
)
"""删除孤立资产节点（``DETACH DELETE``：同时清掉其残留关系）。"""

COUNT_ORPHAN_COMPONENTS: str = (
    f"MATCH (c:{NODE_COMPONENT}) WHERE NOT (c)<-[:{RELATION_AFFECTS}]-() RETURN count(c) AS c"
)
"""统计不再被任何漏洞引用的孤立组件节点。"""

DELETE_ORPHAN_COMPONENTS: str = (
    f"MATCH (c:{NODE_COMPONENT}) WHERE NOT (c)<-[:{RELATION_AFFECTS}]-() DETACH DELETE c RETURN count(*) AS c"
)
"""删除孤立组件节点（重新灌图后清理残骸）。"""

RESET_CVE_EDGES: str = (
    f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[r]->(c:{NODE_COMPONENT}) "
    f"OPTIONAL MATCH (c)-[i:{RELATION_INSTALLED_ON}]->() DELETE r, i RETURN count(*) AS c"
)
"""重置指定 CVE 的组件子图（删 ``AFFECTS`` 与这些组件的 ``INSTALLED_ON`` 边）。

用途：``load_graph`` 是**幂等 upsert**（只增不删），修复后的重灌图必须先把旧边清掉，
否则旧的 2 万条脏边会原样留存。
"""

RESET_CVE_OTHER_EDGES: str = (
    f"MATCH (v:{NODE_VULNERABILITY} {{cve_id: $cve_id}})-[r]->() WHERE NOT r:{RELATION_AFFECTS} DELETE r"
    " RETURN count(*) AS c"
)
"""重置指定 CVE 的其余出边（``RELATED_TO`` / ``EXPLOITS`` / ``FIXED_BY``）。"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="Neo4j 图谱清理（低置信度 INSTALLED_ON 边 + 孤立资产节点）")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help=f"保留门槛，低于该值的 INSTALLED_ON 边被删除（默认 {DEFAULT_MIN_CONFIDENCE}）",
    )
    parser.add_argument(
        "--max-edges-per-component",
        type=int,
        default=0,
        help="单组件保留的 INSTALLED_ON 边上限（0 表示用 INSTALLED_ON_MAX_PER_COMPONENT 配置值）",
    )
    parser.add_argument(
        "--reset-cve",
        action="append",
        default=[],
        help="重置指定 CVE 的图谱出边（可重复；为修复后重新灌图铺路）",
    )
    parser.add_argument("--dry-run", action="store_true", help="只统计不删除")
    return parser.parse_args(argv)


async def _scalar(client: Neo4jClient, cypher: str, params: dict[str, object] | None = None) -> int:
    """执行聚合查询并取首行首列的整数结果。

    Args:
        client: Neo4j 客户端。
        cypher: 返回单个 ``c`` 列的语句。
        params: 参数字典。

    Returns:
        计数结果（无记录时为 ``0``）。
    """
    rows = await client.run(cypher, params or {})
    if not rows:
        return 0
    return int(rows[0].get("c") or 0)


def format_counts(title: str, counts: dict[str, int]) -> str:
    """把节点/边计数渲染为一行（纯函数）。

    Args:
        title: 行首标签。
        counts: 标签/关系 → 计数。

    Returns:
        形如 ``[图谱规模 清理前] 节点：Asset=144、Vulnerability=3 ｜ 合计 304；边：…`` 的文本。
    """
    nodes = "、".join(f"{key}={value}" for key, value in sorted(counts.items())) or "（无）"
    return f"[{title}] {nodes}；合计={sum(counts.values())}"


async def run(args: argparse.Namespace) -> int:
    """执行清理流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（``0`` 成功；``1`` Neo4j 不可用）。
    """
    settings: Settings = get_settings()
    threshold = max(0.0, float(args.min_confidence))
    keep = args.max_edges_per_component if args.max_edges_per_component > 0 else settings.installed_on_max_per_component
    print(
        f"[环境] neo4j={settings.neo4j_uri} | enabled={settings.neo4j_enabled} "
        f"| 阈值 confidence<{threshold} | 单组件上限={keep}"
    )

    client = Neo4jClient(settings)
    try:
        try:
            repo = GraphRepository(client)
            before_nodes = await repo.count_nodes()
            before_edges = await repo.count_edges()
            if not before_nodes and not before_edges:
                print("[提示] 图谱为空（请先跑 python -m scripts.load_graph --all）")
                return 0
            dirty = await _scalar(client, COUNT_DIRTY_EDGES, {"threshold": threshold})
            excess = await _scalar(client, COUNT_EXCESS_EDGES, {"keep": keep})
            orphans = await _scalar(client, COUNT_ORPHAN_ASSETS)
            orphan_components = await _scalar(client, COUNT_ORPHAN_COMPONENTS)
            print(format_counts("清理前 节点", before_nodes))
            print(format_counts("清理前 边  ", before_edges))
            print(
                f"[待清理] 低置信度边={dirty}（confidence<{threshold}）；超限边={excess}（单组件>{keep}）；"
                f"孤立资产={orphans}；孤立组件={orphan_components}"
            )
            reset_targets = [item.strip().upper() for item in args.reset_cve if item.strip()]
            if reset_targets:
                print(f"[重置] 待重置 CVE：{reset_targets}（删除其 AFFECTS 边与组件的 INSTALLED_ON 边）")

            if args.dry_run:
                print("[dry-run] 未执行任何删除")
            else:
                for cve_id in reset_targets:
                    removed = await _scalar(client, RESET_CVE_EDGES, {"cve_id": cve_id})
                    other = await _scalar(client, RESET_CVE_OTHER_EDGES, {"cve_id": cve_id})
                    print(f"[重置] {cve_id}：删除 AFFECTS/INSTALLED_ON 边={removed}；其它出边={other}")
                removed_edges = await _scalar(client, DELETE_DIRTY_EDGES, {"threshold": threshold})
                trimmed_edges = await _scalar(client, DELETE_EXCESS_EDGES, {"keep": keep})
                removed_assets = await _scalar(client, DELETE_ORPHAN_ASSETS)
                removed_components = await _scalar(client, DELETE_ORPHAN_COMPONENTS)
                print(
                    f"[已清理] 低置信度边={removed_edges}；超限边={trimmed_edges}；"
                    f"孤立资产={removed_assets}；孤立组件={removed_components}"
                )

            after_nodes = await repo.count_nodes()
            after_edges = await repo.count_edges()
            print(format_counts("清理后 节点", after_nodes))
            print(format_counts("清理后 边  ", after_edges))
            print(
                f"[对比] 节点 {sum(before_nodes.values())} → {sum(after_nodes.values())}；"
                f"边 {sum(before_edges.values())} → {sum(after_edges.values())}"
            )
        except Neo4jUnavailableError as exc:
            print(f"[FAIL] 图谱清理失败：{exc}")
            return 1
    finally:
        await client.aclose()
    return 0


def main(argv: list[str] | None = None) -> int:
    """脚本入口。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        进程退出码。
    """
    return asyncio.run(run(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
