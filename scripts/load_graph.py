"""图谱填充脚本（PROJECT_PLAN.md §5.7 ``scripts/load_graph.py``，P6）。

把 ``enriched_vuln`` 表中的富化结果灌入 Neo4j 知识图谱：

    读 PG（``VulnRepository``）→ 纯函数抽取（:func:`aisec_intel.graph.extractor.extract_graph`）
    → 幂等 upsert（:class:`aisec_intel.storage.repositories.graph_repo.GraphRepository`，UNWIND 批量）

用法::

    python -m scripts.load_graph --cve CVE-2024-3400      # 单条
    python -m scripts.load_graph --limit 20               # 最近富化的 20 条（默认）
    python -m scripts.load_graph --all                    # 全部已富化条目
    python -m scripts.load_graph --cve CVE-2024-3400 --dry-run   # 只抽取不写库
    python -m scripts.load_graph --no-report              # 不刷新 reports/graph_stats.md

退出码：0 = 全部成功；1 = 无可灌数据或存在错误。
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
from aisec_intel.graph.extractor import ExtractionResult, extract_graph  # noqa: E402
from aisec_intel.logging_config import get_logger  # noqa: E402
from aisec_intel.models.enriched_vuln import EnrichedVuln  # noqa: E402
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.neo4j_client import Neo4jClient, Neo4jUnavailableError  # noqa: E402
from aisec_intel.storage.repositories.graph_repo import GraphRepository  # noqa: E402
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

logger = get_logger(__name__)

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
"""仓库根目录。"""

DEFAULT_REPORT_PATH: Path = REPO_ROOT / "reports" / "graph_stats.md"
"""/§5.7 P6 交付物：图谱规模统计报告（``reports/`` 可被 Cline 读写）。"""

DEFAULT_LIMIT: int = 20
"""默认灌图条数（与 ``run_enrich --limit`` 同量级，避免误灌全库）。"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="Neo4j 图谱填充（enriched_vuln → extractor → graph_repo）")
    parser.add_argument("--cve", default=None, help="指定单条漏洞（如 CVE-2024-3400）")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"批量条数（默认 {DEFAULT_LIMIT}）")
    parser.add_argument("--all", action="store_true", help="灌入全部已富化条目（忽略 --cve/--limit）")
    parser.add_argument("--dry-run", action="store_true", help="只抽取并打印统计，不连接 Neo4j、不写库")
    parser.add_argument("--no-schema", action="store_true", help="跳过约束/索引创建（节点已存在时加速）")
    parser.add_argument("--no-report", action="store_true", help=f"不刷新 {DEFAULT_REPORT_PATH.name}")
    parser.add_argument(
        "--report-path",
        default=str(DEFAULT_REPORT_PATH),
        help="统计报告输出路径（默认 reports/graph_stats.md）",
    )
    parser.add_argument("--verbose", action="store_true", help="打印每条 CVE 的抽取明细")
    return parser.parse_args(argv)


async def load_enriched(
    settings: Settings,
    *,
    cve_id: str | None = None,
    limit: int = DEFAULT_LIMIT,
    all_rows: bool = False,
) -> list[EnrichedVuln]:
    """从 ``enriched_vuln`` 读取待灌图的富化实体。

    Args:
        settings: 全局配置。
        cve_id: 指定单条漏洞主键；``None`` 时按富化时间倒序取。
        limit: 取数上限（``all_rows=True`` 时忽略）。
        all_rows: ``True`` 时取全部已富化条目。

    Returns:
        富化实体列表（``cve_id`` 指定但未富化时为空列表）。
    """
    async with session_scope(get_engine(settings)) as session:
        repo = VulnRepository(session)
        if cve_id:
            found = await repo.get_enriched(cve_id)
            return [found] if found is not None else []
        limit_value = None if all_rows else max(1, limit)
        ids = await repo.list_enriched_ids(limit=limit_value)
        loaded: list[EnrichedVuln] = []
        for vuln_id in ids:
            enriched = await repo.get_enriched(vuln_id)
            if enriched is not None:
                loaded.append(enriched)
    logger.info(f"读取待灌图富化条目：{len(loaded)} 条")
    return loaded


def render_report(
    extractions: list[ExtractionResult],
    *,
    node_counts: dict[str, int],
    edge_counts: dict[str, int],
    command: str,
    dry_run: bool = False,
) -> str:
    """渲染 ``reports/graph_stats.md`` 内容（纯函数，便于测试断言）。

    Args:
        extractions: 本次抽取结果列表。
        node_counts: Neo4j 现有节点按标签统计（dry-run 时为空字典）。
        edge_counts: Neo4j 现有关系按类型统计（dry-run 时为空字典）。
        command: 复现本次灌图的命令。
        dry_run: 是否为 dry-run（不写库）模式。

    Returns:
        Markdown 文本。
    """
    lines: list[str] = [
        "# P6 图谱规模统计（graph_stats.md）",
        "",
        f"> 生成命令：`{command}`（Day9 / P6）",
        "> 数据流：PostgreSQL `enriched_vuln` → `aisec_intel.graph.extractor`（纯函数，无 LLM）→ Neo4j",
        f"> 模式：{'dry-run（仅抽取，未写库）' if dry_run else '实灌（幂等 upsert）'}",
        "",
        "## 1. 本次抽取统计",
        "",
        "| 漏洞 | 节点数 | 边数 | 节点明细 | 边明细 |",
        "|---|---:|---:|---|---|",
    ]
    for result in extractions:
        nodes = ", ".join(f"{label}:{count}" for label, count in result.node_counts().items()) or "-"
        edges = ", ".join(f"{relation}:{count}" for relation, count in result.edge_counts().items()) or "-"
        lines.append(f"| {result.vuln_id} | {len(result.nodes)} | {len(result.edges)} | {nodes} | {edges} |")

    total_nodes = sum(len(result.nodes) for result in extractions)
    total_edges = sum(len(result.edges) for result in extractions)
    lines.extend(
        [
            f"| **合计** | {total_nodes} | {total_edges} | — | — |",
            "",
            "## 2. Neo4j 现有规模",
            "",
            "| 节点标签 | 数量 | 关系类型 | 数量 |",
            "|---|---:|---|---:|",
        ]
    )
    labels = sorted(set(node_counts) | {"Vulnerability", "Component", "Asset", "Paper", "AttackTechnique", "Patch"})
    relations = sorted(
        set(edge_counts) | {"AFFECTS", "INSTALLED_ON", "RELATED_TO", "EXPLOITS", "FIXED_BY"}
    )
    for index in range(max(len(labels), len(relations))):
        label = labels[index] if index < len(labels) else ""
        relation = relations[index] if index < len(relations) else ""
        label_total = node_counts.get(label, 0) if label else ""
        relation_total = edge_counts.get(relation, 0) if relation else ""
        lines.append(f"| {label} | {label_total} | {relation} | {relation_total} |")

    lines.extend(
        [
            "",
            "## 3. 复核用查询（Neo4j Browser）",
            "",
            "```cypher",
            "MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'}) RETURN v",
            "MATCH (v:Vulnerability {cve_id:'CVE-2024-3400'})-[r]->(n) RETURN v, r, n",
            "MATCH (v:Vulnerability)-[:AFFECTS]->(c:Component)<-[:AFFECTS]-(peer:Vulnerability) "
            "RETURN c.key, collect(peer.cve_id) AS related_cves",
            "```",
            "",
            "> 约束与索引由 `aisec_intel/graph/schema.py` 统一声明，"
            "`GraphRepository.ensure_schema()` 幂等执行。",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(path: str | Path, content: str) -> Path:
    """把报告写入磁盘（自动创建父目录）。

    Args:
        path: 目标路径。
        content: Markdown 文本。

    Returns:
        实际写入的路径。
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def format_extraction(result: ExtractionResult) -> str:
    """格式化单条抽取结果（打印用，纯函数）。

    Args:
        result: 抽取结果。

    Returns:
        形如 ``[OK  ] CVE-2024-3400 节点=7（Component:2…）边=9（AFFECTS:2…）`` 的一行文本。
    """
    return f"[OK  ] {result.vuln_id} {result.summary()}"


async def run(args: argparse.Namespace) -> int:
    """执行图谱填充流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（0 成功；1 无可灌数据或 Neo4j 不可用）。
    """
    settings = get_settings()
    print(
        f"[环境] DSN={settings.effective_storage_dsn} | neo4j={settings.neo4j_uri} "
        f"| enabled={settings.neo4j_enabled}"
    )
    vulns = await load_enriched(settings, cve_id=args.cve, limit=max(1, args.limit), all_rows=args.all)
    if not vulns:
        print("[提示] 未找到已富化条目（请先跑 python -m scripts.run_enrich --cve ... 或 --limit N）")
        return 1

    extractions = [
        extract_graph(
            enriched,
            installed_on_max_per_component=settings.installed_on_max_per_component,
            component_max_per_vuln=settings.component_max_per_vuln,
        )
        for enriched in vulns
    ]
    for result in extractions:
        print(format_extraction(result))

    command = "python -m scripts.load_graph " + " ".join(sys.argv[1:]).strip()
    node_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}
    if args.dry_run:
        print("\n[dry-run] 跳过 Neo4j 写入与规模统计")
    else:
        client = Neo4jClient(settings)
        try:
            if not await client.ping():
                print(f"[FAIL] Neo4j 不可用：{settings.neo4j_uri}（检查 docker compose ps / NEO4J_ENABLED）")
                return 1
            repo = GraphRepository(client)
            if not args.no_schema:
                created = await repo.ensure_schema()
                print(f"[OK  ] 图谱 schema：{created} 条约束/索引就绪")
            written_nodes = 0
            written_edges = 0
            for enriched in vulns:
                stats = await repo.upsert_many(
                    extract_graph(
                        enriched,
                        installed_on_max_per_component=settings.installed_on_max_per_component,
                        component_max_per_vuln=settings.component_max_per_vuln,
                    )
                )
                written_nodes += stats["nodes"]
                written_edges += stats["edges"]
            node_counts = await repo.count_nodes()
            edge_counts = await repo.count_edges()
            print(
                f"\n[写入] 本次节点={written_nodes} 边={written_edges}（幂等 upsert）"
            )
        except Neo4jUnavailableError as exc:
            print(f"[FAIL] 图谱写入失败：{exc}")
            return 1
        finally:
            await client.aclose()

    print("[图谱规模] 节点：" + "、".join(f"{label}={count}" for label, count in node_counts.items() or []))
    print("[图谱规模] 边：" + "、".join(f"{relation}={count}" for relation, count in edge_counts.items() or []))
    if node_counts:
        print(f"[图谱合计] 节点={sum(node_counts.values())} 边={sum(edge_counts.values())}")
    else:
        print("[图谱合计] dry-run（未统计）")

    if not args.no_report:
        content = render_report(
            extractions, node_counts=node_counts, edge_counts=edge_counts, command=command, dry_run=args.dry_run
        )
        path = write_report(args.report_path, content)
        print(f"[报告] 已写入 {path}")
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
