"""向量索引填充脚本（Day10 P6 收尾；PROJECT_PLAN.md §5.7 Chroma 向量化）。

把三张表向量化写入 ChromaDB（嵌入在本地完成，不调任何外部 API）：

======================  ====================  ==================================
集合                     数据源                 渲染口径
======================  ====================  ==================================
``vuln_descriptions``   ``unified_vuln``      :func:`~aisec_intel.normalize.index_text.render_vuln_text`
``paper_abstracts``     ``raw_item``（论文源）  :func:`~aisec_intel.normalize.papers.paper_text`
``remediation_texts``   ``enriched_vuln``     :func:`~aisec_intel.normalize.index_text.render_remediation_text`
======================  ====================  ==================================

用法::

    python -m scripts.index_vectors                                   # 三个集合全量
    python -m scripts.index_vectors --all                             # 同上（调度器 pipeline 向量层使用）
    python -m scripts.index_vectors --collection vuln_descriptions --limit 100
    python -m scripts.index_vectors --rebuild --limit 200             # 先清空再重建索引
    python -m scripts.index_vectors --dsn sqlite+aiosqlite:///./data/aisec.db
    python -m scripts.index_vectors --embedding-backend hashing       # 无权重时离线跑通
    python -m scripts.index_vectors --dry-run                         # 只读库不写向量

输出：每个集合的「读取条数 / 写入条数 / 耗时」+ 向量库统计。
退出码：``0`` = 成功；``1`` = 全部集合均失败。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sqlalchemy import select  # noqa: E402

from aisec_intel.config import Settings, get_settings  # noqa: E402
from aisec_intel.logging_config import get_logger  # noqa: E402
from aisec_intel.models.base import iso_z  # noqa: E402
from aisec_intel.normalize.index_text import (  # noqa: E402
    remediation_index_metadata,
    render_remediation_text,
    render_vuln_text,
    vuln_index_metadata,
)
from aisec_intel.normalize.papers import paper_text  # noqa: E402
from aisec_intel.storage.database import get_engine, session_scope  # noqa: E402
from aisec_intel.storage.models.enriched import EnrichedVulnRow  # noqa: E402
from aisec_intel.storage.models.vuln import UnifiedVulnRow  # noqa: E402
from aisec_intel.storage.repositories.paper_repo import PaperRepository  # noqa: E402
from aisec_intel.storage.vector_store import (  # noqa: E402
    COLLECTION_PAPER_ABSTRACTS,
    COLLECTION_REMEDIATION_TEXTS,
    COLLECTION_VULN_DESCRIPTIONS,
    COLLECTIONS,
    VectorDoc,
    VectorStore,
    VectorStoreError,
)

logger = get_logger(__name__)

ALL_COLLECTIONS: str = "all"
"""``--collection all``：处理全部集合。"""

DEFAULT_LIMIT: int = 500
"""默认每集合索引条数（与富化批量同量级，避免误索引全库）。"""

DEFAULT_TIMEOUT_S: float = 30.0
"""单集合「读库 + 写入」的整体超时（秒）。

Note:
    数据库不可达时（如 PG 容器未起且端口被黑洞），底层连接可能长时间无响应；
    该超时保证 CLI **快速失败并给出可操作的提示**，而不是把演示现场挂死。
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """解析命令行参数。

    Args:
        argv: 参数列表；``None`` 表示使用 ``sys.argv``。

    Returns:
        解析后的命名空间。
    """
    parser = argparse.ArgumentParser(description="ChromaDB 向量索引填充（unified/enriched/paper → 三集合）")
    parser.add_argument(
        "--collection",
        default=ALL_COLLECTIONS,
        choices=[ALL_COLLECTIONS, *COLLECTIONS],
        help=f"目标集合（默认 {ALL_COLLECTIONS}）",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=f"等价 --collection {ALL_COLLECTIONS}（全量三集合；调度器 pipeline 向量层使用）",
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"每集合索引条数（默认 {DEFAULT_LIMIT}）")
    parser.add_argument("--rebuild", action="store_true", help="先删除并重建目标集合（幂等重跑）")
    parser.add_argument("--dsn", default=None, help="覆盖数据库 DSN（等价 DATABASE_URL；降级演示用）")
    parser.add_argument(
        "--embedding-backend",
        default=None,
        choices=["auto", "sentence_transformers", "hashing"],
        help="覆盖 EMBEDDING_BACKEND（离线无权重时用 hashing）",
    )
    parser.add_argument("--ephemeral", action="store_true", help="写入内存向量库（不落盘，演练用）")
    parser.add_argument("--dry-run", action="store_true", help="只读库并打印条数，不写向量库")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"单集合读库+写入的整体超时秒数（默认 {DEFAULT_TIMEOUT_S}；连不上库时快速失败而非挂死）",
    )
    return parser.parse_args(argv)


def resolve_settings(args: argparse.Namespace) -> Settings:
    """按命令行覆盖项构造配置。

    Args:
        args: 命令行参数。

    Returns:
        覆盖后的 :class:`~aisec_intel.config.Settings`（不修改进程级单例）。
    """
    settings = get_settings()
    overrides: dict[str, object] = {}
    if args.dsn:
        overrides["database_url"] = args.dsn
    if args.embedding_backend:
        overrides["embedding_backend"] = args.embedding_backend
    return settings.model_copy(update=overrides) if overrides else settings


def target_collections(name: str) -> list[str]:
    """把 ``--collection`` 取值展开为集合列表（纯函数）。

    Args:
        name: ``all`` 或具体集合名。

    Returns:
        集合名列表（未知取值返回空列表）。
    """
    if name == ALL_COLLECTIONS:
        return list(COLLECTIONS)
    return [name] if name in COLLECTIONS else []


async def build_vuln_docs(settings: Settings, *, limit: int) -> list[VectorDoc]:
    """读取 ``unified_vuln`` 并渲染为「漏洞描述」文档。

    Args:
        settings: 配置。
        limit: 条数上限。

    Returns:
        :class:`~aisec_intel.storage.vector_store.VectorDoc` 列表。
    """
    stmt = (
        select(UnifiedVulnRow)
        .order_by(UnifiedVulnRow.normalized_at.desc(), UnifiedVulnRow.vuln_id)
        .limit(max(1, limit))
    )
    async with session_scope(get_engine(settings)) as session:
        rows = (await session.execute(stmt)).scalars().all()
    docs: list[VectorDoc] = []
    for row in rows:
        vuln = row.to_domain()
        docs.append(
            VectorDoc(
                doc_id=f"{COLLECTION_VULN_DESCRIPTIONS}:{vuln.vuln_id}",
                content=render_vuln_text(vuln),
                metadata=vuln_index_metadata(vuln),
            )
        )
    return docs


async def build_remediation_docs(settings: Settings, *, limit: int) -> list[VectorDoc]:
    """读取 ``enriched_vuln``（联父表）并渲染为「处置要点」文档。

    Args:
        settings: 配置。
        limit: 条数上限。

    Returns:
        :class:`~aisec_intel.storage.vector_store.VectorDoc` 列表。
    """
    stmt = (
        select(EnrichedVulnRow, UnifiedVulnRow)
        .join(UnifiedVulnRow, UnifiedVulnRow.vuln_id == EnrichedVulnRow.vuln_id)
        .order_by(EnrichedVulnRow.enriched_at.desc(), EnrichedVulnRow.vuln_id)
        .limit(max(1, limit))
    )
    async with session_scope(get_engine(settings)) as session:
        rows = (await session.execute(stmt)).all()
    docs: list[VectorDoc] = []
    for enriched_row, vuln_row in rows:
        enriched = enriched_row.to_domain(vuln_row.to_domain())
        docs.append(
            VectorDoc(
                doc_id=f"{COLLECTION_REMEDIATION_TEXTS}:{enriched.vuln_id}",
                content=render_remediation_text(enriched),
                metadata=remediation_index_metadata(enriched),
            )
        )
    return docs


async def build_paper_docs(settings: Settings, *, limit: int) -> list[VectorDoc]:
    """读取 ``raw_item`` 中的论文源行并渲染为「论文摘要」文档。

    Args:
        settings: 配置。
        limit: 条数上限。

    Returns:
        :class:`~aisec_intel.storage.vector_store.VectorDoc` 列表。
    """
    async with session_scope(get_engine(settings)) as session:
        papers = await PaperRepository(session).list_recent(limit=max(1, limit))
    docs: list[VectorDoc] = []
    for paper in papers:
        content = paper_text(paper)
        if not content.strip():
            continue
        metadata: dict[str, str] = {"paper_id": paper.paper_id, "source": paper.source}
        if paper.published_at is not None:
            metadata["published_at"] = iso_z(paper.published_at)
        docs.append(
            VectorDoc(
                doc_id=f"{COLLECTION_PAPER_ABSTRACTS}:{paper.paper_id}",
                content=content,
                metadata=metadata,
            )
        )
    return docs


BUILDERS = {
    COLLECTION_VULN_DESCRIPTIONS: build_vuln_docs,
    COLLECTION_PAPER_ABSTRACTS: build_paper_docs,
    COLLECTION_REMEDIATION_TEXTS: build_remediation_docs,
}
"""集合名 → 文档构建函数（唯一注册表，新增集合只需在此登记）。"""


async def index_collection(
    store: VectorStore,
    settings: Settings,
    collection: str,
    *,
    limit: int,
    rebuild: bool,
    dry_run: bool,
) -> tuple[int, float]:
    """索引单个集合（读取 → 渲染 → 批量 upsert）。

    Args:
        store: 向量库。
        settings: 配置。
        collection: 集合名。
        limit: 条数上限。
        rebuild: 是否先删除并重建集合。
        dry_run: 是否只读库不写入。

    Returns:
        ``(写入条数, 耗时秒)``。

    Raises:
        KeyError: 集合未在 :data:`BUILDERS` 注册。
    """
    builder = BUILDERS[collection]
    started = time.perf_counter()
    if rebuild and not dry_run:
        store.reset(collection)
    docs = await builder(settings, limit=limit)
    written = 0 if dry_run else store.upsert(collection, docs)
    elapsed = time.perf_counter() - started
    tag = "dry-run" if dry_run else "OK"
    print(f"[{tag:<7}] {collection:<20} 读取={len(docs):<5} 写入={written:<5} 耗时={elapsed:.2f}s")
    return written, elapsed


async def run(args: argparse.Namespace) -> int:
    """执行索引填充流程。

    Args:
        args: 命令行参数。

    Returns:
        进程退出码（``0`` 成功；``1`` 无可用集合或全部集合失败）。
    """
    settings = resolve_settings(args)
    collections = target_collections(ALL_COLLECTIONS if args.all else args.collection)
    print(
        f"[环境] DSN={settings.effective_storage_dsn} | vector={settings.effective_vector_backend} "
        f"| embedder={settings.embedding_model}({args.embedding_backend or settings.embedding_backend})"
    )
    if not collections:
        print(f"[FAIL] 无效的 --collection：{args.collection}")
        return 1

    store = VectorStore(settings=settings, in_memory=args.ephemeral)
    failures: list[str] = []
    total_written = 0
    total_started = time.perf_counter()
    try:
        for collection in collections:
            try:
                written, _ = await asyncio.wait_for(
                    index_collection(
                        store,
                        settings,
                        collection,
                        limit=max(1, args.limit),
                        rebuild=args.rebuild,
                        dry_run=args.dry_run,
                    ),
                    timeout=max(1.0, args.timeout),
                )
                total_written += written
            except TimeoutError:
                failures.append(collection)
                print(
                    f"[FAIL] {collection}：读取超时（>{args.timeout:.0f}s）"
                    "（检查 DATABASE_URL / docker compose ps，或先跑 python -m scripts.init_db）"
                )
            except (VectorStoreError, KeyError) as exc:
                failures.append(collection)
                print(f"[FAIL] {collection}：{type(exc).__name__}: {exc}")
            except Exception as exc:  # 读库失败（连不上 PG / 表未建）不阻断其它集合，统一留痕
                failures.append(collection)
                print(
                    f"[FAIL] {collection}：{type(exc).__name__}: {exc}"
                    "（检查 DATABASE_URL / docker compose ps，或先跑 python -m scripts.init_db）"
                )
        total_elapsed = time.perf_counter() - total_started
        # 未写入任何向量时**完全不触碰向量库与嵌入器**：
        # dry-run 无需建集合；全部读库失败时更不该因「加载嵌入模型」把 CLI 卡死。
        if not args.dry_run and total_written:
            stats = store.stats()
            print("\n[向量库统计] " + "、".join(f"{name}={count}" for name, count in stats.items()))
        dimension = "-" if (args.dry_run or not total_written) else str(store.dimension)
        print(
            f"[合计] 集合数={len(collections)} 写入={total_written} 耗时={total_elapsed:.2f}s "
            f"（backend={store.backend} dim={dimension}）"
        )
    finally:
        store.close()
    return 1 if failures and len(failures) == len(collections) else 0


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
