"""ChromaDB 向量库适配器（Day10 P6 收尾，PROJECT_PLAN.md §5.7 向量化 / §3 技术选型「向量库」）。

设计要点：

1. **官方 client**：``chromadb.PersistentClient``（``VECTOR_BACKEND=chroma_persistent``）或
   ``chromadb.EphemeralClient``（``chroma_memory`` / 降级模式 / 单元测试）；
2. **三个集合**（与三类可检索文本一一对应，见 :mod:`aisec_intel.normalize.index_text`）：

   - :data:`COLLECTION_VULN_DESCRIPTIONS`：漏洞描述（来源 ``unified_vuln``）；
   - :data:`COLLECTION_PAPER_ABSTRACTS`：论文摘要（来源 ``raw_item`` 论文源）；
   - :data:`COLLECTION_REMEDIATION_TEXTS`：处置要点（来源 ``enriched_vuln``）；

3. **嵌入由本项目自持**：向量一律由 :mod:`aisec_intel.storage.embeddings` 显式计算后传入
   （``upsert(embeddings=...)`` / ``query(query_embeddings=...)``），
   不依赖 Chroma 内置的 ONNX MiniLM —— 避免隐式下载、保证「文档/查询」两侧口径一致；
4. **元数据扁平化**：Chroma 只接受 ``str/int/float/bool``，``None`` 会直接报错；
   :func:`sanitize_metadata` 负责丢弃 ``None``、把时间转 ISO8601、把列表转逗号串；
5. **失败不静默**：集合名越界、维度不一致、依赖缺失均抛异常，
   由上层（:class:`aisec_intel.services.retrieval_service.RetrievalService`）决定降级；
   本模块**只做存储**，不含任何业务语义与 LLM 调用。
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import to_utc
from aisec_intel.storage.embeddings import EmbedderBase, HashingEmbedder, build_embedder

logger = get_logger(__name__)

COLLECTION_VULN_DESCRIPTIONS: str = "vuln_descriptions"
"""集合①：漏洞描述（``unified_vuln`` → :func:`normalize.index_text.render_vuln_text`）。"""

COLLECTION_PAPER_ABSTRACTS: str = "paper_abstracts"
"""集合②：论文摘要（``raw_item`` 论文源 → :func:`normalize.papers.paper_text`）。"""

COLLECTION_REMEDIATION_TEXTS: str = "remediation_texts"
"""集合③：处置要点（``enriched_vuln`` → :func:`normalize.index_text.render_remediation_text`）。"""

COLLECTIONS: tuple[str, ...] = (
    COLLECTION_VULN_DESCRIPTIONS,
    COLLECTION_PAPER_ABSTRACTS,
    COLLECTION_REMEDIATION_TEXTS,
)
"""全部集合名（顺序即默认初始化顺序）。"""

MAX_BATCH_SIZE: int = 512
"""单次 ``upsert`` 的最大条数（分批写入，避免超大批次拖垮嵌入式后端）。"""

DEFAULT_TOP_K: int = 10
"""默认召回条数。"""

MetadataValue = str | int | float | bool
"""Chroma 允许的元数据类型（``None`` 与嵌套结构一律非法）。"""


class VectorStoreError(RuntimeError):
    """向量库错误基类。"""


class VectorStoreUnavailableError(VectorStoreError):
    """向量库不可用（未安装 chromadb / 客户端创建失败）。"""


@dataclass(frozen=True, slots=True)
class VectorDoc:
    """待写入向量库的文档。

    Attributes:
        doc_id: 文档主键（幂等键；建议 ``f"{collection}:{业务主键}"``）。
        content: 文档正文（向量化对象，检索命中后原样返回给引用层）。
        metadata: 扁平元数据（``cve_id`` / ``source`` / ``published_at`` 等）。
    """

    doc_id: str
    content: str
    metadata: dict[str, MetadataValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VectorHit:
    """向量检索命中。

    Attributes:
        doc_id: 文档主键。
        content: 文档正文。
        metadata: 元数据。
        distance: 原始距离（余弦空间下 ``1 - 余弦相似度``）。
        score: 归一化相似度，区间 ``[0.0, 1.0]``（越大越相关，供融合排序使用）。
    """

    doc_id: str
    content: str
    metadata: dict[str, MetadataValue]
    distance: float
    score: float


def sanitize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, MetadataValue]:
    """把任意元数据扁平化为 Chroma 可接受的形式（纯函数）。

    规则：
        - ``None`` 值**整键丢弃**（Chroma 拒绝 ``None``）；
        - ``datetime`` → ISO8601 UTC 字符串（§10.2 不变式 3）；
        - ``list`` / ``tuple`` / ``set`` → 逗号串（保持确定性：集合先排序）；
        - 其余标量按原类型保留；``dict`` 等复杂结构转 ``str`` 兜底。

    Args:
        metadata: 原始元数据。

    Returns:
        仅含 ``str/int/float/bool`` 的字典；**可能为空**（写入时由
        :meth:`VectorStore.upsert` 转为 ``None``，因为 Chroma 拒绝空 dict）。
    """
    cleaned: dict[str, MetadataValue] = {}
    for key, value in (metadata or {}).items():
        if value is None:
            continue
        if isinstance(value, bool | int | float | str):
            cleaned[str(key)] = value
        elif isinstance(value, datetime):
            cleaned[str(key)] = to_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")
        elif isinstance(value, list | tuple | set):
            items = sorted(str(item) for item in value) if isinstance(value, set) else [str(item) for item in value]
            cleaned[str(key)] = ",".join(items)
        else:  # pragma: no cover - 兜底分支，保持「绝不写入非法值」的契约
            cleaned[str(key)] = str(value)
    return cleaned


def score_from_distance(distance: float | None) -> float:
    """把余弦距离换算为相似度得分（纯函数）。

    Args:
        distance: Chroma 返回的距离（余弦空间下 ``1 - 相似度``；``None`` 视为最不相关）。

    Returns:
        相似度，区间 ``[0.0, 1.0]``。
    """
    if distance is None:
        return 0.0
    return max(0.0, min(1.0, 1.0 - float(distance)))


def hits_from_query(raw: Mapping[str, Any], *, limit: int | None = None) -> list[VectorHit]:
    """把 Chroma ``query`` 的原始返回值解析为 :class:`VectorHit` 列表（纯函数）。

    Args:
        raw: ``Collection.query`` 的返回值（``ids`` / ``documents`` / ``metadatas`` / ``distances`` 均为嵌套列表）。
        limit: 最多返回条数；``None`` 表示全部。

    Returns:
        命中列表（保持 Chroma 的距离升序）。
    """
    ids = (raw.get("ids") or [[]])[0] or []
    documents = (raw.get("documents") or [[]])[0] or []
    metadatas = (raw.get("metadatas") or [[]])[0] or []
    distances = (raw.get("distances") or [[]])[0] or []
    hits: list[VectorHit] = []
    for index, doc_id in enumerate(ids):
        if limit is not None and len(hits) >= limit:
            break
        distance = float(distances[index]) if index < len(distances) and distances[index] is not None else None
        hits.append(
            VectorHit(
                doc_id=str(doc_id),
                content=str(documents[index]) if index < len(documents) and documents[index] is not None else "",
                metadata=dict(metadatas[index]) if index < len(metadatas) and metadatas[index] else {},
                distance=float(distance) if distance is not None else 1.0,
                score=score_from_distance(distance),
            )
        )
    return hits


def dedupe_docs(docs: Sequence[VectorDoc]) -> list[VectorDoc]:
    """按 ``doc_id`` 去重（同批重复时保留**最后一条**，纯函数）。

    典型场景：``raw_item`` 中同一篇论文存在多个采集版本（``sha256`` 不同、``source_id`` 相同），
    渲染出的 ``doc_id`` 相同；而 Chroma 的 ``upsert`` **不接受同一批次内重复 id**，
    会导致整批写入失败（实测：``paper_abstracts`` 报 ``Expected IDs to be unique``）。

    Args:
        docs: 待写入文档序列。

    Returns:
        去重后的文档列表（保持首次出现的顺序）。
    """
    merged: dict[str, VectorDoc] = {}
    for doc in docs:
        merged[doc.doc_id] = doc
    return list(merged.values())



def chunked(items: Sequence[Any], size: int = MAX_BATCH_SIZE) -> list[list[Any]]:
    """把序列切成固定大小的批次（纯函数）。

    Args:
        items: 待切分序列。
        size: 单批上限（``<=0`` 时回退到 :data:`MAX_BATCH_SIZE`）。

    Returns:
        批次列表（空输入返回空列表）。
    """
    step = size if size > 0 else MAX_BATCH_SIZE
    return [list(items[index : index + step]) for index in range(0, len(items), step)]


class VectorStore:
    """ChromaDB 向量库门面（三集合统一读写，惰性连接、可复用）。

    Attributes:
        path: 持久化目录（内存模式为 ``None``）。
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        embedder: EmbedderBase | None = None,
        path: str | None = None,
        in_memory: bool = False,
    ) -> None:
        """初始化（不创建客户端、不加载嵌入模型）。

        Args:
            settings: 全局配置；``None`` 时使用 :func:`aisec_intel.config.get_settings`。
            embedder: 嵌入器；``None`` 时按配置惰性构建（``EMBEDDING_BACKEND=auto``）。
            path: 持久化目录覆盖值；``None`` 时取 ``CHROMA_PATH``。
            in_memory: ``True`` 时强制内存后端（降级模式 / 单元测试）。
        """
        self._settings = settings or get_settings()
        self.path: str | None = None if in_memory else (path or self._settings.chroma_path)
        self._embedder = embedder
        self._client: Any | None = None
        self._collections: dict[str, Any] = {}

    @classmethod
    def ephemeral(cls, *, settings: Settings | None = None, dim: int = 0) -> VectorStore:
        """构造内存态向量库（默认哈希嵌入，供单元测试与降级模式）。

        Args:
            settings: 全局配置；``None`` 时使用进程级单例。
            dim: 哈希嵌入维度（``<=0`` 时取 :data:`~aisec_intel.storage.embeddings.DEFAULT_HASH_DIM`）。

        Returns:
            内存态 :class:`VectorStore`。
        """
        embedder = HashingEmbedder(dim=dim) if dim > 0 else build_embedder(settings, backend="hashing")
        return cls(settings=settings, embedder=embedder, in_memory=True)

    @property
    def backend(self) -> str:
        """后端标识（``chroma_persistent`` / ``chroma_memory``）。"""
        return "chroma_memory" if self.path is None else "chroma_persistent"

    @property
    def embedder(self) -> EmbedderBase:
        """嵌入器（首次访问时按配置构建）。

        Returns:
            可用的嵌入器实例。
        """
        if self._embedder is None:
            self._embedder = build_embedder(self._settings)
        return self._embedder

    @property
    def dimension(self) -> int:
        """向量维度（哈希嵌入构造即可知；本地模型需加载后才可知）。"""
        return self.embedder.dimension

    @property
    def client(self) -> Any:
        """Chroma 客户端（惰性创建）。

        Returns:
            ``chromadb.ClientAPI`` 实例。

        Raises:
            VectorStoreUnavailableError: 未安装 ``chromadb`` 或客户端创建失败。
        """
        if self._client is not None:
            return self._client
        try:
            import chromadb
        except ImportError as exc:  # pragma: no cover - 依赖缺失属环境问题
            raise VectorStoreUnavailableError("未安装 chromadb：pip install chromadb") from exc
        try:
            if self.path is None:
                self._client = chromadb.EphemeralClient()
            else:
                Path(self.path).mkdir(parents=True, exist_ok=True)
                self._client = chromadb.PersistentClient(path=str(self.path))
        except Exception as exc:  # noqa: BLE001 - 统一包装为领域错误，便于上层降级
            raise VectorStoreUnavailableError(f"创建 Chroma 客户端失败（{self.backend}）：{exc}") from exc
        logger.info(f"Chroma 客户端就绪：backend={self.backend} path={self.path or ':memory:'}")
        return self._client

    def collection(self, name: str) -> Any:
        """获取（或创建）集合（余弦空间）。

        Args:
            name: 集合名，必须是 :data:`COLLECTIONS` 之一。

        Returns:
            ``chromadb.Collection`` 实例。

        Raises:
            ValueError: 集合名未声明（防止拼错集合名静默创建空集合）。
            VectorStoreError: 创建失败。
        """
        if name not in COLLECTIONS:
            raise ValueError(f"未声明的向量集合：{name}（可选：{', '.join(COLLECTIONS)}）")
        if name in self._collections:
            return self._collections[name]
        try:
            handle = self.client.get_or_create_collection(
                name=name,
                embedding_function=self.embedder,
                metadata={"hnsw:space": "cosine"},
            )
        except Exception as exc:  # noqa: BLE001 - 统一包装
            raise VectorStoreError(f"获取向量集合失败：{name}：{exc}") from exc
        self._collections[name] = handle
        return handle

    def ensure_collections(self) -> list[str]:
        """创建全部集合（幂等；索引脚本与 ``scripts/init_db.py`` 共用）。

        Returns:
            就绪的集合名列表（顺序同 :data:`COLLECTIONS`）。
        """
        return [name for name in COLLECTIONS if self.collection(name) is not None]

    def upsert(self, collection: str, docs: Sequence[VectorDoc]) -> int:
        """批量幂等写入（按 ``doc_id`` 覆盖同键文档；同批重复 id 自动去重保留最后一条）。

        Args:
            collection: 集合名。
            docs: 待写入文档（空列表直接返回 ``0``，不触发嵌入计算）。

        Returns:
            实际写入条数（已按 ``doc_id`` 去重）。

        Raises:
            VectorStoreError: 写入失败（维度不一致 / 后端异常）。
        """
        if not docs:
            return 0
        unique_docs = dedupe_docs(docs)
        handle = self.collection(collection)
        written = 0
        try:
            for batch in chunked(unique_docs):
                contents = [doc.content for doc in batch]
                # Chroma 拒绝空 dict（"Expected metadata to be a non-empty dict"），
                # 无元数据的文档一律以 None 写入（等价于「不带元数据」）。
                metadatas = [sanitize_metadata(doc.metadata) or None for doc in batch]
                handle.upsert(
                    ids=[doc.doc_id for doc in batch],
                    embeddings=self.embedder.embed_documents(contents),
                    documents=contents,
                    metadatas=metadatas,
                )
                written += len(batch)
        except Exception as exc:  # noqa: BLE001 - 统一包装
            raise VectorStoreError(f"向量写入失败：collection={collection} 已写入 {written} 条：{exc}") from exc
        return written

    def query(
        self,
        collection: str,
        text: str,
        *,
        top_k: int = DEFAULT_TOP_K,
        where: Mapping[str, Any] | None = None,
    ) -> list[VectorHit]:
        """语义检索。

        Args:
            collection: 集合名。
            text: 查询文本（经 :meth:`EmbedderBase.embed_query` 编码；bge 中文自动加检索指令前缀）。
            top_k: 召回条数上限。
            where: 元数据过滤条件（Chroma 语法，如 ``{"severity": "CRITICAL"}``）。

        Returns:
            命中列表（按相似度降序，即距离升序）。

        Raises:
            VectorStoreError: 检索失败。
        """
        handle = self.collection(collection)
        if top_k <= 0 or not text.strip() or handle.count() == 0:
            return []
        try:
            raw = handle.query(
                query_embeddings=[self.embedder.embed_query(text)],
                n_results=max(1, top_k),
                where=dict(where) if where else None,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as exc:  # noqa: BLE001 - 统一包装
            raise VectorStoreError(f"向量检索失败：collection={collection}：{exc}") from exc
        return hits_from_query(raw, limit=top_k)

    def delete(
        self,
        collection: str,
        *,
        doc_ids: Sequence[str] | None = None,
        where: Mapping[str, Any] | None = None,
    ) -> int:
        """按主键或元数据删除文档。

        Args:
            collection: 集合名。
            doc_ids: 待删除主键。
            where: 元数据过滤条件。

        Returns:
            删除条数。

        Raises:
            ValueError: 未指定任何条件（清空整集合请用 :meth:`reset`，避免误删）。
            VectorStoreError: 删除失败。
        """
        if not doc_ids and not where:
            raise ValueError("delete 必须指定 doc_ids 或 where（清空集合请使用 reset）")
        handle = self.collection(collection)
        before = handle.count()
        try:
            handle.delete(ids=list(doc_ids) if doc_ids else None, where=dict(where) if where else None)
        except Exception as exc:  # noqa: BLE001 - 统一包装
            raise VectorStoreError(f"向量删除失败：collection={collection}：{exc}") from exc
        return max(0, before - handle.count())

    def count(self, collection: str) -> int:
        """集合内文档条数。

        Args:
            collection: 集合名。

        Returns:
            条数。
        """
        return int(self.collection(collection).count())

    def stats(self) -> dict[str, int]:
        """各集合条数快照（索引脚本与运维页用）。

        Returns:
            集合名 → 条数。
        """
        return {name: self.count(name) for name in COLLECTIONS}

    def reset(self, collection: str) -> None:
        """删除并重建集合（``--rebuild`` 用；幂等）。

        Args:
            collection: 集合名。

        Raises:
            ValueError: 集合名未声明。
            VectorStoreError: 重建失败。
        """
        if collection not in COLLECTIONS:
            raise ValueError(f"未声明的向量集合：{collection}（可选：{', '.join(COLLECTIONS)}）")
        self._collections.pop(collection, None)
        try:
            existing = {item.name for item in self.client.list_collections()}
            if collection in existing:
                self.client.delete_collection(collection)
        except Exception as exc:  # noqa: BLE001 - 统一包装
            raise VectorStoreError(f"重建向量集合失败：{collection}：{exc}") from exc
        logger.info(f"向量集合已重建：{collection}")

    def close(self) -> None:
        """释放客户端与集合句柄（幂等；Windows 下释放 SQLite 文件锁需要调用）。"""
        self._collections.clear()
        if self._client is None:
            return
        self._client = None
        try:
            from chromadb.api.client import SharedSystemClient

            SharedSystemClient.clear_system_cache()
        except Exception as exc:  # noqa: BLE001 - 释放失败不影响主流程
            logger.debug(f"释放 Chroma 系统缓存失败（忽略）：{exc}")
