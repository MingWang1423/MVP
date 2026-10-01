"""本地嵌入模型封装（PROJECT_PLAN.md §5.7 ``storage/embeddings.py`` / §3 技术选型「嵌入模型」）。

本模块是**全项目唯一的向量化出口**（地位与 ``llm/provider.py`` 之于 LLM 对称）：

1. :class:`SentenceTransformerEmbedder`：本地 ``sentence-transformers`` 模型
   （默认 ``BAAI/bge-small-zh-v1.5``，可切 ``BAAI/bge-m3``）。
   **不调用任何云端 embedding API** —— 离线可用、零成本（§3 技术选型）。
2. :class:`HashingEmbedder`：**确定性哈希嵌入**（词元 + 中文字符二元组，带符号哈希 + L2 归一）。
   无语义能力，用于「无网络 / 无权重」时的降级路径与单元测试，
   保证向量链路的**接口与流程**始终可跑通、可回归。
3. :func:`build_embedder`：唯一工厂。``EMBEDDING_BACKEND=auto``（默认）时先尝试本地模型，
   加载失败自动降级为哈希嵌入并**记录告警**（不抛异常、不中断主链路，§11.1 降级思路）。

Note:
    ``auto`` 模式需要「能访问 HuggingFace 或本地已缓存权重」。**完全断网**时请显式设置
    ``EMBEDDING_BACKEND=hashing``（哈希嵌入无语义能力，但保证链路可跑通、可回归）；
    本模块已为 ``huggingface_hub`` 设置**有界**下载超时默认值（见下方环境变量），
    避免离线环境下把主流程挂死在网络重试上。

接口约定：两个实现都是 ``chromadb`` 的 ``EmbeddingFunction`` 兼容对象
（``__call__(self, input)`` 签名 + ``name()`` / ``get_config()`` / ``build_from_config()``），
可直接传给 Chroma 集合；对外另有 :meth:`EmbedderBase.embed_query`
（bge 中文检索需给查询加指令前缀，见 :data:`BGE_ZH_QUERY_PREFIX`）。
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from collections.abc import Sequence

from aisec_intel.config import Settings, get_settings
from aisec_intel.logging_config import get_logger
from aisec_intel.normalize.dedupe import tokenize

logger = get_logger(__name__)

# 断网 / 无权重时，``sentence-transformers`` 的权重下载会以「分钟级」超时挂住主流程；
# 这里给 huggingface_hub 设置**有界**超时默认值（不覆盖用户显式配置），
# 使 ``EMBEDDING_BACKEND=auto`` 能在数十秒内判定「不可用」并降级为哈希嵌入。
os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "20")
os.environ.setdefault("HF_HUB_ETAG_TIMEOUT", "10")

EmbeddingBackend = str
"""嵌入后端标识：``auto`` / ``sentence_transformers`` / ``hashing``（取值见 ``config.Settings``）。"""

DEFAULT_HASH_DIM: int = 512
"""哈希嵌入维度（无权重降级 / 单测用；越大冲突越少，512 与本项目文本量级匹配）。"""

DEFAULT_BATCH_SIZE: int = 32
"""批量编码大小（本地模型 CPU 推理的折中值）。"""

BGE_ZH_QUERY_PREFIX: str = "为这个句子生成表示以用于检索相关文章："
"""bge 中文模型的**查询指令前缀**（官方推荐写法，只加在 query 侧，文档侧不加）。"""

_CJK_PATTERN: re.Pattern[str] = re.compile(r"[\u3400-\u9fff]+")
"""CJK 连续片段（用于生成字符二元组；英文/数字走 ``normalize.dedupe.tokenize``）。"""

SEMANTIC_BACKENDS: frozenset[str] = frozenset({"sentence_transformers"})
"""具备语义能力的后端标识。"""


class EmbedderUnavailableError(RuntimeError):
    """嵌入模型不可用（缺少依赖 / 权重缺失 / 无网络且本地无缓存）。"""


class EmbedderBase:
    """嵌入器基类（统一 ``dimension`` / ``name`` / 查询侧前缀语义）。

    Attributes:
        dim: 向量维度（哈希嵌入为构造参数；本地模型为模型输出维度）。
    """

    def __init__(self, *, dim: int) -> None:
        """初始化基类。

        Args:
            dim: 向量维度。
        """
        self.dim = int(dim)

    @property
    def dimension(self) -> int:
        """向量维度。"""
        return self.dim

    @property
    def is_semantic(self) -> bool:
        """是否具备语义能力（哈希嵌入为 ``False``，供上层在回答中提示口径）。"""
        return False

    def __call__(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002 - 参数名须与 chroma 协议一致
        """批量编码（``chromadb`` 的 ``EmbeddingFunction`` 协议入口）。

        Args:
            input: 待编码文本序列（**参数名固定为 ``input``**，Chroma 按签名校验）。

        Returns:
            与输入等长的向量列表。
        """
        raise NotImplementedError

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        """编码文档（默认直接调用 :meth:`__call__`）。

        Args:
            texts: 文档文本序列。

        Returns:
            向量列表。
        """
        return self(list(texts))

    def embed_query(self, text: str) -> list[float]:
        """编码查询（默认直接调用 :meth:`__call__`）。

        Args:
            text: 查询文本。

        Returns:
            查询向量。
        """
        return self([text])[0]

    @staticmethod
    def name() -> str:
        """返回嵌入器名称（供 Chroma 记录集合配置）。"""
        raise NotImplementedError

    def get_config(self) -> dict[str, object]:
        """返回可序列化配置（供 Chroma 持久化集合元数据）。"""
        raise NotImplementedError

    @staticmethod
    def build_from_config(config: dict[str, object]) -> EmbedderBase:
        """由序列化配置重建实例。

        Args:
            config: :meth:`get_config` 的输出。

        Returns:
            新的嵌入器实例。
        """
        raise NotImplementedError


class HashingEmbedder(EmbedderBase):
    """确定性哈希嵌入（离线降级 / 单元测试用，**无语义能力**）。

    算法（纯函数、跨进程稳定，不使用内置 ``hash()``）：
        1. 词元来源 = ``normalize.dedupe.tokenize`` 的英文数字词 + CJK 字符二元组；
        2. 每个词元取 ``blake2b`` 64 位摘要 → ``index = value % dim``、``sign = ±1``
           （带符号哈希，降低碰撞偏置）；
        3. 累加后 L2 归一化（余弦空间下与文本长度无关）。
    """

    def __init__(self, *, dim: int = DEFAULT_HASH_DIM) -> None:
        """初始化哈希嵌入器。

        Args:
            dim: 向量维度。

        Raises:
            ValueError: ``dim`` 非正（配置错误应显式暴露）。
        """
        if dim <= 0:
            raise ValueError(f"哈希嵌入维度必须为正整数，收到 {dim}")
        super().__init__(dim=dim)

    def __call__(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002 - chroma 协议固定参数名
        """批量编码（同输入必然同输出）。

        Args:
            input: 文本序列。

        Returns:
            维度为 ``dim`` 的向量列表。
        """
        return [self._encode(text) for text in input]

    def _encode(self, text: str) -> list[float]:
        """编码单条文本。

        Args:
            text: 任意文本（空文本返回零向量）。

        Returns:
            已 L2 归一化的向量。
        """
        buckets = [0.0] * self.dim
        for token in hashing_tokens(text):
            value = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
            buckets[value % self.dim] += 1.0 if value & 1 else -1.0
        norm = sum(component * component for component in buckets) ** 0.5
        if norm == 0.0:
            return buckets
        return [component / norm for component in buckets]

    @staticmethod
    def name() -> str:
        """返回嵌入器名称。"""
        return "aisec-hashing-embedder-v1"

    def get_config(self) -> dict[str, object]:
        """返回可序列化配置。"""
        return {"dim": self.dim}

    @staticmethod
    def build_from_config(config: dict[str, object]) -> HashingEmbedder:
        """由配置重建哈希嵌入器。

        Args:
            config: 形如 ``{"dim": 512}`` 的配置。

        Returns:
            新的 :class:`HashingEmbedder`。
        """
        return HashingEmbedder(dim=int(config.get("dim") or DEFAULT_HASH_DIM))


def hashing_tokens(text: str) -> list[str]:
    """把文本切成哈希词元（英文数字词 + CJK 字符二元组，纯函数）。

    Args:
        text: 任意文本。

    Returns:
        词元列表（可能为空）。
    """
    tokens = [token for token in tokenize(text) if len(token) > 1]
    for run in _CJK_PATTERN.findall(text):
        if len(run) == 1:
            tokens.append(run)
            continue
        tokens.extend(run[index : index + 2] for index in range(len(run) - 1))
    return tokens


class SentenceTransformerEmbedder(EmbedderBase):
    """本地 ``sentence-transformers`` 嵌入（默认 ``BAAI/bge-small-zh-v1.5``）。

    模型**惰性加载**（首次编码时才 import / 读权重），构造本对象不会触发任何网络请求；
    加载失败抛 :class:`EmbedderUnavailableError`，由 :func:`build_embedder` 决定是否降级为哈希嵌入。

    Attributes:
        model_name: 模型标识（如 ``BAAI/bge-small-zh-v1.5`` 或 ``BAAI/bge-m3``）。
        device: 推理设备（``cpu`` / ``cuda``）。
    """

    def __init__(
        self,
        model_name: str,
        *,
        device: str = "cpu",
        batch_size: int = DEFAULT_BATCH_SIZE,
        query_prefix: str = "",
        local_files_only: bool = False,
    ) -> None:
        """初始化（不加载权重）。

        Args:
            model_name: 模型标识。
            device: 推理设备。
            batch_size: 批量编码大小（``<=0`` 时回退到 :data:`DEFAULT_BATCH_SIZE`）。
            query_prefix: 查询侧指令前缀（bge 中文模型建议非空，见 :data:`BGE_ZH_QUERY_PREFIX`）。
            local_files_only: 是否只使用本地缓存（断网演练用；``True`` 时不发起下载）。
        """
        super().__init__(dim=0)
        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size if batch_size > 0 else DEFAULT_BATCH_SIZE
        self.query_prefix = query_prefix
        self.local_files_only = local_files_only
        self._model: object | None = None
        self._lock = threading.Lock()

    def ensure_model(self) -> object:
        """惰性加载模型（线程安全，可被工厂用于「提前探活」）。

        Returns:
            ``sentence_transformers.SentenceTransformer`` 实例。

        Raises:
            EmbedderUnavailableError: 缺少依赖，或权重不可用（无网络且无本地缓存）。
        """
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:  # pragma: no cover - 依赖缺失属环境问题
                raise EmbedderUnavailableError(
                    "未安装 sentence-transformers：pip install sentence-transformers"
                ) from exc
            try:
                model = SentenceTransformer(
                    self.model_name,
                    device=self.device,
                    local_files_only=self.local_files_only,
                )
            except Exception as exc:  # noqa: BLE001 - 任何加载失败都归为「不可用」，交由工厂降级
                raise EmbedderUnavailableError(
                    f"加载本地嵌入模型失败（{self.model_name}）：{type(exc).__name__}: {exc}"
                ) from exc
            self._model = model
            self.dim = int(model.get_sentence_embedding_dimension())
            logger.info(f"本地嵌入模型已加载：{self.model_name}（dim={self.dim} device={self.device}）")
            return self._model

    @property
    def is_semantic(self) -> bool:
        """本地句向量模型具备语义能力。"""
        return True

    def __call__(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002 - chroma 协议固定参数名
        """批量编码文档（**不加**查询前缀）。

        Args:
            input: 文本序列。

        Returns:
            向量列表（已 L2 归一化）。

        Raises:
            EmbedderUnavailableError: 模型不可用。
        """
        return self._encode([str(text) for text in input])

    def embed_query(self, text: str) -> list[float]:
        """编码查询（加 bge 指令前缀，提升中文检索召回）。

        Args:
            text: 查询文本。

        Returns:
            查询向量。

        Raises:
            EmbedderUnavailableError: 模型不可用。
        """
        return self._encode([f"{self.query_prefix}{text}"])[0]

    def _encode(self, texts: Sequence[str]) -> list[list[float]]:
        """调用模型编码（空输入不加载模型）。

        Args:
            texts: 文本序列。

        Returns:
            向量列表。
        """
        if not texts:
            return []
        model = self.ensure_model()
        vectors = model.encode(  # type: ignore[attr-defined]
            list(texts),
            batch_size=self.batch_size,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return [[float(value) for value in row] for row in vectors]

    @staticmethod
    def name() -> str:
        """返回嵌入器名称（固定常量，语义同 Chroma 的 EF 注册名）。"""
        return "aisec-sentence-transformer-v1"

    def get_config(self) -> dict[str, object]:
        """返回可序列化配置。"""
        return {
            "model_name": self.model_name,
            "device": self.device,
            "batch_size": self.batch_size,
            "query_prefix": self.query_prefix,
            "local_files_only": self.local_files_only,
        }

    @staticmethod
    def build_from_config(config: dict[str, object]) -> SentenceTransformerEmbedder:
        """由配置重建本地模型嵌入器。

        Args:
            config: :meth:`get_config` 的输出。

        Returns:
            新的 :class:`SentenceTransformerEmbedder`。
        """
        return SentenceTransformerEmbedder(
            str(config.get("model_name") or "BAAI/bge-small-zh-v1.5"),
            device=str(config.get("device") or "cpu"),
            batch_size=int(config.get("batch_size") or DEFAULT_BATCH_SIZE),
            query_prefix=str(config.get("query_prefix") or ""),
            local_files_only=bool(config.get("local_files_only", False)),
        )


def default_query_prefix(model_name: str) -> str:
    """按模型名推导查询指令前缀（纯函数）。

    规则：bge 中文系列（``bge-small-zh`` / ``bge-base-zh`` / ``bge-large-zh``）使用
    :data:`BGE_ZH_QUERY_PREFIX`；``bge-m3`` 与其它模型返回空串（官方不要求指令前缀）。

    Args:
        model_name: 模型标识。

    Returns:
        查询前缀（无要求时为空串）。
    """
    lowered = model_name.strip().lower()
    if "bge" in lowered and "m3" not in lowered:
        return BGE_ZH_QUERY_PREFIX
    return ""


def build_embedder(
    settings: Settings | None = None,
    *,
    backend: EmbeddingBackend | None = None,
) -> EmbedderBase:
    """按配置构建嵌入器（唯一工厂）。

    Args:
        settings: 全局配置；``None`` 时使用 :func:`aisec_intel.config.get_settings`。
        backend: 显式指定后端（``auto`` / ``sentence_transformers`` / ``hashing``）；``None`` 时取配置值。

    Returns:
        可用的嵌入器实例。``auto`` 模式下本地模型不可用时**返回哈希嵌入**（记录告警，不抛异常）。

    Raises:
        ValueError: 指定了未知后端标识。
        EmbedderUnavailableError: 显式要求本地模型且加载失败，且未开启自动降级。
    """
    resolved = settings or get_settings()
    selected = (backend or resolved.embedding_backend or "auto").strip().lower()
    if selected == "hashing":
        return HashingEmbedder(dim=resolved.embedding_dim)
    if selected != "auto" and selected not in SEMANTIC_BACKENDS:
        raise ValueError(f"未知 EMBEDDING_BACKEND：{selected}（可选 auto / sentence_transformers / hashing）")

    semantic = SentenceTransformerEmbedder(
        resolved.embedding_model,
        device=resolved.embedding_device,
        query_prefix=default_query_prefix(resolved.embedding_model) or resolved.embedding_query_prefix,
        local_files_only=resolved.embedding_local_files_only,
    )
    try:
        semantic.ensure_model()
    except EmbedderUnavailableError as exc:
        if not resolved.embedding_fallback_to_hash:
            raise
        logger.warning(f"本地嵌入模型不可用，降级为哈希嵌入（无语义能力）：{exc}")
        return HashingEmbedder(dim=resolved.embedding_dim)
    return semantic

