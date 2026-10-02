"""Day10 嵌入层单元测试（``aisec_intel.storage.embeddings``，PROJECT_PLAN.md §5.7）。

覆盖：哈希嵌入的确定性与维度、CJK 词元、查询前缀推导、工厂的降级与非法取值。
**不下载任何模型权重**（本地模型路径用桩替换，保证离线可跑）。
"""

from __future__ import annotations

import pytest

from aisec_intel.config import Settings
from aisec_intel.storage import embeddings as emb


def _settings(**overrides: object) -> Settings:
    """构造测试用配置（默认走哈希嵌入，避免任何模型下载）。"""
    base: dict[str, object] = {"embedding_backend": "hashing", "embedding_dim": 64}
    base.update(overrides)
    return Settings(**base)


class TestHashingEmbedder:
    """哈希嵌入（离线降级路径）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 6 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_dimension_and_determinism()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_dimension_and_determinism: {type(exc).__name__}: {exc}")
        try:
            self._case_test_vectors_are_l2_normalized()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_vectors_are_l2_normalized: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_text_returns_zero_vector()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_text_returns_zero_vector: {type(exc).__name__}: {exc}")
        try:
            self._case_test_similar_text_scores_higher_than_unrelated()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_similar_text_scores_higher_than_unrelated: {type(exc).__name__}: {exc}")
        try:
            self._case_test_non_positive_dim_rejected()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_non_positive_dim_rejected: {type(exc).__name__}: {exc}")
        try:
            self._case_test_name_and_config_roundtrip()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_name_and_config_roundtrip: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_dimension_and_determinism(self) -> None:
        """同输入必得同输出，且维度与配置一致。"""
        embedder = emb.HashingEmbedder(dim=32)
        first = embedder(["CVE-2024-3400 PAN-OS 命令注入"])
        second = embedder(["CVE-2024-3400 PAN-OS 命令注入"])
        assert len(first) == 1 and len(first[0]) == 32
        assert first == second
        assert embedder.dimension == 32

    def _case_test_vectors_are_l2_normalized(self) -> None:
        """向量已 L2 归一化（余弦空间下与文本长度无关）。"""
        vector = emb.HashingEmbedder(dim=64).embed_query("PAN-OS 命令注入漏洞")
        norm = sum(value * value for value in vector) ** 0.5
        assert norm == pytest.approx(1.0, abs=1e-9)

    def _case_test_empty_text_returns_zero_vector(self) -> None:
        """空文本返回零向量（不抛异常，避免空描述污染链路）。"""
        vector = emb.HashingEmbedder(dim=16).embed_query("")
        assert set(vector) == {0.0}

    def _case_test_similar_text_scores_higher_than_unrelated(self) -> None:
        """同主题文本的余弦相似度高于无关文本（哈希嵌入的基础可用性）。"""
        embedder = emb.HashingEmbedder(dim=512)
        query = embedder.embed_query("PAN-OS 命令注入 漏洞")
        near = embedder.embed_query("PAN-OS 命令注入漏洞 GlobalProtect")
        far = embedder.embed_query("Linux 内核提权 本地权限提升")
        similarity = lambda a, b: sum(x * y for x, y in zip(a, b, strict=True))  # noqa: E731 - 测试内联
        assert similarity(query, near) > similarity(query, far)

    def _case_test_non_positive_dim_rejected(self) -> None:
        """非法维度显式报错（禁止静默降级）。"""
        with pytest.raises(ValueError, match="维度必须为正整数"):
            emb.HashingEmbedder(dim=0)

    def _case_test_name_and_config_roundtrip(self) -> None:
        """``name()`` / ``get_config()`` / ``build_from_config()`` 可往返。"""
        embedder = emb.HashingEmbedder(dim=24)
        rebuilt = emb.HashingEmbedder.build_from_config(embedder.get_config())
        assert emb.HashingEmbedder.name() == "aisec-hashing-embedder-v1"
        assert rebuilt.dimension == 24
        assert rebuilt(["AbC"]) == embedder(["AbC"])

    def test_merged_batch2(self) -> None:
        """合并用例批次 2：顺序执行 1 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_is_semantic_flag()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_is_semantic_flag: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_is_semantic_flag(self) -> None:
        """哈希嵌入不具备语义能力（供上层提示口径）。"""
        assert emb.HashingEmbedder(dim=8).is_semantic is False


class TestHashingTokens:
    """词元切分（英文数字词 + 中文二元组）。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_mixed_language_tokens()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_mixed_language_tokens: {type(exc).__name__}: {exc}")
        try:
            self._case_test_single_cjk_char_kept()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_single_cjk_char_kept: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_mixed_language_tokens(self) -> None:
        """中英混排都能切出词元（中文按二元组，保证可哈希）。"""
        tokens = emb.hashing_tokens("PAN-OS 命令注入 exploit")
        assert "pan" in tokens and "exploit" in tokens
        assert "命令" in tokens and "令注" in tokens and "注入" in tokens

    def _case_test_single_cjk_char_kept(self) -> None:
        """单个汉字也保留（避免短查询无词元）。"""
        assert emb.hashing_tokens("漏") == ["漏"]


class TestQueryPrefix:
    """查询指令前缀推导（bge 中文系列需要，m3 不需要）。"""

    @pytest.mark.parametrize(
        ("model_name", "expected"),
        [
            ("BAAI/bge-small-zh-v1.5", emb.BGE_ZH_QUERY_PREFIX),
            ("bge-large-zh", emb.BGE_ZH_QUERY_PREFIX),
            ("BAAI/bge-m3", ""),
            ("sentence-transformers/all-MiniLM-L6-v2", ""),
        ],
    )
    def test_prefix_by_model(self, model_name: str, expected: str) -> None:
        assert emb.default_query_prefix(model_name) == expected


class TestBuildEmbedder:
    """工厂：后端选择与降级。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 2 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_hashing_backend()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_hashing_backend: {type(exc).__name__}: {exc}")
        try:
            self._case_test_unknown_backend_raises()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_unknown_backend_raises: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_hashing_backend(self) -> None:
        """显式 hashing 后端直接返回哈希嵌入。"""
        embedder = emb.build_embedder(_settings())
        assert isinstance(embedder, emb.HashingEmbedder)
        assert embedder.dimension == 64

    def _case_test_unknown_backend_raises(self) -> None:
        """未知后端标识报错（配置错误应显式暴露）。"""
        with pytest.raises(ValueError, match="未知 EMBEDDING_BACKEND"):
            emb.build_embedder(_settings(embedding_backend="openai-api"))

    def test_auto_falls_back_to_hashing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``auto`` 模式下本地模型不可用时自动降级为哈希嵌入（不抛异常）。"""
        settings = _settings(embedding_backend="auto")

        def _boom(self: emb.SentenceTransformerEmbedder) -> object:
            raise emb.EmbedderUnavailableError("模拟无网络 / 无权重")

        monkeypatch.setattr(emb.SentenceTransformerEmbedder, "ensure_model", _boom)
        embedder = emb.build_embedder(settings)
        assert isinstance(embedder, emb.HashingEmbedder)

    def test_strict_mode_raises_without_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """显式 sentence_transformers + 关闭降级时，模型不可用即报错。"""
        settings = _settings(embedding_backend="sentence_transformers", embedding_fallback_to_hash=False)

        def _boom(self: emb.SentenceTransformerEmbedder) -> object:
            raise emb.EmbedderUnavailableError("模拟无权重")

        monkeypatch.setattr(emb.SentenceTransformerEmbedder, "ensure_model", _boom)
        with pytest.raises(emb.EmbedderUnavailableError):
            emb.build_embedder(settings)


class TestSentenceTransformerEmbedder:
    """本地模型嵌入器（用 ``sentence_transformers`` 桩替换，验证协议与查询前缀拼接）。"""

    @staticmethod
    def _patch_module(monkeypatch: pytest.MonkeyPatch, factory: type) -> None:
        """把 ``sentence_transformers`` 模块替换为桩（避免真实权重下载 / torch 导入）。"""
        import sys
        import types

        monkeypatch.setitem(sys.modules, "sentence_transformers", types.SimpleNamespace(SentenceTransformer=factory))

    def test_load_path_sets_dimension_and_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """加载路径：``ensure_model`` 记录维度；``embed_query`` 打前缀、``__call__`` 不打。"""

        class FakeModel:
            """最小模型桩。"""

            def __init__(self, model_name: str, **_: object) -> None:
                self.model_name = model_name

            def get_sentence_embedding_dimension(self) -> int:
                return 3

            def encode(self, texts: list[str], **_: object) -> list[list[float]]:
                return [[float(len(text)), 0.0, 1.0] for text in texts]

        self._patch_module(monkeypatch, FakeModel)
        embedder = emb.SentenceTransformerEmbedder("BAAI/bge-small-zh-v1.5", query_prefix="P:")
        assert embedder(["abc"]) == [[3.0, 0.0, 1.0]]
        assert embedder.embed_query("abc") == [5.0, 0.0, 1.0]  # "P:abc" 长度 5
        assert embedder.dimension == 3
        assert embedder.is_semantic is True

    def test_empty_input_does_not_load_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """空输入不加载模型（避免无意义的权重加载）。"""

        class ExplodingModel:
            """一旦被实例化即失败，用于证明「未加载」。"""

            def __init__(self, *_: object, **__: object) -> None:
                raise AssertionError("空输入不应加载模型")

        self._patch_module(monkeypatch, ExplodingModel)
        embedder = emb.SentenceTransformerEmbedder("BAAI/bge-m3")
        assert embedder([]) == []

    def test_load_failure_wrapped_as_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """权重不可用统一包装为 :class:`EmbedderUnavailableError`（便于工厂降级）。"""

        class BrokenModel:
            """模拟离线 / 权重缺失。"""

            def __init__(self, *_: object, **__: object) -> None:
                raise OSError("无法连接 huggingface.co")

        self._patch_module(monkeypatch, BrokenModel)
        embedder = emb.SentenceTransformerEmbedder("BAAI/bge-m3")
        with pytest.raises(emb.EmbedderUnavailableError, match="加载本地嵌入模型失败"):
            embedder.ensure_model()

    def test_config_roundtrip(self) -> None:
        """``get_config`` 可被 ``build_from_config`` 还原（不加载权重）。"""
        embedder = emb.SentenceTransformerEmbedder("BAAI/bge-m3", device="cpu", batch_size=8)
        rebuilt = emb.SentenceTransformerEmbedder.build_from_config(embedder.get_config())
        assert rebuilt.model_name == "BAAI/bge-m3"
        assert rebuilt.batch_size == 8
        assert emb.SentenceTransformerEmbedder.name() == "aisec-sentence-transformer-v1"