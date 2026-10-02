"""Day10 向量库适配器单元测试（``aisec_intel.storage.vector_store``，PROJECT_PLAN.md §5.7）。

使用 Chroma **内存后端** + 哈希嵌入，不落盘、不下载模型；
另有 1 例用 ``tmp_path`` 验证持久化后端可重启复用。
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("chromadb", reason="需要 chromadb：pip install chromadb")

from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.storage.embeddings import HashingEmbedder  # noqa: E402
from aisec_intel.storage.vector_store import (  # noqa: E402
    COLLECTION_REMEDIATION_TEXTS,
    COLLECTION_VULN_DESCRIPTIONS,
    COLLECTIONS,
    VectorDoc,
    VectorStore,
    chunked,
    hits_from_query,
    sanitize_metadata,
    score_from_distance,
)


def _store(dim: int = 128) -> VectorStore:
    """构造内存态向量库（先清空进程内共享的内存系统，保证用例之间互不影响）。"""
    store = VectorStore.ephemeral(dim=dim)
    for existing in store.client.list_collections():
        store.client.delete_collection(existing.name)
    return store


class TestPureHelpers:
    """无 IO 的纯函数。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 4 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_sanitize_metadata_flattens_and_drops_none()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_sanitize_metadata_flattens_and_drops_none: {type(exc).__name__}: {exc}")
        try:
            self._case_test_hits_from_query_parses_nested_payload()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_hits_from_query_parses_nested_payload: {type(exc).__name__}: {exc}")
        try:
            self._case_test_hits_from_query_respects_limit()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_hits_from_query_respects_limit: {type(exc).__name__}: {exc}")
        try:
            self._case_test_chunked()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_chunked: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_sanitize_metadata_flattens_and_drops_none(self) -> None:
        """``None`` 丢弃、时间转 ISO8601 Z、列表转逗号串、标量原样保留。"""
        cleaned = sanitize_metadata(
            {
                "cve_id": "CVE-2024-3400",
                "kev": True,
                "score": 9.8,
                "count": 3,
                "published_at": datetime(2024, 4, 12, tzinfo=UTC),
                "sources": ["kev", "nvd"],
                "tags": {"b", "a"},
                "missing": None,
            }
        )
        assert "missing" not in cleaned
        assert cleaned["published_at"] == "2024-04-12T00:00:00Z"
        assert cleaned["sources"] == "kev,nvd"
        assert cleaned["tags"] == "a,b"
        assert cleaned["cve_id"] == "CVE-2024-3400" and cleaned["kev"] is True

    @pytest.mark.parametrize(
        ("distance", "expected"),
        [(0.0, 1.0), (0.25, 0.75), (1.0, 0.0), (2.0, 0.0), (-1.0, 1.0), (None, 0.0)],
    )
    def test_score_from_distance(self, distance: float | None, expected: float) -> None:
        """余弦距离 → 相似度，并夹紧到 ``[0,1]``。"""
        assert score_from_distance(distance) == pytest.approx(expected)

    def _case_test_hits_from_query_parses_nested_payload(self) -> None:
        """Chroma 的嵌套返回结构被正确摊平为 ``VectorHit``。"""
        raw = {
            "ids": [["a", "b"]],
            "documents": [["doc-a", "doc-b"]],
            "metadatas": [[{"cve_id": "CVE-1"}, None]],
            "distances": [[0.1, 0.4]],
        }
        hits = hits_from_query(raw, limit=2)
        assert [hit.doc_id for hit in hits] == ["a", "b"]
        assert hits[0].metadata == {"cve_id": "CVE-1"} and hits[1].metadata == {}
        assert hits[1].score == pytest.approx(0.6)

    def _case_test_hits_from_query_respects_limit(self) -> None:
        """``limit`` 生效（提前截断）。"""
        raw = {
            "ids": [["a", "b"]],
            "documents": [["x", "y"]],
            "metadatas": [[{}, {}]],
            "distances": [[0.0, 0.0]],
        }
        assert len(hits_from_query(raw, limit=1)) == 1

    def _case_test_chunked(self) -> None:
        """分批切分（空输入返回空列表）。"""
        assert [len(batch) for batch in chunked(list(range(5)), 2)] == [2, 2, 1]
        assert chunked([], 3) == []


class TestVectorStore:
    """写入 / 检索 / 过滤 / 删除 / 重建。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 6 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_upsert_count_and_idempotent()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_upsert_count_and_idempotent: {type(exc).__name__}: {exc}")
        try:
            self._case_test_query_ranks_similar_first()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_query_ranks_similar_first: {type(exc).__name__}: {exc}")
        try:
            self._case_test_query_with_metadata_filter()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_query_with_metadata_filter: {type(exc).__name__}: {exc}")
        try:
            self._case_test_query_empty_collection_and_blank_text()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_query_empty_collection_and_blank_text: {type(exc).__name__}: {exc}")
        try:
            self._case_test_delete_by_ids_and_guard()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_delete_by_ids_and_guard: {type(exc).__name__}: {exc}")
        try:
            self._case_test_reset_and_stats()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_reset_and_stats: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_upsert_count_and_idempotent(self) -> None:
        """同 ``doc_id`` 重复写入不新增条数（upsert 语义）。"""
        store = _store()
        try:
            docs = [
                VectorDoc("vuln_descriptions:CVE-2024-3400", "PAN-OS 命令注入", {"cve_id": "CVE-2024-3400"}),
                VectorDoc("vuln_descriptions:CVE-2024-4577", "PHP CGI 参数注入", {"cve_id": "CVE-2024-4577"}),
            ]
            assert store.upsert(COLLECTION_VULN_DESCRIPTIONS, docs) == 2
            assert store.count(COLLECTION_VULN_DESCRIPTIONS) == 2
            assert store.upsert(COLLECTION_VULN_DESCRIPTIONS, docs) == 2
            assert store.count(COLLECTION_VULN_DESCRIPTIONS) == 2
        finally:
            store.close()

    def _case_test_query_ranks_similar_first(self) -> None:
        """同主题文档排在前（相似度降序）。"""
        store = _store()
        try:
            store.upsert(
                COLLECTION_VULN_DESCRIPTIONS,
                [
                    VectorDoc(
                        "vuln_descriptions:CVE-2024-3400",
                        "PAN-OS 命令注入漏洞 远程代码执行",
                        {"cve_id": "CVE-2024-3400"},
                    ),
                    VectorDoc(
                        "vuln_descriptions:CVE-2024-4577",
                        "Linux 内核本地权限提升",
                        {"cve_id": "CVE-2024-4577"},
                    ),
                ],
            )
            hits = store.query(COLLECTION_VULN_DESCRIPTIONS, "PAN-OS 命令注入")
            assert hits[0].doc_id.endswith("CVE-2024-3400")
            assert hits[0].score >= hits[-1].score
        finally:
            store.close()

    def _case_test_query_with_metadata_filter(self) -> None:
        """``where`` 元数据过滤生效（只返回匹配文档）。"""
        store = _store()
        try:
            store.upsert(
                COLLECTION_VULN_DESCRIPTIONS,
                [
                    VectorDoc(
                        "vuln_descriptions:CVE-2024-3400",
                        "PAN-OS 命令注入",
                        {"cve_id": "CVE-2024-3400", "severity": "CRITICAL"},
                    ),
                    VectorDoc(
                        "vuln_descriptions:CVE-2024-4577",
                        "PHP 参数注入",
                        {"cve_id": "CVE-2024-4577", "severity": "HIGH"},
                    ),
                ],
            )
            hits = store.query(COLLECTION_VULN_DESCRIPTIONS, "注入", where={"severity": "CRITICAL"})
            assert [hit.doc_id for hit in hits] == ["vuln_descriptions:CVE-2024-3400"]
            assert store.query(COLLECTION_VULN_DESCRIPTIONS, "注入", where={"severity": "LOW"}) == []
        finally:
            store.close()

    def _case_test_query_empty_collection_and_blank_text(self) -> None:
        """空集合 / 空查询直接返回空列表（不抛异常）。"""
        store = _store()
        try:
            assert store.query(COLLECTION_VULN_DESCRIPTIONS, "任意") == []
            store.upsert(COLLECTION_VULN_DESCRIPTIONS, [VectorDoc("vuln_descriptions:CVE-1", "x", {})])
            assert store.query(COLLECTION_VULN_DESCRIPTIONS, "   ") == []
        finally:
            store.close()

    def _case_test_delete_by_ids_and_guard(self) -> None:
        """按主键删除生效；无任何条件时拒绝删除（防止误清空）。"""
        store = _store()
        try:
            store.upsert(
                COLLECTION_VULN_DESCRIPTIONS,
                [
                    VectorDoc("vuln_descriptions:CVE-1", "a", {}),
                    VectorDoc("vuln_descriptions:CVE-2", "b", {}),
                ],
            )
            assert store.delete(COLLECTION_VULN_DESCRIPTIONS, doc_ids=["vuln_descriptions:CVE-2"]) == 1
            assert store.count(COLLECTION_VULN_DESCRIPTIONS) == 1
            with pytest.raises(ValueError, match="必须指定 doc_ids 或 where"):
                store.delete(COLLECTION_VULN_DESCRIPTIONS)
        finally:
            store.close()

    def _case_test_reset_and_stats(self) -> None:
        """``reset`` 清空集合；``stats`` 覆盖全部集合。"""
        store = _store()
        try:
            store.upsert(COLLECTION_VULN_DESCRIPTIONS, [VectorDoc("vuln_descriptions:CVE-1", "a", {})])
            assert store.stats()[COLLECTION_VULN_DESCRIPTIONS] == 1
            store.reset(COLLECTION_VULN_DESCRIPTIONS)
            assert store.count(COLLECTION_VULN_DESCRIPTIONS) == 0
            assert set(store.stats()) == set(COLLECTIONS)
        finally:
            store.close()

    def test_merged_batch2(self) -> None:
        """合并用例批次 2：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_unknown_collection_rejected()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_unknown_collection_rejected: {type(exc).__name__}: {exc}")
        try:
            self._case_test_ensure_collections_idempotent()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_ensure_collections_idempotent: {type(exc).__name__}: {exc}")
        try:
            self._case_test_empty_upsert_is_noop()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_empty_upsert_is_noop: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_unknown_collection_rejected(self) -> None:
        """未声明的集合名报错（防止拼错集合名静默建空集合）。"""
        store = _store()
        try:
            with pytest.raises(ValueError, match="未声明的向量集合"):
                store.collection("qa_memory")
            with pytest.raises(ValueError, match="未声明的向量集合"):
                store.reset("qa_memory")
        finally:
            store.close()

    def _case_test_ensure_collections_idempotent(self) -> None:
        """``ensure_collections`` 一次建齐三个集合（可重复调用）。"""
        store = _store()
        try:
            assert store.ensure_collections() == list(COLLECTIONS)
            assert store.ensure_collections() == list(COLLECTIONS)
        finally:
            store.close()

    def _case_test_empty_upsert_is_noop(self) -> None:
        """空文档列表直接返回 0（不触发嵌入计算）。"""
        store = _store()
        try:
            assert store.upsert(COLLECTION_VULN_DESCRIPTIONS, []) == 0
        finally:
            store.close()


class TestBackends:
    """后端选择与持久化。"""

    def test_ephemeral_backend_metadata(self) -> None:
        """内存后端标识与维度。"""
        store = _store(dim=64)
        try:
            assert store.backend == "chroma_memory"
            assert store.path is None
            assert store.dimension == 64
        finally:
            store.close()

    def test_persistent_reopen_keeps_documents(self, tmp_path: Path) -> None:
        """持久化后端重启后仍可检索（``CHROMA_PATH`` 落盘验证）。"""
        path = str(tmp_path / "chroma")
        settings = Settings(embedding_backend="hashing", embedding_dim=64, chroma_path=path)
        first = VectorStore(settings=settings, embedder=HashingEmbedder(dim=64))
        try:
            assert first.backend == "chroma_persistent"
            first.upsert(
                COLLECTION_REMEDIATION_TEXTS,
                [VectorDoc("remediation_texts:CVE-2024-3400", "升级到 10.2.9-h1", {"cve_id": "CVE-2024-3400"})],
            )
        finally:
            first.close()

        second = VectorStore(settings=settings, embedder=HashingEmbedder(dim=64))
        try:
            assert second.count(COLLECTION_REMEDIATION_TEXTS) == 1
            hits = second.query(COLLECTION_REMEDIATION_TEXTS, "升级")
            assert hits and hits[0].metadata["cve_id"] == "CVE-2024-3400"
        finally:
            second.close()