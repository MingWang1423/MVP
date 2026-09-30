"""Day7 行为变更回归：``upsert`` 多源「逐源重跑」不再互相覆盖。

**缺陷复现（变更前）**：先跑 NVD 写入 ``cvss=10.0``，再跑 KEV（无 CVSS）→ 库里 ``cvss`` 变
``None``；再跑 EPSS → ``kev``/``cvss`` 全丢。

**修复后**：``VulnRepository.upsert`` 命中既有行时按字段类型合并（
:func:`aisec_intel.normalize.dedupe.merge_for_update`），断言最终实体**包含三源全部数据**。

覆盖两条路径（均为离线 + SQLite 内存库）：
    1. 仓储级：把三源归一化结果**分三次** ``upsert``；
    2. 服务级：真实「逐源分开跑采集」``collect_source``（桩采集器）→ 检查最终实体。

本用例不依赖网络 / PostgreSQL / LLM，故**不标记** ``integration``（默认即运行）。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.services.collect_service import collect_source, normalize_batch
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.vuln_repo import VulnRepository
from aisec_intel.utils.hashing import sha256_text

CVE_ID = "CVE-2024-3400"
"""NVD/KEV/EPSS 三源都会覆盖的示教 CVE。"""

NVD_PAYLOAD: dict[str, Any] = {
    "cve": {
        "id": CVE_ID,
        "published": "2024-04-12T00:00:00.000Z",
        "lastModified": "2024-04-20T00:00:00.000Z",
        "descriptions": [
            {"lang": "en", "value": "PAN-OS GlobalProtect command injection (full NVD description text)."}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-77"}]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionEndExcluding": "10.2.9-h1",
                            }
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.org/nvd-advisory"}],
    }
}

KEV_ENTRY: dict[str, Any] = {
    "cveID": CVE_ID,
    "vulnerabilityName": "PAN-OS Command Injection",
    "shortDescription": "KEV view: exploited in the wild.",
    "dateAdded": "2024-04-12",
    "cwes": ["CWE-20"],
}

EPSS_ROW: dict[str, Any] = {
    "cve": CVE_ID,
    "epss": "0.99999",
    "percentile": "0.99998",
    "date": "2026-09-29",
}


def make_item(source: str, source_id: str, payload: dict[str, Any], *, day: int) -> RawItem:
    """构造一条内容与指纹自洽的 ``RawItem``（``day`` 控制发布时间以验证「取最早」）。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=payload.get("vulnerabilityName"),
        raw_text=text,
        lang="en",
        published_at=datetime(2024, 4, day, tzinfo=UTC),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


def source_views() -> dict[str, RawItem]:
    """三源采集件（NVD 12 日、KEV 15 日、EPSS 20 日 → 可验证「发布取最早」）。"""
    return {
        "nvd": make_item("nvd", CVE_ID, NVD_PAYLOAD, day=12),
        "kev": make_item("kev", CVE_ID, KEV_ENTRY, day=15),
        "epss": make_item("epss", CVE_ID, EPSS_ROW, day=20),
    }


def per_source_vuln(source: str) -> Any:
    """按 ``run_collect`` 的方式做「源内归一化」（单源一条 → 该源视图）。"""
    outcome = normalize_batch([source_views()[source]], source=source)
    assert outcome.merged_count == 1
    return outcome.merged[0]


class RecordingConnector:
    """桩采集器：每次只返回单个源的采集件。"""

    def __init__(self, source: str, item: RawItem) -> None:
        """绑定源标识与单条采集件。

        Args:
            source: 源标识。
            item: 该源的采集件。
        """
        self.source_name = source
        self._item = item

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """返回该源的唯一采集件。"""
        return [self._item]

    async def aclose(self) -> None:
        """空实现（无资源需释放）。"""


@pytest.fixture()
def settings() -> Settings:
    """提供不读取 ``.env`` 的配置对象。"""
    return Settings(_env_file=None)


class TestUpsertMergeAtRepositoryLevel:
    """仓储级：三源分三次 ``upsert`` → 最终实体含全部来源数据。"""

    @pytest.mark.parametrize("order", [("nvd", "kev", "epss"), ("epss", "kev", "nvd")])
    async def test_three_separate_writes_preserve_everything(
        self, memory_engine: Any, order: tuple[str, str, str]
    ) -> None:
        """按任意顺序逐源写入：标量不被空值覆盖、集合取并集、极值正确。"""
        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            for source in order:
                await repo.upsert(per_source_vuln(source))
            stored = await repo.get_by_cve(CVE_ID)
            rows = await repo.list_recent(limit=10)

        assert stored is not None
        assert len(rows) == 1  # 始终只有一行
        # NVD 的 CVSS / 严重度 / CPE 未被 KEV、EPSS 的「无值」覆盖（原缺陷点）
        assert [vector.base_score for vector in stored.cvss] == [10.0]
        assert stored.severity == "CRITICAL"
        assert stored.cpe_matches and stored.cpe_matches[0].product == "pan-os"
        assert stored.affected_versions == ["paloaltonetworks:pan-os ==10.2.0"]
        # KEV / EPSS 的贡献同样在库里
        assert stored.kev is True
        assert stored.epss_score == pytest.approx(0.99999)
        assert sorted(stored.sources) == ["epss", "kev", "nvd"]
        assert len(stored.trace_ids) == 3  # 三条链路均保留（§10.2 不变式 5）
        # 集合语义稳定（元素顺序跟随贡献记录的 published_at 升序，见下方 order-independence 用例）
        assert set(stored.cwe_ids) == {"CWE-77", "CWE-20"}  # KEV 的 CWE 并入
        assert stored.published_at == datetime(2024, 4, 12, tzinfo=UTC)  # 取最早
        assert stored.description.startswith("PAN-OS GlobalProtect")  # 取最长

    async def test_semantic_fields_are_order_independent(self, memory_engine: Any) -> None:
        """重跑顺序不影响**语义字段**（集合类字段的元素顺序可能不同，但集合语义一致）。"""
        from aisec_intel.models.unified_vuln import UnifiedVuln
        from aisec_intel.storage.database import create_engine, init_models

        async def write(order: tuple[str, ...]) -> UnifiedVuln:
            engine = create_engine("sqlite+aiosqlite:///:memory:")
            await init_models(engine)
            try:
                async with session_scope(engine) as session:
                    repo = VulnRepository(session)
                    for source in order:
                        await repo.upsert(per_source_vuln(source))
                    stored = await repo.get_by_cve(CVE_ID)
                assert stored is not None
                return stored
            finally:
                await engine.dispose()

        forward = await write(("nvd", "kev", "epss"))
        reverse = await write(("epss", "kev", "nvd"))
        assert memory_engine is not None  # 仅用于复用「SQLAlchemy 可用才运行」的 skip 语义

        assert [vector.base_score for vector in forward.cvss] == [vector.base_score for vector in reverse.cvss]
        assert forward.severity == reverse.severity == "CRITICAL"
        assert forward.kev is True and reverse.kev is True
        assert forward.epss_score == reverse.epss_score == pytest.approx(0.99999)
        assert forward.published_at == reverse.published_at
        assert forward.modified_at == reverse.modified_at
        assert forward.sources == reverse.sources == ["epss", "kev", "nvd"]
        assert set(forward.cwe_ids) == set(reverse.cwe_ids)
        assert {match.product for match in forward.cpe_matches} == {match.product for match in reverse.cpe_matches}
        assert forward.affected_versions == reverse.affected_versions
        assert len(forward.trace_ids) == len(reverse.trace_ids)

    async def test_repeated_rewrite_is_stable(self, memory_engine: Any) -> None:
        """同一源重复重跑不再改变已有数据（幂等），也不产生第二行。"""
        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            for _ in range(3):
                await repo.upsert(per_source_vuln("nvd"))
            first = await repo.get_by_cve(CVE_ID)

        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            await repo.upsert(per_source_vuln("kev"))
            after = await repo.get_by_cve(CVE_ID)
            rows = await repo.list_recent(limit=10)

        assert first is not None and after is not None
        assert [vector.base_score for vector in after.cvss] == [10.0]  # NVD 数据仍在
        assert after.kev is True  # KEV 贡献并入
        assert len(rows) == 1


class TestUpsertMergeThroughCollector:
    """服务级：真实「逐源分开跑采集」路径（``collect_source`` + 桩采集器）。"""

    async def test_three_separate_collect_runs_keep_all_sources(
        self, memory_engine: Any, monkeypatch: Any, settings: Settings
    ) -> None:
        """三次独立采集（NVD → KEV → EPSS）后，实体仍是三源并集。"""
        views = source_views()
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            lambda source, **kwargs: RecordingConnector(source, views[source]),
        )
        since = datetime(2024, 1, 1, tzinfo=UTC)

        stats_list = [
            await collect_source(source, since=since, settings=settings, normalize=True, mode="full")
            for source in ("nvd", "kev", "epss")
        ]

        assert all(stats.status == "succeeded" for stats in stats_list)
        assert [(stats.created, stats.norm_created) for stats in stats_list] == [(1, 1), (1, 0), (1, 0)]

        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            stored = await repo.get_by_cve(CVE_ID)
            rows = await repo.list_recent(limit=10)

        assert stored is not None and len(rows) == 1
        assert sorted(stored.sources) == ["epss", "kev", "nvd"]
        assert [vector.base_score for vector in stored.cvss] == [10.0]
        assert stored.severity == "CRITICAL"
        assert stored.kev is True
        assert stored.epss_score == pytest.approx(0.99999)
        assert stored.affected_versions == ["paloaltonetworks:pan-os ==10.2.0"]

    async def test_later_source_without_scalars_does_not_erase(
        self, memory_engine: Any, monkeypatch: Any, settings: Settings
    ) -> None:
        """后跑源为空值时不清空先跑源（缺陷的直接回归断言）。"""
        views = source_views()
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            lambda source, **kwargs: RecordingConnector(source, views[source]),
        )
        since = datetime(2024, 1, 1, tzinfo=UTC)

        await collect_source("nvd", since=since, settings=settings, normalize=True)
        async with session_scope(memory_engine) as session:
            before = await VulnRepository(session).get_by_cve(CVE_ID)
        await collect_source("kev", since=since, settings=settings, normalize=True)
        async with session_scope(memory_engine) as session:
            after = await VulnRepository(session).get_by_cve(CVE_ID)

        assert before is not None and after is not None
        assert before.cvss  # NVD 视图确实带 CVSS
        assert "metrics" not in (views["kev"].payload or {})  # KEV 载荷确实没有 CVSS
        assert after.cvss == before.cvss  # 未被清空
        assert after.severity == "CRITICAL"
        assert after.cpe_matches == before.cpe_matches
        assert after.kev is True and before.kev is False  # 新增贡献正常并入

