"""Day6 P4 集成测试：多源同 CVE 合并（离线，SQLite 内存库）。

覆盖 §5.5 P4 任务 1：``--normalize`` 先收集全部 ``UnifiedVuln`` → ``merge_unified_vulns``
**合并后**再 upsert 到 ``unified_vuln``，避免「同 CVE 多源重复覆盖」。

说明：本用例只依赖 SQLite 内存库与桩采集器（无网络 / 无 PostgreSQL / 无 LLM），
因此**不标记** ``integration`` 标记 —— 默认 ``python -m pytest`` 即会执行。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from aisec_intel.config import Settings
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.pipeline import build_unified_vuln
from aisec_intel.services.collect_service import merge_and_upsert
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.raw_repo import RawRepository
from aisec_intel.storage.repositories.vuln_repo import VulnRepository
from aisec_intel.utils.hashing import sha256_text
from scripts.run_collect import parse_args, run

CVE_ID = "CVE-2024-3400"
GHSA_ID = "GHSA-jfh8-c2jp-5v3q"

NVD_PAYLOAD: dict[str, Any] = {
    "cve": {
        "id": CVE_ID,
        "published": "2024-04-12T00:00:00.000Z",
        "lastModified": "2024-04-20T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "PAN-OS command injection in GlobalProtect (NVD)."}],
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
        "references": [{"url": "https://example.org/nvd-advisory"}],
    }
}

OSV_PAYLOAD: dict[str, Any] = {
    "id": GHSA_ID,
    "aliases": [CVE_ID],
    "published": "2024-04-15T00:00:00Z",
    "details": "OSV record: the GlobalProtect feature of PAN-OS contains an OS command injection.",
    "references": [{"type": "ADVISORY", "url": "https://example.org/osv-advisory"}],
}

KEV_ENTRY: dict[str, Any] = {
    "cveID": CVE_ID,
    "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
    "shortDescription": "PAN-OS command injection; added to KEV after observed exploitation.",
    "dateAdded": "2024-04-12",
    "cwes": ["CWE-77"],
}


def make_item(source: str, source_id: str, payload: dict[str, Any], *, url: str) -> RawItem:
    """构造一条内容与指纹自洽的 ``RawItem``。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=url,
        title=payload.get("vulnerabilityName"),
        raw_text=text,
        lang="en",
        published_at=datetime(2024, 4, 12, tzinfo=UTC),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


def three_source_items() -> list[RawItem]:
    """三条来自不同源、指向同一 CVE 的采集件。"""
    return [
        make_item("nvd", CVE_ID, NVD_PAYLOAD, url=f"https://nvd.nist.gov/vuln/detail/{CVE_ID}"),
        make_item("osv", GHSA_ID, OSV_PAYLOAD, url=f"https://github.com/advisories/{GHSA_ID}"),
        make_item("kev", CVE_ID, KEV_ENTRY, url=f"https://nvd.nist.gov/vuln/detail/{CVE_ID}"),
    ]


class StubConnector:
    """桩采集器：直接返回预置条目（不访问网络）。"""

    def __init__(self, source: str, items: list[RawItem]) -> None:
        """绑定源标识与预置条目。

        Args:
            source: 源标识。
            items: 固定返回的采集件列表。
        """
        self.source_name = source
        self._items = items
        self.closed = False

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """忽略 ``since``，原样返回预置条目。"""
        return list(self._items)

    async def aclose(self) -> None:
        """记录关闭动作。"""
        self.closed = True


class TestMergeService:
    """``merge_and_upsert`` 的合并语义。"""

    async def test_three_sources_merge_into_one(self, memory_engine: Any) -> None:
        """3 源同 CVE → 1 条合并实体：sources / aliases / cvss / cwe / references 并集。"""
        items = three_source_items()
        vulns = [build_unified_vuln(item) for item in items]
        settings = Settings(_env_file=None)

        outcome = await merge_and_upsert(vulns, settings=settings, engine=memory_engine)

        assert (outcome.input_count, outcome.merged_count, outcome.folded_count) == (3, 1, 2)
        assert (outcome.created, outcome.updated) == (1, 0)

        async with session_scope(memory_engine) as session:
            stored = await VulnRepository(session).get_by_cve(CVE_ID)
            assert stored is not None
            assert stored.vuln_id == CVE_ID
            assert stored.sources == ["kev", "nvd", "osv"]
            assert sorted(stored.trace_ids) == sorted(item.trace_id for item in items)
            assert GHSA_ID in stored.aliases
            assert stored.kev is True
            assert [vector.base_score for vector in stored.cvss] == [10.0]
            assert stored.cwe_ids == ["CWE-77"]
            assert len(stored.references) >= 2
            assert stored.description == max(
                (vuln.description for vuln in vulns if vuln.description), key=len
            )

    async def test_replay_is_idempotent(self, memory_engine: Any) -> None:
        """重复合并写库不新增行（幂等），第二次为「更新」。"""
        items = three_source_items()
        vulns = [build_unified_vuln(item) for item in items]
        settings = Settings(_env_file=None)

        first = await merge_and_upsert(vulns, settings=settings, engine=memory_engine)
        second = await merge_and_upsert(vulns, settings=settings, engine=memory_engine)

        assert (first.created, first.updated) == (1, 0)
        assert (second.created, second.updated) == (0, 1)
        async with session_scope(memory_engine) as session:
            rows = await VulnRepository(session).list_recent(limit=10)
        assert [row.vuln_id for row in rows] == [CVE_ID]


class TestRunCollectEndToEnd:
    """``scripts.run_collect --normalize`` 全链路（桩采集器 + 内存库）。"""

    async def test_multi_source_run_merges_before_upsert(
        self, memory_engine: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        """多源运行时先合并再 upsert，最终库里只有 1 条实体。"""
        items = three_source_items()
        by_source = {item.source: [item] for item in items}
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            lambda source, **kwargs: StubConnector(source, by_source[source]),
        )

        code = await run(parse_args(["--source", "nvd,osv,kev", "--normalize", "--since", "2024-01-01"]))

        assert code == 0
        printed = capsys.readouterr().out
        assert "[跨源合并] 归一化 3 条 → 合并 1 条实体（折叠 2" in printed

        async with session_scope(memory_engine) as session:
            raw_rows = await RawRepository(session).list_by_source("nvd", limit=10)
            vulns = await VulnRepository(session).list_recent(limit=10)
        assert len(raw_rows) == 1
        assert [vuln.vuln_id for vuln in vulns] == [CVE_ID]
        assert vulns[0].sources == ["kev", "nvd", "osv"]

    async def test_single_source_run_does_not_touch_cross_merge(
        self, memory_engine: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        """单源运行时只做源内合并（不打印跨源合并行）。"""
        items = three_source_items()
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            lambda source, **kwargs: StubConnector(source, items),
        )

        code = await run(parse_args(["--source", "nvd", "--normalize", "--since", "2024-01-01"]))

        assert code == 0
        printed = capsys.readouterr().out
        assert "[跨源合并]" not in printed
        assert "合并=1" in printed
        assert "折叠=2" in printed

    async def test_dry_run_writes_nothing(self, memory_engine: Any, monkeypatch: Any) -> None:
        """``--dry-run`` 只采集不落库（但登记 task_run）。"""
        items = three_source_items()
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            lambda source, **kwargs: StubConnector(source, items),
        )

        code = await run(parse_args(["--source", "kev", "--normalize", "--dry-run", "--since", "2024-01-01"]))

        assert code == 0
        async with session_scope(memory_engine) as session:
            assert await VulnRepository(session).list_recent(limit=10) == []
            assert await RawRepository(session).count_by_source("kev") == 0

