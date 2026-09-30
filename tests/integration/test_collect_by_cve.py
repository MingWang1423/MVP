"""Day7 前置集成测试：``--cve`` 单条采集（离线，SQLite 内存库）。

覆盖 §8.1 最小演示路径的第 ①：「采集一条 CVE」::

    python -m scripts.run_collect --source nvd,epss,kev --cve CVE-2024-3400

验证点：
    1. 每个源单独登记 ``task_run``（可逐源排查），且异常隔离（单源失败不影响其它源）；
    2. NVD / EPSS / KEV 三源同 CVE → 归一化 → **合并成 1 条** ``unified_vuln`` 实体；
    3. ``--dry-run`` / ``--no-normalize`` 行为与开关一致；
    4. 不支持单条拉取的源被跳过并给出提示。

本用例不需要网络 / PostgreSQL / LLM，故**不标记** ``integration``（默认即运行）。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.services.collect_service import collect_cves
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.raw_repo import RawRepository
from aisec_intel.storage.repositories.task_repo import TaskRepository
from aisec_intel.storage.repositories.vuln_repo import VulnRepository
from aisec_intel.utils.hashing import sha256_text
from scripts.run_collect import parse_args, run

CVE_ID = "CVE-2024-3400"
GHSA_ID = "GHSA-jfh8-c2jp-5v3q"

NVD_PAYLOAD: dict[str, Any] = {
    "cve": {
        "id": CVE_ID,
        "published": "2024-04-12T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "PAN-OS command injection (NVD view)."}],
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
    "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
    "shortDescription": "PAN-OS command injection (KEV view).",
    "dateAdded": "2024-04-12",
    "cwes": ["CWE-77"],
}

EPSS_ROW: dict[str, Any] = {
    "cve": CVE_ID,
    "epss": "0.99999",
    "percentile": "0.99998",
    "date": "2026-09-29",
}


def make_item(source: str, source_id: str, payload: dict[str, Any]) -> RawItem:
    """构造一条内容与指纹自洽的 ``RawItem``。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=payload.get("vulnerabilityName"),
        raw_text=text,
        lang="en",
        published_at=datetime(2024, 4, 12, tzinfo=UTC),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


class StubConnector:
    """桩采集器：支持 ``fetch_cves`` 与 ``fetch_incremental``（不访问网络）。"""

    def __init__(self, source: str, items: list[RawItem], *, fail: bool = False) -> None:
        """绑定源标识与预置条目。

        Args:
            source: 源标识。
            items: 固定返回的采集件列表。
            fail: ``True`` 时模拟源侧异常（用于验证异常隔离）。
        """
        self.source_name = source
        self._items = items
        self._fail = fail

    async def fetch_cves(self, cve_ids: list[str]) -> list[RawItem]:
        """返回预置条目（按请求编号过滤）。"""
        if self._fail:
            raise RuntimeError(f"{self.source_name} 源不可用")
        wanted = {cve_id.upper() for cve_id in cve_ids}
        return [item for item in self._items if item.source_id.upper() in wanted]

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """返回预置条目（EPSS 走此通道）。"""
        if self._fail:
            raise RuntimeError(f"{self.source_name} 源不可用")
        return list(self._items)

    async def aclose(self) -> None:
        """空实现（无资源需释放）。"""


def stub_factory(overrides: dict[str, Any]) -> Any:
    """构造 ``create_connector`` 的替身：按源返回桩采集器。

    Args:
        overrides: ``{源标识: StubConnector | list[RawItem]}``，未覆盖的源用默认三源条目。

    Returns:
        可直接替换 ``collect_service.create_connector`` 的可调用对象。
    """
    default_items = [
        make_item("nvd", CVE_ID, NVD_PAYLOAD),
        make_item("kev", CVE_ID, KEV_ENTRY),
        make_item("epss", CVE_ID, EPSS_ROW),
    ]

    def _create(source: str, **kwargs: Any) -> StubConnector:
        spec = overrides.get(source)
        if isinstance(spec, StubConnector):
            return spec
        return StubConnector(source, list(spec if spec is not None else default_items))

    return _create


@pytest.fixture()
def settings() -> Settings:
    """提供不读取 ``.env`` 的配置对象。"""
    return Settings(_env_file=None)


class TestCollectCvesService:
    """``collect_cves`` 服务层行为。"""

    async def test_three_sources_merge_into_one(
        self, memory_engine: Any, monkeypatch: Any, settings: Settings
    ) -> None:
        """三源同 CVE → 1 条实体；raw_item 3 条；task_run 3 条（每源一条）。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr("aisec_intel.services.collect_service.create_connector", stub_factory({}))

        result = await collect_cves(["CVE-2024-3400"], settings=settings, sources=["nvd", "kev", "epss"])

        assert [stats.source for stats in result.stats] == ["nvd", "kev", "epss"]  # 保持调用方顺序
        assert result.failed == 0
        assert result.created == 3
        assert result.merge is not None
        assert (result.merge.input_count, result.merge.merged_count) == (3, 1)
        assert result.merged_count == 1

        async with session_scope(memory_engine) as session:
            assert await RawRepository(session).count_by_source("nvd") == 1
            assert len(await TaskRepository(session).list_recent(limit=10)) == 3
            stored = await VulnRepository(session).get_by_cve(CVE_ID)
        assert stored is not None
        assert stored.sources == ["epss", "kev", "nvd"]
        assert stored.severity == "CRITICAL"
        assert stored.kev is True
        assert stored.epss_score == 0.99999
        assert stored.affected_versions == ["paloaltonetworks:pan-os ==10.2.0"]

    async def test_single_source_failure_is_isolated(
        self, memory_engine: Any, monkeypatch: Any, settings: Settings
    ) -> None:
        """单源异常不影响其它源；失败记录在 task_run 中。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            stub_factory({"kev": StubConnector("kev", [], fail=True)}),
        )

        result = await collect_cves(["CVE-2024-3400"], settings=settings, sources=["nvd", "kev", "epss"])

        by_source = {stats.source: stats for stats in result.stats}
        assert by_source["kev"].status == "failed"
        assert "源不可用" in (by_source["kev"].error or "")
        assert by_source["nvd"].status == "succeeded"
        assert result.failed == 1
        assert result.merge is not None and result.merge.merged_count == 1

        async with session_scope(memory_engine) as session:
            failed = await TaskRepository(session).list_recent(status="failed")
        assert [task.source for task in failed] == ["kev"]

    async def test_dry_run_writes_nothing(self, memory_engine: Any, monkeypatch: Any, settings: Settings) -> None:
        """``dry_run`` 只拉取：不写 raw_item / unified_vuln，也不合并。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr("aisec_intel.services.collect_service.create_connector", stub_factory({}))

        result = await collect_cves(["CVE-2024-3400"], settings=settings, sources=["nvd", "kev"], dry_run=True)

        assert result.merge is None
        assert result.created == 0
        assert [stats.status for stats in result.stats] == ["succeeded", "succeeded"]
        async with session_scope(memory_engine) as session:
            assert await RawRepository(session).count_by_source("nvd") == 0
            assert await VulnRepository(session).list_recent(limit=10) == []

    async def test_empty_cve_list_raises(self, memory_engine: Any, monkeypatch: Any, settings: Settings) -> None:
        """空编号列表显式报错。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        with pytest.raises(ValueError, match="至少一个 CVE"):
            await collect_cves([" ", ""], settings=settings)


class TestRunCollectByCve:
    """CLI ``--cve`` 分支端到端。"""

    async def test_cli_defaults_to_three_sources(
        self, memory_engine: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        """不带 ``--source`` 时默认使用 nvd/epss/kev，并输出合并汇总。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr("aisec_intel.services.collect_service.create_connector", stub_factory({}))

        code = await run(parse_args(["--cve", CVE_ID]))

        assert code == 0
        printed = capsys.readouterr().out
        assert "[单条采集] cve=['CVE-2024-3400'] | sources=['epss', 'kev', 'nvd']" in printed
        assert "归一化 3 条 → 合并 1 条实体" in printed
        assert "unified_vuln 就绪：1 条实体" in printed

        async with session_scope(memory_engine) as session:
            assert len(await VulnRepository(session).list_recent(limit=10)) == 1

    async def test_cli_no_normalize_keeps_raw_only(
        self, memory_engine: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        """``--no-normalize`` 只落 raw_item（不产生漏洞实体）。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr("aisec_intel.services.collect_service.create_connector", stub_factory({}))

        code = await run(parse_args(["--cve", CVE_ID, "--source", "nvd", "--no-normalize"]))

        assert code == 0
        printed = capsys.readouterr().out
        assert "normalize=False" in printed
        assert "[跨源合并]" not in printed
        async with session_scope(memory_engine) as session:
            assert await RawRepository(session).count_by_source("nvd") == 1
            assert await VulnRepository(session).list_recent(limit=10) == []

    async def test_cli_skips_unsupported_source(self, memory_engine: Any, monkeypatch: Any, capsys: Any) -> None:
        """``--source arxiv`` 不支持单条拉取：提示后无可用源时返回 2。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr("aisec_intel.services.collect_service.create_connector", stub_factory({}))

        code = await run(parse_args(["--cve", CVE_ID, "--source", "arxiv"]))

        assert code == 2
        assert "不支持按 CVE 单条拉取" in capsys.readouterr().out

    async def test_cli_reports_failed_source(self, memory_engine: Any, monkeypatch: Any, capsys: Any) -> None:
        """存在失败源时返回 1，并提示逐源排查。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector",
            stub_factory({"kev": StubConnector("kev", [], fail=True)}),
        )

        code = await run(parse_args(["--cve", CVE_ID, "--source", "nvd,kev"]))

        assert code == 1
        printed = capsys.readouterr().out
        assert "[FAIL kev]" in printed
        assert "逐源排查" in printed

    async def test_cli_accepts_multiple_cves(self, memory_engine: Any, monkeypatch: Any, capsys: Any) -> None:
        """``--cve a,b`` 支持多编号（含空白与大小写）。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda _: memory_engine)
        monkeypatch.setattr("aisec_intel.services.collect_service.create_connector", stub_factory({}))

        code = await run(parse_args(["--cve", f"{CVE_ID}, cve-2024-3094 "]))

        assert code == 0
        assert "cve=['CVE-2024-3400', 'CVE-2024-3094']" in capsys.readouterr().out

    async def test_parse_args_defaults(self) -> None:
        """``--cve`` 存在时 ``--normalize`` 默认为 ``None``（由运行分支决定为 True）。"""
        args = parse_args(["--cve", CVE_ID])
        assert args.cve == CVE_ID
        assert args.normalize is None
        assert parse_args(["--normalize"]).normalize is True
        assert parse_args(["--no-normalize"]).normalize is False


