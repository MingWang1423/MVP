"""Day6 P4 集成测试：增量游标 / 全量模式 / 断点续采（离线，SQLite 内存库）。

覆盖 §5.5 P4 与 §6.2 P4 验收口径：
    ① 增量窗口（``--days`` 与游标优先级）；
    ② ``--mode full`` 从固定起点全量拉；
    ③ 断点续采：重启后以 ``task_run`` 游标为起点，重复内容不丢不重。

本用例不依赖网络 / PostgreSQL / LLM，故**不标记** ``integration``（默认即运行）。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aisec_intel.config import Settings, load_sources_config
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.services.collect_service import (
    FULL_MODE_START,
    collect_source,
    enabled_sources_from_config,
    resolve_since,
    supported_connector_kwargs,
)
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.task_repo import TaskRepository
from aisec_intel.storage.repositories.vuln_repo import VulnRepository
from aisec_intel.utils.hashing import sha256_text

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_YAML = REPO_ROOT / "configs" / "sources.yaml"

CVE_ID = "CVE-2024-3400"

KEV_ENTRY: dict[str, Any] = {
    "cveID": CVE_ID,
    "vulnerabilityName": "PAN-OS Command Injection",
    "shortDescription": "PAN-OS command injection vulnerability.",
    "dateAdded": "2024-04-12",
    "cwes": ["CWE-77"],
}


def make_item(source_id: str, payload: dict[str, Any], *, source: str = "kev") -> RawItem:
    """构造一条内容与指纹自洽的 ``RawItem``。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=None,
        raw_text=text,
        lang="en",
        published_at=datetime(2024, 4, 12, tzinfo=UTC),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


class RecordingConnector:
    """桩采集器：记录收到的 ``since``，并原样返回预置条目。"""

    def __init__(self, source: str, items: list[RawItem]) -> None:
        """绑定源标识与预置条目。

        Args:
            source: 源标识。
            items: 固定返回的采集件列表。
        """
        self.source_name = source
        self._items = items
        self.since_seen: list[datetime] = []

    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """记录起点并返回预置条目。"""
        self.since_seen.append(since)
        return list(self._items)

    async def aclose(self) -> None:
        """空实现（无资源需释放）。"""


def make_settings() -> Settings:
    """构造不读取 ``.env`` 的配置对象。"""
    return Settings(_env_file=None)


class TestResolveSince:
    """增量起点推导（P4 游标优先级）。"""

    async def test_first_run_falls_back_to_default_window(
        self, memory_engine: Any, monkeypatch: Any
    ) -> None:
        """首次运行（无游标）回退 ``now - COLLECT_DEFAULT_DAYS``。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        settings = make_settings()

        since = await resolve_since("kev", settings=settings)

        expected = utc_now() - timedelta(days=settings.collect_default_days)
        assert abs((since - expected).total_seconds()) < 60

    async def test_cursor_advances_after_success(self, memory_engine: Any, monkeypatch: Any) -> None:
        """成功任务推进游标：第二次起点 = 上次成功完成时间。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        settings = make_settings()
        first = await resolve_since("kev", settings=settings)

        async with session_scope(memory_engine) as session:
            repo = TaskRepository(session)
            task_id = await repo.start(source="kev")
            await repo.succeeded(task_id, fetched=3, created=3)

        cursor = await resolve_since("kev", settings=settings)
        assert cursor > first
        async with session_scope(memory_engine) as session:
            snapshot = await TaskRepository(session).get(task_id)
        assert snapshot is not None and snapshot.finished_at is not None
        assert abs((cursor - snapshot.finished_at).total_seconds()) < 1

    async def test_explicit_since_and_days_beat_cursor(self, memory_engine: Any, monkeypatch: Any) -> None:
        """``--since`` / ``--days`` 优先于游标。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        settings = make_settings()
        async with session_scope(memory_engine) as session:
            repo = TaskRepository(session)
            task_id = await repo.start(source="kev")
            await repo.succeeded(task_id)

        explicit = datetime(2024, 1, 1, tzinfo=UTC)
        assert await resolve_since("kev", settings=settings, explicit=explicit) == explicit
        days_since = await resolve_since("kev", settings=settings, days=1)
        assert abs((days_since - (utc_now() - timedelta(days=1))).total_seconds()) < 60

    async def test_full_mode_uses_fixed_start(self, memory_engine: Any, monkeypatch: Any) -> None:
        """``--mode full`` 从固定起点（2024-01-01）全量拉。"""
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        since = await resolve_since("kev", settings=make_settings(), mode="full")
        assert since == FULL_MODE_START == datetime(2024, 1, 1, tzinfo=UTC)


class TestCollectSourceCursor:
    """断点续采：游标推进 + 幂等重放。"""

    async def test_replay_does_not_duplicate(self, memory_engine: Any, monkeypatch: Any) -> None:
        """两轮采集（第二轮用游标作起点）：内容寻址不重、合并结果不翻倍。"""
        items = [make_item(CVE_ID, KEV_ENTRY), make_item(CVE_ID, {**KEV_ENTRY, "shortDescription": "updated"})]
        connector = RecordingConnector("kev", items)
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector", lambda source, **kwargs: connector
        )
        settings = make_settings()

        first_since = datetime(2024, 1, 1, tzinfo=UTC)
        first = await collect_source("kev", since=first_since, settings=settings, normalize=True)

        assert first.status == "succeeded"
        assert (first.created, first.skipped) == (2, 0)
        assert (first.merged_count, first.skipped_count) == (1, 1)
        assert (first.norm_created, first.norm_skipped) == (1, 0)

        second_since = await resolve_since("kev", settings=settings)
        assert second_since > first_since  # 游标已推进（断点续采）
        second = await collect_source("kev", since=second_since, settings=settings, normalize=True)

        assert (second.created, second.skipped) == (0, 2)
        assert (second.merged_count, second.skipped_count) == (1, 1)
        assert (second.norm_created, second.norm_skipped) == (0, 1)
        assert connector.since_seen == [first_since, second_since]

        async with session_scope(memory_engine) as session:
            assert [vuln.vuln_id for vuln in await VulnRepository(session).list_recent(limit=10)] == [CVE_ID]

    async def test_task_run_records_merge_stats(self, memory_engine: Any, monkeypatch: Any) -> None:
        """``task_run.meta`` 留下增量与合并统计，供运维页与验收取证。"""
        connector = RecordingConnector("kev", [make_item(CVE_ID, KEV_ENTRY)])
        monkeypatch.setattr("aisec_intel.services.collect_service.get_engine", lambda settings: memory_engine)
        monkeypatch.setattr(
            "aisec_intel.services.collect_service.create_connector", lambda source, **kwargs: connector
        )
        settings = make_settings()

        await collect_source("kev", since=FULL_MODE_START, settings=settings, normalize=True, mode="full")

        async with session_scope(memory_engine) as session:
            tasks = await TaskRepository(session).list_recent(source="kev")
        assert len(tasks) == 1
        assert tasks[0].meta["mode"] == "full"
        assert tasks[0].meta["merged_count"] == 1
        assert tasks[0].meta["normalize"] is True


class TestSourcesConfigIntegration:
    """``sources.yaml`` 与调度 / 采集参数的联动（含 P4 新增论文源）。"""

    def test_enabled_sources_include_paper_sources(self) -> None:
        """``arxiv`` / ``openalex`` 已加入声明并处于启用状态（间隔 720 分钟）。"""
        config = load_sources_config(REAL_YAML)
        enabled = enabled_sources_from_config(make_settings(), config=config)
        assert enabled == ["arxiv", "epss", "ghsa", "kev", "nvd", "openalex", "osv"]
        arxiv = config.for_source("arxiv")
        openalex = config.for_source("openalex")
        assert arxiv is not None and arxiv.interval_minutes == 720
        assert openalex is not None and openalex.interval_minutes == 720

    def test_connector_kwargs_are_filtered_by_signature(self) -> None:
        """YAML 参数按采集器签名过滤，别名 ``watchlist`` → ``packages``。"""
        config = load_sources_config(REAL_YAML)
        settings = make_settings()

        arxiv_params = config.for_source("arxiv").params
        assert supported_connector_kwargs(settings, "arxiv", config=config) == {
            "query": arxiv_params["query"],
            "max_results": 100,
        }

        nvd = supported_connector_kwargs(settings, "nvd", config=config)
        assert set(nvd) == {"page_size", "max_pages"}  # window_days 不属于构造参数，被忽略

        osv = supported_connector_kwargs(settings, "osv", config=config)
        assert osv == {"packages": config.for_source("osv").params["watchlist"]}

