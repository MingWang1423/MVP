"""Day3 ``task_repo`` 测试（SQLite 内存库，不依赖 PostgreSQL）。

覆盖状态流转（started/succeeded/failed）、统计留痕与增量游标 ``last_run_at``。
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from aisec_intel.models.base import utc_now
from aisec_intel.storage.repositories.task_repo import TaskRepository


class TestTaskLifecycle:
    """任务生命周期与统计。"""

    async def test_start_creates_running_task(self, db_session: Any) -> None:
        """``start`` 返回自增 ID，初始状态为 ``running``。"""
        repo = TaskRepository(db_session)
        task_id = await repo.start(source="kev", meta={"since": "2024-01-01"})
        assert task_id > 0

        snapshot = await repo.get(task_id)
        assert snapshot is not None
        assert snapshot.status == "running"
        assert snapshot.task_name == "collect:kev"
        assert snapshot.finished_at is None
        assert snapshot.duration_s is None
        assert snapshot.meta == {"since": "2024-01-01"}

    async def test_succeeded_records_stats_and_duration(self, db_session: Any) -> None:
        """``succeeded`` 写入统计与结束时间，并算出耗时。"""
        repo = TaskRepository(db_session)
        task_id = await repo.start(source="kev")
        await repo.succeeded(task_id, fetched=45, created=40, skipped=5, meta={"limit": 50})

        snapshot = await repo.get(task_id)
        assert snapshot is not None
        assert snapshot.status == "succeeded"
        assert (snapshot.fetched, snapshot.created, snapshot.skipped) == (45, 40, 5)
        assert snapshot.finished_at is not None
        assert snapshot.duration_s is not None and snapshot.duration_s >= 0
        assert snapshot.meta["limit"] == 50

    async def test_failed_records_error(self, db_session: Any) -> None:
        """``failed`` 记录失败原因并结束任务。"""
        repo = TaskRepository(db_session)
        task_id = await repo.start(source="kev")
        await repo.failed(task_id, "ConnectError: 连接被拒绝")

        snapshot = await repo.get(task_id)
        assert snapshot is not None
        assert snapshot.status == "failed"
        assert "连接被拒绝" in (snapshot.error or "")
        assert snapshot.finished_at is not None

    async def test_failed_truncates_long_error(self, db_session: Any) -> None:
        """超长错误信息被截断，避免撑爆列宽。"""
        repo = TaskRepository(db_session)
        task_id = await repo.start(source="kev")
        await repo.failed(task_id, "x" * 5000)
        snapshot = await repo.get(task_id)
        assert snapshot is not None
        assert len(snapshot.error or "") == 2000

    async def test_unknown_task_id_raises(self, db_session: Any) -> None:
        """操作不存在的任务时抛出 ``LookupError``。"""
        repo = TaskRepository(db_session)
        with pytest.raises(LookupError, match="不存在"):
            await repo.succeeded(9999)
        with pytest.raises(LookupError, match="不存在"):
            await repo.failed(9999, "boom")


class TestIncrementalCursor:
    """增量游标 ``last_run_at``。"""

    async def test_returns_none_when_never_succeeded(self, db_session: Any) -> None:
        """从未成功过时返回 ``None``（调用方回退默认窗口）。"""
        repo = TaskRepository(db_session)
        await repo.start(source="kev")
        assert await repo.last_run_at("kev") is None

    async def test_only_successful_runs_are_used(self, db_session: Any) -> None:
        """失败任务不推进游标。"""
        repo = TaskRepository(db_session)
        failed_id = await repo.start(source="kev")
        await repo.failed(failed_id, "boom")
        assert await repo.last_run_at("kev") is None

        ok_id = await repo.start(source="kev")
        await repo.succeeded(ok_id, fetched=1, created=1)
        cursor = await repo.last_run_at("kev")
        assert cursor is not None
        assert cursor.tzinfo is not None  # 统一 UTC

    async def test_cursor_isolated_per_source(self, db_session: Any) -> None:
        """不同源的游标互不影响。"""
        repo = TaskRepository(db_session)
        kev_id = await repo.start(source="kev")
        await repo.succeeded(kev_id)
        assert await repo.last_run_at("osv") is None


class TestListing:
    """任务列表与过滤。"""

    async def test_list_recent_orders_and_filters(self, db_session: Any) -> None:
        """按开始时间倒序，支持按源与状态过滤。"""
        repo = TaskRepository(db_session)
        first = await repo.start(source="kev")
        await repo.succeeded(first)
        second = await repo.start(source="osv")
        await repo.failed(second, "boom")

        all_tasks = await repo.list_recent()
        assert len(all_tasks) == 2
        assert all_tasks[0].id == second  # 最近开始的排在最前

        kev_only = await repo.list_recent(source="kev")
        assert [task.source for task in kev_only] == ["kev"]

        failed_only = await repo.list_recent(status="failed")
        assert [task.status for task in failed_only] == ["failed"]

    async def test_list_recent_respects_limit(self, db_session: Any) -> None:
        """``limit`` 生效。"""
        repo = TaskRepository(db_session)
        for _ in range(3):
            task_id = await repo.start(source="kev")
            await repo.succeeded(task_id)
        assert len(await repo.list_recent(limit=2)) == 2

    async def test_started_at_is_recent_utc(self, db_session: Any) -> None:
        """``started_at`` 为近期的 UTC 时间。"""
        repo = TaskRepository(db_session)
        task_id = await repo.start(source="kev")
        snapshot = await repo.get(task_id)
        assert snapshot is not None
        assert abs((snapshot.started_at - utc_now()).total_seconds()) < timedelta(minutes=5).total_seconds()
