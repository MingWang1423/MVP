"""Day3 ``raw_repo`` 测试（SQLite 内存库，不依赖 PostgreSQL）。

覆盖内容寻址幂等、指纹查询、按源列表（排序 / 过滤）与计数。
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from aisec_intel.models.base import utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.storage.repositories.raw_repo import RawRepository


def make_item(
    *,
    sha256: str,
    source: str = "kev",
    source_id: str = "CVE-2024-3400",
    published_at: datetime | None = None,
    raw_text: str = "{}",
) -> RawItem:
    """构造用于入库的 ``RawItem``。"""
    return RawItem(
        trace_id=f"trace-{sha256[:8]}",
        source=source,
        source_id=source_id,
        url=f"https://example.test/{source_id}",
        title=f"title-{source_id}",
        raw_text=raw_text,
        lang="en",
        published_at=published_at,
        fetched_at=utc_now(),
        sha256=sha256,
        meta={"k": "v"},
    )


class TestRawRepository:
    """``raw_item`` 仓储行为。"""

    async def test_upsert_creates_then_skips_duplicate(self, db_session: Any) -> None:
        """首次写入为新增，第二次同指纹被跳过（内容寻址幂等）。"""
        repo = RawRepository(db_session)
        item = make_item(sha256="a" * 64)

        first = await repo.upsert(item)
        assert first.created is True
        assert first.item.source_id == "CVE-2024-3400"

        second = await repo.upsert(item)
        assert second.created is False
        assert await repo.count_by_source("kev") == 1

    async def test_get_by_hash(self, db_session: Any) -> None:
        """按指纹读回，未命中返回 ``None``。"""
        repo = RawRepository(db_session)
        digest = "b" * 64
        await repo.upsert(make_item(sha256=digest, raw_text='{"x":1}'))

        loaded = await repo.get_by_hash(digest.upper())
        assert loaded is not None
        assert loaded.sha256 == digest
        assert loaded.raw_text == '{"x":1}'
        assert loaded.meta == {"k": "v"}

        assert await repo.get_by_hash("c" * 64) is None

    async def test_invalid_hash_rejected(self, db_session: Any) -> None:
        """非法指纹（非 64 位十六进制）直接报错，避免全表扫描。"""
        repo = RawRepository(db_session)
        with pytest.raises(ValueError, match="非法 sha256"):
            await repo.get_by_hash("not-a-hash")
        with pytest.raises(ValueError, match="非法 sha256"):
            await repo.exists("short")

    async def test_exists(self, db_session: Any) -> None:
        """``exists`` 反映指纹是否已入库。"""
        repo = RawRepository(db_session)
        digest = "d" * 64
        assert await repo.exists(digest) is False
        await repo.upsert(make_item(sha256=digest))
        assert await repo.exists(digest) is True

    async def test_list_by_source_orders_and_filters(self, db_session: Any) -> None:
        """按发布时间倒序，并支持 ``since`` / ``source_id`` 过滤。"""
        repo = RawRepository(db_session)
        now = utc_now()
        await repo.upsert(make_item(sha256="1" * 64, source_id="CVE-2024-0001", published_at=now - timedelta(days=5)))
        await repo.upsert(make_item(sha256="2" * 64, source_id="CVE-2024-0002", published_at=now))
        await repo.upsert(make_item(sha256="3" * 64, source="osv", source_id="GHSA-x", published_at=now))

        ordered = await repo.list_by_source("kev")
        assert [item.source_id for item in ordered] == ["CVE-2024-0002", "CVE-2024-0001"]

        filtered = await repo.list_by_source("kev", source_id="CVE-2024-0001")
        assert [item.source_id for item in filtered] == ["CVE-2024-0001"]

        recent = await repo.list_by_source("kev", since=now - timedelta(hours=1))
        assert [item.source_id for item in recent] == ["CVE-2024-0002"]

    async def test_list_by_source_falls_back_to_fetched_at(self, db_session: Any) -> None:
        """``published_at`` 为空时用 ``fetched_at`` 参与排序。"""
        repo = RawRepository(db_session)
        await repo.upsert(make_item(sha256="4" * 64, source_id="CVE-2024-0004"))
        items = await repo.list_by_source("kev")
        assert items[0].published_at is None
        assert items[0].fetched_at is not None

    async def test_count_by_source(self, db_session: Any) -> None:
        """按源计数。"""
        repo = RawRepository(db_session)
        for index in range(3):
            await repo.upsert(make_item(sha256=str(index) * 64, source_id=f"CVE-2024-100{index}"))
        assert await repo.count_by_source("kev") == 3
        assert await repo.count_by_source("osv") == 0
