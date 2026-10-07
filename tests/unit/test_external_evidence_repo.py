"""Day25 阶段 2 任务 2.1：``external_evidence`` 仓储单元测试（迁移 0009）。

覆盖：领域模型 ↔ ORM 的转换边界、按 ``content_hash`` 幂等写入、按 CVE / 复核状态过滤与计数。
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install 'sqlalchemy[asyncio]' aiosqlite")

from aisec_intel.models.base import utc_now  # noqa: E402
from aisec_intel.models.external_evidence import ExternalEvidence  # noqa: E402
from aisec_intel.storage.models.external_evidence import ExternalEvidenceRow  # noqa: E402
from aisec_intel.storage.repositories.external_evidence_repo import (  # noqa: E402
    ExternalEvidenceRepository,
)

CVE = "CVE-2024-34359"


def _item(*, cve: str = CVE, verified: bool = False, snippet: str = "修复版本: 0.2.72") -> ExternalEvidence:
    """构造一条外部证据（测试夹具）。"""
    return ExternalEvidence(
        query=f"{cve} 应升级到哪个版本",
        cve_id=cve,
        source_type="ghsa",
        source_name="GHSA-56xg-wfcc-g829",
        url="https://github.com/advisories/GHSA-56xg-wfcc-g829",
        title="llama-cpp-python RCE",
        snippet=snippet,
        retrieved_at=utc_now(),
        trust_score=0.73,
        verified=verified,
        content_hash=f"hash-{cve}-{snippet[:4]}",
        facts=["fixed_version"],
    )


class TestRoundTrip:
    """领域模型 ↔ ORM 转换边界。"""

    def test_from_and_to_domain(self) -> None:
        """``from_domain`` → ``to_domain`` 字段一致；``facts`` 由读取侧重算（ORM 不还原）。"""
        row = ExternalEvidenceRow.from_domain(_item())
        restored = row.to_domain()
        assert restored.cve_id == CVE and restored.source_type == "ghsa"
        assert restored.snippet == "修复版本: 0.2.72" and restored.untrusted is True
        assert restored.facts == [] and restored.trust_score == pytest.approx(0.73)


class TestUpsertAndQuery:
    """幂等写入与过滤查询（SQLite 内存库）。"""

    async def test_upsert_is_idempotent_by_content_hash(self, db_session: Any) -> None:
        """同一 ``content_hash`` 重复写入只刷新字段，不产生重复行。"""
        repo = ExternalEvidenceRepository(db_session)
        assert await repo.upsert_many([_item(), _item()]) == 1
        assert await repo.count() == 1

        refreshed = _item(verified=True).model_copy(update={"trust_score": 0.9})
        await repo.upsert_many([refreshed])
        assert await repo.count() == 1
        rows = await repo.list_by_cve(CVE)
        assert rows[0].verified is True and rows[0].trust_score == pytest.approx(0.9)

    async def test_filters_and_counts(self, db_session: Any) -> None:
        """按 CVE / 复核状态过滤与计数（大小写不敏感）。"""
        repo = ExternalEvidenceRepository(db_session)
        await repo.upsert_many([_item(), _item(cve="CVE-2024-3400", snippet="受影响版本: pan-os")])
        await repo.upsert_many([_item(verified=True).model_copy(update={"content_hash": "hash-verified"})])

        assert await repo.count() == 3
        assert await repo.count(cve_id="cve-2024-34359") == 2
        assert await repo.count(verified_only=True) == 1
        assert len(await repo.list_by_cve(CVE, verified_only=True)) == 1
        assert len(await repo.list_recent(limit=2)) == 2
        assert await repo.upsert_many([]) == 0
