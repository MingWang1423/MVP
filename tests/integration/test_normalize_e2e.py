"""Day5 集成测试：**真实** OSV 采集 → 归一化流水线 → 入库（需网络）。

运行方式（默认 `python -m pytest` 会跳过）::

    python -m pytest tests/integration/test_normalize_e2e.py -m integration -q

覆盖最小数据流「采集 → 归一化 → 持久化 → 幂等重放」，用 SQLite 内存库隔离外部依赖，
网络部分为真实 OSV API（对应 §6.2 P2 的「5 个源跑通 + 归一化」验收）。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisec_intel.connectors.osv import OsvConnector
from aisec_intel.normalize.pipeline import build_unified_vuln
from aisec_intel.storage.database import create_engine, init_models, session_scope
from aisec_intel.storage.repositories.vuln_repo import VulnRepository

pytestmark = pytest.mark.integration

SINCE = datetime.now(UTC) - timedelta(days=900)
WATCH_PACKAGE = "langchain"
MEMORY_DSN = "sqlite+aiosqlite:///:memory:"


@pytest.mark.asyncio
async def test_osv_collect_normalize_and_persist() -> None:
    """真实抓取 3 条 OSV 漏洞 → 归一化 → 写入 ``unified_vuln`` → 重放幂等。"""
    connector = OsvConnector(packages=[WATCH_PACKAGE], max_records=3)
    try:
        items = await connector.fetch_incremental(SINCE)
    finally:
        await connector.aclose()

    assert len(items) >= 3, f"OSV 应至少返回 3 条 {WATCH_PACKAGE} 相关漏洞（检查网络）"
    selected = items[:3]
    vulns = [build_unified_vuln(raw) for raw in selected]
    assert len({vuln.vuln_id for vuln in vulns}) == 3

    engine = create_engine(MEMORY_DSN)
    try:
        await init_models(engine)
        async with session_scope(engine) as session:
            repo = VulnRepository(session)
            for vuln in vulns:
                outcome = await repo.upsert_with_status(vuln)
                assert outcome.created is True, f"{vuln.vuln_id} 首次写入应为新增"

        async with session_scope(engine) as session:
            repo = VulnRepository(session)
            for vuln in vulns:
                stored = await repo.get_by_cve(vuln.vuln_id)
                assert stored is not None, f"{vuln.vuln_id} 应可读回"
                assert stored.trace_ids, "trace_id 必须透传（§10.2 不变式 5）"
                assert stored.description, "描述不应为空"
            assert len(await repo.list_recent(limit=10)) >= 3

        async with session_scope(engine) as session:
            repo = VulnRepository(session)
            for vuln in vulns:
                assert (await repo.upsert_with_status(vuln)).created is False, "重放应为更新而非新增"
    finally:
        await engine.dispose()
