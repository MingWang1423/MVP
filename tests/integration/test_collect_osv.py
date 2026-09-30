"""Day4 集成测试：**真实调用** OSV API 并走完整归一化流水线（需要网络）。

运行方式（默认 `python -m pytest` 会跳过，见 ``pyproject.toml`` 的 ``addopts``）::

    python -m pytest tests/integration/test_collect_osv.py -m integration -q

断言目标（对应 §6.2 P2 验收）：真实采集 3 条 → 归一化为 ``UnifiedVuln`` → 关键字段完整。
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aisec_intel.connectors.osv import OsvConnector
from aisec_intel.normalize.pipeline import build_unified_vuln

pytestmark = pytest.mark.integration

SINCE = datetime(2023, 1, 1, tzinfo=UTC)
WATCH_PACKAGE = "langchain"


@pytest.mark.asyncio
async def test_collect_osv_and_normalize_pipeline() -> None:
    """真实拉取 OSV（langchain）→ 取前 3 条 → 走 pipeline 并校验字段完整性。"""
    connector = OsvConnector(packages=[WATCH_PACKAGE])
    try:
        items = await connector.fetch_incremental(SINCE)
    finally:
        await connector.aclose()

    assert items, f"OSV 应至少返回一条 {WATCH_PACKAGE} 相关漏洞（检查网络连通性）"
    selected = items[:3]
    vulns = [build_unified_vuln(raw) for raw in selected]

    for vuln in vulns:
        assert vuln.vuln_id
        assert vuln.description, "描述不应为空"
        assert vuln.sources == ["osv"]
        assert vuln.trace_ids, "trace_id 必须透传（§10.2 不变式 5）"
        assert vuln.normalized_at.tzinfo is not None, "归一化时间必须带时区"
        assert vuln.published_at is not None, "OSV 条目应带发布时间"
        assert vuln.references, "应至少有一条参考链接"

    assert any(v.ecosystem_packages for v in vulns), "应能抽出 PyPI 生态包"
    assert all(v.vuln_id != v.aliases[0] for v in vulns if v.aliases), "别名不与主键重复"
