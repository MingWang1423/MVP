"""富化候选筛选测试（Day19 分层 pipeline：``run_enrich --only-high-risk``）。

覆盖两处：

1. :func:`aisec_intel.services.enrich_service.is_high_risk`（**纯函数**，KEV / severity 口径）；
2. :func:`aisec_intel.services.enrich_service.load_unified_vulns` 的 ``only_high_risk`` 过滤
   （SQLite 内存库 + 桩引擎，不依赖 PostgreSQL / 网络 / LLM）。

口径与仪表盘 / P4 报告一致：``kev=True`` 或事实层 ``severity ∈ {HIGH, CRITICAL}``。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.models.base import utc_now
from aisec_intel.models.unified_vuln import UnifiedVuln
from aisec_intel.services.enrich_service import is_high_risk, load_unified_vulns
from aisec_intel.storage.repositories.vuln_repo import VulnRepository


def make_vuln(vuln_id: str, *, severity: str | None, kev: bool = False) -> UnifiedVuln:
    """构造一条事实层漏洞（默认无 CVSS，只控制 ``severity`` / ``kev``）。

    Args:
        vuln_id: 主键（如 ``CVE-2024-1001``）。
        severity: 事实层严重度；``None`` 表示源未提供。
        kev: 是否进入 CISA KEV。

    Returns:
        :class:`UnifiedVuln` 实例。
    """
    return UnifiedVuln(
        vuln_id=vuln_id,
        description=f"{vuln_id} description",
        severity=severity,
        kev=kev,
        published_at=utc_now(),
        normalized_at=utc_now(),
        sources=["nvd"],
    )


class TestIsHighRisk:
    """``is_high_risk`` 纯函数口径。"""

    def test_kev_rows_are_high_risk(self) -> None:
        """命中 KEV（即使无 severity）即高危。"""
        assert is_high_risk(make_vuln("CVE-2024-0001", severity=None, kev=True)) is True

    @pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
    def test_high_and_critical_are_high_risk(self, severity: str) -> None:
        """``HIGH`` / ``CRITICAL`` 即高危。"""
        assert is_high_risk(make_vuln("CVE-2024-0002", severity=severity)) is True

    @pytest.mark.parametrize("severity", ["LOW", "MEDIUM", "NONE", None])
    def test_other_severities_are_not_high_risk(self, severity: str | None) -> None:
        """``LOW`` / ``MEDIUM`` / ``NONE`` / 缺失一律不算高危（不做推断）。"""
        assert is_high_risk(make_vuln("CVE-2024-0003", severity=severity)) is False


class TestLoadUnifiedVulnsHighRiskFilter:
    """``load_unified_vulns(only_high_risk=True)`` 的行为。"""

    async def test_only_high_risk_filters_rows(
        self, memory_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """只返回 KEV / HIGH / CRITICAL，其余被过滤。"""
        from aisec_intel.services import enrich_service
        from aisec_intel.storage.database import session_scope

        monkeypatch.setattr(enrich_service, "get_engine", lambda settings: memory_engine)
        async with session_scope(memory_engine) as session:
            repo = VulnRepository(session)
            for vuln in (
                make_vuln("CVE-2024-1001", severity="CRITICAL"),
                make_vuln("CVE-2024-1002", severity="LOW"),
                make_vuln("CVE-2024-1003", severity=None, kev=True),
                make_vuln("CVE-2024-1004", severity="MEDIUM"),
            ):
                await repo.upsert(vuln)

        settings = Settings(_env_file=None)
        all_rows = await load_unified_vulns(settings, limit=10)
        high_rows = await load_unified_vulns(settings, limit=10, only_high_risk=True)

        assert {vuln.vuln_id for vuln in all_rows} == {
            "CVE-2024-1001",
            "CVE-2024-1002",
            "CVE-2024-1003",
            "CVE-2024-1004",
        }
        assert {vuln.vuln_id for vuln in high_rows} == {"CVE-2024-1001", "CVE-2024-1003"}

    async def test_single_cve_not_high_risk_returns_empty(
        self, memory_engine: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``--cve`` 指向低危条目时返回空（调度器据此跳过）。"""
        from aisec_intel.services import enrich_service
        from aisec_intel.storage.database import session_scope

        monkeypatch.setattr(enrich_service, "get_engine", lambda settings: memory_engine)
        async with session_scope(memory_engine) as session:
            await VulnRepository(session).upsert(make_vuln("CVE-2024-2001", severity="LOW"))

        settings = Settings(_env_file=None)
        assert await load_unified_vulns(settings, cve_id="CVE-2024-2001", only_high_risk=True) == []
        found = await load_unified_vulns(settings, cve_id="CVE-2024-2001")
        assert [vuln.vuln_id for vuln in found] == ["CVE-2024-2001"]
