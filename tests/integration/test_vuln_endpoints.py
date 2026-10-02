"""Day12 任务 5：漏洞查询 API 集成测试（``api/routers/vulns.py``）。

用 SQLite 内存库 + ``dependency_overrides`` 覆盖 ``get_vuln_repo``，
**不需要 PostgreSQL / Neo4j / LLM** 即可验证「列表（分页 + 筛选）→ 详情（事实 + 富化）」
这两个前端主流程端点，以及仓储层 ``list_filtered`` / ``risk_levels`` 的过滤口径
（含 JSON ``sources`` 包含过滤在 SQLite 与 PostgreSQL 上的一致语义）。
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from aisec_intel.api.deps import get_vuln_repo  # noqa: E402
from aisec_intel.api.main import create_app  # noqa: E402
from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"

NOW = utc_now()
"""固定基准时间（UTC），避免用例受真实时钟影响。"""


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造一条事实层实体（测试辅助）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "title": f"{vuln_id} title",
        "description": f"{vuln_id} description",
        "severity": "CRITICAL",
        "sources": ["nvd", "kev"],
        "normalized_at": NOW,
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched(vuln_id: str, **overrides: Any) -> EnrichedVuln:
    """构造一条富化层实体（测试辅助）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "description": f"{vuln_id} description",
        "normalized_at": NOW,
        "affected_assets": [
            {
                "asset_type": "service",
                "name": "PAN-OS Firewall",
                "vendor": "Palo Alto Networks",
                "confidence": 0.8,
            }
        ],
        "exploits": [{"source": "github", "url": "https://example.test/poc", "maturity": "poc"}],
        "risk_score": 96.0,
        "risk_level": "critical",
        "risk_breakdown": {"cvss": 40.0, "epss": 20.0, "kev": 30.0, "poc": 6.0},
        "confidence": 0.85,
        "model_used": "deepseek-chat",
        "enriched_at": NOW,
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


async def seed(engine: Any) -> None:
    """写入三条事实 + 一条富化（时间正序：0100 < 0200 < 0300）。"""
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        await repo.upsert(
            make_vuln("CVE-2024-0100", published_at=NOW - timedelta(days=2), sources=["osv"])
        )
        await repo.upsert(
            make_vuln(
                "CVE-2024-0200",
                published_at=NOW - timedelta(hours=2),
                severity="MEDIUM",
                kev=False,
                sources=["nvd", "ghsa"],
            )
        )
        await repo.upsert(make_vuln("CVE-2024-0300", published_at=NOW - timedelta(minutes=5), kev=True))
        await repo.upsert_enriched(make_enriched("CVE-2024-0300"))


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """构造注入了内存库仓储的测试客户端（同步 fixture：``TestClient`` 自带事件循环）。"""
    import asyncio

    engine = create_engine(MEMORY_DSN)
    asyncio.run(init_models(engine))
    asyncio.run(seed(engine))
    factory = create_session_factory(engine)

    async def override_repo() -> AsyncIterator[VulnRepository]:
        async with factory() as session:
            yield VulnRepository(session)

    app = create_app()
    app.dependency_overrides[get_vuln_repo] = override_repo
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


class TestVulnerabilityEndpoints:
    """``GET /api/v1/vulnerabilities`` 与 ``/{cve_id}``。"""

    def test_list_paginates_and_orders(self, client: TestClient) -> None:
        """列表按发布时间倒序返回，含分页元信息与富化风险分。"""
        page = client.get("/api/v1/vulnerabilities", params={"limit": 2}).json()
        assert page["total"] == 3 and page["limit"] == 2 and page["offset"] == 0
        assert [item["vuln_id"] for item in page["items"]] == ["CVE-2024-0300", "CVE-2024-0200"]
        latest = page["items"][0]
        assert latest["risk_score"] == pytest.approx(96.0)
        assert latest["risk_level"] == "critical" and latest["enriched"] is True
        second = client.get("/api/v1/vulnerabilities", params={"limit": 2, "offset": 2}).json()
        assert [item["vuln_id"] for item in second["items"]] == ["CVE-2024-0100"]
        assert second["items"][0]["enriched"] is False

    def test_list_filters(self, client: TestClient) -> None:
        """严重度 / 来源 / 时间 / KEV 四类筛选口径正确（组合筛选取交集）。"""
        cases: list[tuple[dict[str, Any], list[str]]] = [
            ({"severity": "MEDIUM"}, ["CVE-2024-0200"]),
            ({"source": "ghsa"}, ["CVE-2024-0200"]),
            ({"source": "OSV"}, ["CVE-2024-0100"]),
            ({"days": 1}, ["CVE-2024-0300", "CVE-2024-0200"]),
            ({"kev_only": True}, ["CVE-2024-0300"]),
            ({"severity": "CRITICAL", "source": "osv"}, ["CVE-2024-0100"]),
        ]
        for params, expected in cases:
            payload = client.get("/api/v1/vulnerabilities", params=params).json()
            assert [item["vuln_id"] for item in payload["items"]] == expected, params

    def test_detail_returns_fact_and_enriched(self, client: TestClient) -> None:
        """详情同时给出事实层与富化层（七维字段齐全，且大小写不敏感）。"""
        payload = client.get("/api/v1/vulnerabilities/cve-2024-0300").json()
        assert payload["unified"]["vuln_id"] == "CVE-2024-0300"
        assert payload["unified"]["severity"] == "CRITICAL"
        enriched = payload["enriched"]
        assert enriched["risk_score"] == pytest.approx(96.0)
        for field in ("affected_assets", "exploits", "risk_breakdown", "confidence"):
            assert enriched[field], field
        assert enriched["model_used"] == "deepseek-chat"

    def test_detail_unknown_returns_404(self, client: TestClient) -> None:
        """不存在的漏洞返回 404 且带可读提示。"""
        response = client.get("/api/v1/vulnerabilities/CVE-1999-0001")
        assert response.status_code == 404
        assert "未找到漏洞" in response.json()["detail"]


class TestRepositoryFiltering:
    """仓储层过滤口径（直接验证 SQL 语义，不经过 HTTP）。"""

    async def test_list_filtered_and_risk_levels(self) -> None:
        """``list_filtered`` 分页与过滤、``risk_levels`` 批量取风险分。"""
        engine = create_engine(MEMORY_DSN)
        await init_models(engine)
        await seed(engine)
        factory = create_session_factory(engine)
        try:
            async with factory() as session:
                repo = VulnRepository(session)
                rows, total = await repo.list_filtered(limit=10)
                assert total == 3 and [row.vuln_id for row in rows][0] == "CVE-2024-0300"
                assert [row.vuln_id for row in (await repo.list_filtered(source="nvd", limit=10))[0]] == [
                    "CVE-2024-0300",
                    "CVE-2024-0200",
                ]
                assert (await repo.list_filtered(severity="medium", limit=10))[1] == 1
                assert (await repo.list_filtered(since=NOW - timedelta(hours=1), limit=10))[1] == 1
                assert (await repo.list_filtered(offset=10, limit=10)) == ([], 3)
                risks = await repo.risk_levels(["CVE-2024-0300", "CVE-2024-0100"])
                assert risks == {"CVE-2024-0300": (96.0, "critical")}
        finally:
            await engine.dispose()
