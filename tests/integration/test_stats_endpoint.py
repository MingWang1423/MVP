"""Day14 任务 6：``GET /api/v1/stats`` 集成测试（仪表盘唯一数据源）。

用 SQLite 内存库 + ``dependency_overrides`` 覆盖 ``get_stats_repo`` / ``get_source_repo``，
**不需要 PostgreSQL / Neo4j / LLM** 即可验证：

- 4 个 KPI 口径（总数 / CRITICAL / 已启用源数 / 近 24h 新增）；
- 风险分布（含未定级 → ``unknown``）与来源分布（JSON 数组展开）；
- 趋势窗口（日期连续 30 点、``published_at`` 缺省回退 ``normalized_at``）；
- 高危清单（``CRITICAL`` / ``HIGH`` 倒序 + 富化风险分左连接）。
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from aisec_intel.api.deps import get_source_repo, get_stats_repo  # noqa: E402
from aisec_intel.api.main import create_app  # noqa: E402
from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.source_repo import SourceRepository, SourceSpec  # noqa: E402
from aisec_intel.storage.repositories.stats_repo import StatsRepository  # noqa: E402
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"

NOW = utc_now()
"""基准时间（UTC）：所有种子数据相对它偏移，避免用例受真实时钟影响。"""


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造一条事实层实体（测试辅助）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "title": f"{vuln_id} title",
        "description": f"{vuln_id} description",
        "severity": "CRITICAL",
        "sources": ["nvd"],
        "published_at": NOW - timedelta(days=2),
        "normalized_at": NOW - timedelta(days=2),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


async def seed(engine: Any) -> None:
    """写入 4 条事实（覆盖 4 种分布 + 未定级）+ 1 条富化 + 3 个源登记。

    时间轴设计：

    =================  ==========================  =====================================
    条目               时间轴（published 优先）      用途
    =================  ==========================  =====================================
    ``CVE-A``          NOW - 2 天                  KPI / 高危 / 富化左连接
    ``CVE-B``          NOW - 3 小时                近 24h 新增 + 高危
    ``CVE-C``          ``published_at=None``       回退 ``normalized_at``（NOW-5h）
    ``CVE-D``          NOW - 40 天                 趋势窗口外 + ``unknown`` 分布
    =================  ==========================  =====================================
    """
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        await repo.upsert(make_vuln("CVE-A", sources=["nvd", "kev"]))
        await repo.upsert(
            make_vuln(
                "CVE-B",
                severity="HIGH",
                sources=["nvd"],
                published_at=NOW - timedelta(hours=3),
                normalized_at=NOW - timedelta(hours=3),
            )
        )
        await repo.upsert(
            make_vuln(
                "CVE-C",
                severity="MEDIUM",
                sources=["osv"],
                published_at=None,
                normalized_at=NOW - timedelta(hours=5),
            )
        )
        await repo.upsert(
            make_vuln(
                "CVE-D",
                severity=None,
                sources=["ghsa"],
                published_at=NOW - timedelta(days=40),
                normalized_at=NOW - timedelta(days=40),
            )
        )
        await repo.upsert_enriched(
            EnrichedVuln(
                vuln_id="CVE-A",
                description="CVE-A description",
                normalized_at=NOW - timedelta(days=2),
                risk_score=91.5,
                risk_level="critical",
                confidence=0.9,
                model_used="deepseek-chat",
                enriched_at=NOW - timedelta(days=1),
            )
        )
        await SourceRepository(session).upsert_many(
            [
                SourceSpec(name="nvd", connector_class="NvdConnector"),
                SourceSpec(name="osv", connector_class="OsvConnector"),
                SourceSpec(name="ghsa", connector_class="GhsaConnector", enabled=False),
            ]
        )


@pytest.fixture()
def client() -> Iterator[TestClient]:
    """构造注入了内存库仓储的测试客户端（``TestClient`` 自带事件循环）。"""
    engine = create_engine(MEMORY_DSN)
    asyncio.run(init_models(engine))
    asyncio.run(seed(engine))
    factory = create_session_factory(engine)

    async def override_stats() -> AsyncIterator[StatsRepository]:
        async with factory() as session:
            yield StatsRepository(session)

    async def override_sources() -> AsyncIterator[SourceRepository]:
        async with factory() as session:
            yield SourceRepository(session)

    app = create_app()
    app.dependency_overrides[get_stats_repo] = override_stats
    app.dependency_overrides[get_source_repo] = override_sources
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


class TestStatsEndpoint:
    """``GET /api/v1/stats`` 全字段口径。"""

    def test_kpis(self, client: TestClient) -> None:
        """4 个 KPI：总数 / CRITICAL / 已启用源 / 近 24h 新增。"""
        payload = client.get("/api/v1/stats").json()
        assert payload["total_vulns"] == 4
        assert payload["critical_count"] == 1
        assert payload["source_count"] == 2  # ghsa 已停用，不计入
        assert payload["today_new"] == 2  # CVE-B(-3h) + CVE-C(-5h)

    def test_risk_distribution_keeps_fixed_keys(self, client: TestClient) -> None:
        """风险分布：小写键 + 未定级归 ``unknown`` + 零值键保留。"""
        payload = client.get("/api/v1/stats").json()
        assert payload["risk_distribution"] == {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "unknown": 1,
        }

    def test_source_distribution_expands_json(self, client: TestClient) -> None:
        """来源分布：``sources`` JSON 数组展开后按条数倒序。"""
        payload = client.get("/api/v1/stats").json()
        assert payload["source_distribution"] == {"nvd": 2, "ghsa": 1, "kev": 1, "osv": 1}

    def test_timeline_window_is_continuous(self, client: TestClient) -> None:
        """趋势：默认 30 个连续日期点；窗口外条目不落入；``published_at`` 缺省回退入库时间。"""
        payload = client.get("/api/v1/stats").json()
        points = payload["timeline"]
        assert len(points) == 30
        dates = [point["date"] for point in points]
        assert dates == sorted(dates) and len(set(dates)) == 30
        assert dates[-1] == datetime.now(UTC).date().isoformat()
        # CVE-A(-2d) + CVE-B(-3h) + CVE-C(回退 normalized_at, -5h)；CVE-D(-40d) 在窗口外
        assert sum(point["count"] for point in points) == 3

    def test_timeline_days_param(self, client: TestClient) -> None:
        """``timeline_days`` 可调；越界由 FastAPI 校验为 422。"""
        assert len(client.get("/api/v1/stats", params={"timeline_days": 7}).json()["timeline"]) == 7
        assert client.get("/api/v1/stats", params={"timeline_days": 0}).status_code == 422

    def test_top_high_risk_list(self, client: TestClient) -> None:
        """高危清单：仅 CRITICAL/HIGH、时间倒序、带富化风险分（左连接）。"""
        payload = client.get("/api/v1/stats", params={"high_risk_limit": 5}).json()
        rows = payload["top_high_risk"]
        assert [row["vuln_id"] for row in rows] == ["CVE-B", "CVE-A"]
        assert rows[0]["enriched"] is False and rows[0]["risk_score"] is None
        assert rows[1]["risk_score"] == pytest.approx(91.5)
        assert rows[1]["risk_level"] == "critical" and rows[1]["enriched"] is True

    def test_generated_at_present(self, client: TestClient) -> None:
        """``generated_at`` 为 ISO8601 ``Z`` 结尾（§10.2 不变式 3）。"""
        payload = client.get("/api/v1/stats").json()
        assert payload["generated_at"].endswith("Z")
