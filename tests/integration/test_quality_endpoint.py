"""Day16 任务 2：数据质量端点集成测试（``GET /api/v1/data-quality``）。

不需要真实 PostgreSQL：用 SQLite 内存库 + ``dependency_overrides`` 注入
:class:`~aisec_intel.services.quality_service.DataQualityService`。

覆盖：

1. KPI 口径：已启用源数 / 采集总条数 / 归一化成功率 / 字段完整率；
2. 各源明细（含零数据源）与缺失源提示；
3. 趋势两条线（采集 / 入库）长度与补 0 行为；
4. Markdown 报告：``data_quality`` 与 P4 脚本同生成器，``graph_stats`` 可缺省；
5. 采样上限截断：``truncated=true`` 且 ``sample_limit`` 回显。
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from aisec_intel.api.deps import get_quality_service  # noqa: E402
from aisec_intel.api.main import create_app  # noqa: E402
from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models.base import new_trace_id, utc_now  # noqa: E402
from aisec_intel.models.raw_item import RawItem  # noqa: E402
from aisec_intel.services.quality_service import DataQualityService, SnapshotCache  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.raw_repo import RawRepository  # noqa: E402
from aisec_intel.storage.repositories.source_repo import (  # noqa: E402
    SourceRepository,
    SourceSpec,
)
from aisec_intel.utils.hashing import sha256_text  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"

SETTINGS = Settings(neo4j_enabled=False)
"""降级配置：不触碰 Neo4j（本端点与图谱无关）。"""

NVD_FULL: dict[str, Any] = {
    "cve": {
        "id": "CVE-2024-3400",
        "published": "2024-04-12T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "PAN-OS command injection."}],
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
        "references": [{"url": "https://example.org/advisory"}],
    }
}

NVD_MINIMAL: dict[str, Any] = {
    "cve": {
        "id": "CVE-2024-1111",
        "published": "2024-05-01T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "Minimal record without CVSS/CWE."}],
    }
}


def make_raw(source: str, source_id: str, payload: dict[str, Any]) -> RawItem:
    """构造一条 ``RawItem``（内容与指纹自洽）。

    Args:
        source: 源标识。
        source_id: 源内 ID。
        payload: 原始 JSON 负载。

    Returns:
        :class:`~aisec_intel.models.raw_item.RawItem`。
    """
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=None,
        raw_text=text,
        lang="en",
        published_at=datetime(2024, 5, 1, tzinfo=UTC),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


async def seed(engine: Any) -> None:
    """写入两条 NVD 原始件与两个启用源。

    Args:
        engine: SQLite 内存库引擎。
    """
    async with session_scope(engine) as session:
        repo = RawRepository(session)
        await repo.upsert(make_raw("nvd", "CVE-2024-3400", NVD_FULL))
        await repo.upsert(make_raw("nvd", "CVE-2024-1111", NVD_MINIMAL))
        await SourceRepository(session).upsert_many(
            [
                SourceSpec(name="nvd", connector_class="NvdConnector"),
                SourceSpec(name="kev", connector_class="KevConnector"),
            ]
        )
        await session.commit()


def build_client(engine: Any) -> TestClient:
    """构造注入了数据质量服务（独立缓存）的测试客户端。

    Args:
        engine: SQLite 内存库引擎。

    Returns:
        已装配依赖覆盖的 :class:`TestClient`。
    """
    factory = create_session_factory(engine)
    cache = SnapshotCache()

    async def override_service() -> AsyncIterator[DataQualityService]:
        async with factory() as session:
            yield DataQualityService(session, settings=SETTINGS, cache=cache)

    app = create_app()
    app.dependency_overrides[get_quality_service] = override_service
    return TestClient(app)


@pytest.fixture()
def engine() -> Iterator[Any]:
    """建表并写入种子数据的内存库引擎。"""
    instance = create_engine(MEMORY_DSN)
    asyncio.run(init_models(instance))
    asyncio.run(seed(instance))
    yield instance
    asyncio.run(instance.dispose())


class TestDataQualityEndpoint:
    """``GET /api/v1/data-quality`` 契约与口径。"""

    def test_kpi_and_source_details(self, engine: Any) -> None:
        """KPI 与各源明细：2 条 NVD 原始件、归一化 2/2、字段完整率按成功条数计。"""
        with build_client(engine) as client:
            response = client.get("/api/v1/data-quality")
        assert response.status_code == 200
        payload = response.json()

        assert payload["enabled_source_count"] == 2
        assert payload["total_raw"] == 2
        assert payload["normalized_ok"] == 2
        assert payload["normalized_failed"] == 0
        assert payload["normalization_success_rate"] == 1.0
        # 两条记录：一条带 CVSS/CWE，一条不带 → 50%
        assert payload["field_completeness"]["cvss"] == 0.5
        assert payload["field_completeness"]["cwe"] == 0.5
        assert payload["field_completeness"]["description"] == 1.0
        assert payload["field_completeness"]["references"] == 1.0

        by_source = {item["source"]: item for item in payload["sources"]}
        # 明细覆盖 sources.yaml 声明的全部启用源（零数据源同样出现在列表里 → 暴露采集缺口）
        assert len(payload["sources"]) == len(payload["declared_sources"])
        assert set(by_source) >= {"nvd", "kev"}
        assert by_source["nvd"]["raw_count"] == 2
        assert by_source["nvd"]["success_rate"] == 1.0
        assert by_source["kev"]["raw_count"] == 0
        assert by_source["kev"]["success_rate"] == 0.0
        assert "kev" in payload["missing_sources"]
        assert 0.0 < payload["coverage_rate"] < 1.0

    def test_trend_has_two_continuous_series(self, engine: Any) -> None:
        """趋势两条线均为 30 天连续日期（缺失日补 0），当天计数 > 0。"""
        with build_client(engine) as client:
            payload = client.get("/api/v1/data-quality", params={"trend_days": 30}).json()
        trend = payload["trend"]
        assert payload["trend_days"] == 30
        assert len(trend) == 30
        assert len(payload["trend_normalized"]) == 30
        assert trend[-1]["count"] >= 1
        assert [point["date"] for point in trend] == sorted(point["date"] for point in trend)

    def test_reports_are_markdown(self, engine: Any) -> None:
        """报告字段为 Markdown 原文；``include_reports=false`` 时整体为 ``null``。"""
        with build_client(engine) as client:
            payload = client.get("/api/v1/data-quality").json()
            without = client.get("/api/v1/data-quality", params={"include_reports": False}).json()
        reports = payload["reports"]
        assert reports is not None
        assert reports["data_quality"].startswith("# 采集数据质量报告（P4）")
        assert "## 1. 采集量与归一化成功率" in reports["data_quality"]
        # graph_stats.md 在仓库内存在 → 随响应返回；缺失时应为 null（前端展示空态）
        assert reports["graph_stats"] is None or "图谱" in reports["graph_stats"]
        assert without["reports"] is None

    def test_sample_limit_truncates(self, engine: Any) -> None:
        """采样上限生效时 ``truncated=true``，并把生效上限回显给前端。"""
        with build_client(engine) as client:
            payload = client.get("/api/v1/data-quality", params={"sample_limit": 2}).json()
        assert payload["sample_limit"] == 2
        assert payload["truncated"] is True
        assert payload["total_raw"] == 2

    def test_cache_is_used_unless_refresh(self, engine: Any) -> None:
        """同一参数第二次请求命中缓存（``generated_at`` 不变）；``refresh=true`` 重算。"""
        with build_client(engine) as client:
            first = client.get("/api/v1/data-quality").json()
            second = client.get("/api/v1/data-quality").json()
            refreshed = client.get("/api/v1/data-quality", params={"refresh": True}).json()
        assert first["generated_at"] == second["generated_at"]
        assert refreshed["generated_at"] >= first["generated_at"]

    def test_invalid_params_are_rejected(self, engine: Any) -> None:
        """``trend_days`` 越界与 ``sample_limit`` 负数都返回 422（契约校验）。"""
        with build_client(engine) as client:
            assert client.get("/api/v1/data-quality", params={"trend_days": 0}).status_code == 422
            assert (
                client.get("/api/v1/data-quality", params={"sample_limit": -1}).status_code == 422
            )
