"""Day16 任务 1.4：图谱全图概览端点集成测试（``GET /api/v1/graph``）。

不需要真实 Neo4j：概览走「冻结契约现场推导 + 合并」路径（SQLite 内存库即可）。
覆盖：

1. 多 CVE 合并：节点 / 边去重，共享组件只出现一次；
2. 未富化 CVE 同样参与建图（退化为「组件 + 补丁」）；
3. 容量裁剪：``max_nodes`` 生效时 ``truncated=true``，且中心漏洞必须保留；
4. 参数校验：``limit`` / ``max_nodes`` 越界返回 422；
5. 空库：返回空节点 / 空边（前端渲染空态）。
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install sqlalchemy[asyncio] aiosqlite")
pytest.importorskip("aiosqlite", reason="需要 aiosqlite：pip install aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from aisec_intel.api.deps import get_graph_service  # noqa: E402
from aisec_intel.api.main import create_app  # noqa: E402
from aisec_intel.config import Settings  # noqa: E402
from aisec_intel.models import EnrichedVuln, UnifiedVuln, utc_now  # noqa: E402
from aisec_intel.models.enriched_vuln import AffectedAsset  # noqa: E402
from aisec_intel.models.unified_vuln import CpeMatch, Reference  # noqa: E402
from aisec_intel.services.graph_service import GraphService  # noqa: E402
from aisec_intel.storage.database import (  # noqa: E402
    create_engine,
    create_session_factory,
    init_models,
    session_scope,
)
from aisec_intel.storage.repositories.vuln_repo import VulnRepository  # noqa: E402

MEMORY_DSN = "sqlite+aiosqlite:///:memory:"

DEGRADED_SETTINGS = Settings(neo4j_enabled=False)
"""降级配置：概览本身不查 Neo4j，但仍固定关闭以免误连。"""

NOW = utc_now()


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造事实层实体（含共享 CPE 与补丁引用）。

    Args:
        vuln_id: 漏洞主键。
        overrides: 覆盖字段。

    Returns:
        :class:`~aisec_intel.models.unified_vuln.UnifiedVuln`。
    """
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "title": f"{vuln_id} title",
        "description": f"{vuln_id} description",
        "severity": "CRITICAL",
        "sources": ["nvd"],
        # 两个 CVE 共用同一组件 → 概览图中该组件只应出现一次
        "cpe_matches": [CpeMatch(vendor="paloaltonetworks", product="pan-os")],
        "references": [
            Reference(
                url="https://security.paloaltonetworks.com/advisory",
                source="vendor",
                tags=["patch"],
            )
        ],
        "normalized_at": NOW,
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched(vuln_id: str, *, risk_score: float, asset: str) -> EnrichedVuln:
    """构造富化实体（带资产，令子图出现 Asset 节点）。

    Args:
        vuln_id: 漏洞主键。
        risk_score: 风险分（决定概览中的排序）。
        asset: 资产名。

    Returns:
        :class:`~aisec_intel.models.enriched_vuln.EnrichedVuln`。
    """
    return EnrichedVuln(
        **make_vuln(vuln_id).model_dump(),
        affected_assets=[AffectedAsset(asset_type="device", name=asset, confidence=0.9)],
        risk_score=risk_score,
        risk_level="critical",
        confidence=0.9,
        model_used="deepseek-chat",
        enriched_at=NOW,
    )


async def seed(engine: Any) -> None:
    """写入三个漏洞：两个已富化（风险分 95 / 60）+ 一个未富化。

    Args:
        engine: SQLite 内存库引擎。
    """
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        await repo.upsert(make_vuln("CVE-OVERVIEW-A"))
        await repo.upsert(make_vuln("CVE-OVERVIEW-B"))
        await repo.upsert(make_vuln("CVE-OVERVIEW-C"))
        await repo.upsert_enriched(make_enriched("CVE-OVERVIEW-A", risk_score=95.0, asset="edge-fw-a"))
        await repo.upsert_enriched(make_enriched("CVE-OVERVIEW-B", risk_score=60.0, asset="edge-fw-b"))


def build_client(engine: Any) -> TestClient:
    """构造注入了图谱服务的测试客户端。

    Args:
        engine: SQLite 内存库引擎。

    Returns:
        已装配依赖覆盖的 :class:`TestClient`。
    """
    factory = create_session_factory(engine)

    async def override_service() -> AsyncIterator[GraphService]:
        async with factory() as session:
            yield GraphService(session, settings=DEGRADED_SETTINGS)

    app = create_app()
    app.dependency_overrides[get_graph_service] = override_service
    return TestClient(app)


@pytest.fixture()
def engine() -> Iterator[Any]:
    """建表并写入种子数据的内存库引擎。"""
    instance = create_engine(MEMORY_DSN)
    asyncio.run(init_models(instance))
    asyncio.run(seed(instance))
    yield instance
    asyncio.run(instance.dispose())


@pytest.fixture()
def empty_engine() -> Iterator[Any]:
    """仅建表的空库引擎（校验空态）。"""
    instance = create_engine(MEMORY_DSN)
    asyncio.run(init_models(instance))
    yield instance
    asyncio.run(instance.dispose())


class TestGraphOverviewEndpoint:
    """``GET /api/v1/graph`` 契约与合并口径。"""

    def test_merges_and_deduplicates(self, engine: Any) -> None:
        """三个 CVE 合并为一张图：共享组件 / 补丁只出现一次，边两端都在节点集合内。"""
        with build_client(engine) as client:
            payload = client.get("/api/v1/graph", params={"limit": 10}).json()

        assert payload["backend"] == "postgres"
        assert payload["node_count"] == len(payload["nodes"])
        assert payload["edge_count"] == len(payload["edges"])
        assert payload["truncated"] is False
        # 风险分倒序：95 → 60 → 未富化（-1）
        assert payload["cve_ids"][:2] == ["CVE-OVERVIEW-A", "CVE-OVERVIEW-B"]
        assert set(payload["cve_ids"]) == {"CVE-OVERVIEW-A", "CVE-OVERVIEW-B", "CVE-OVERVIEW-C"}

        node_ids = [item["id"] for item in payload["nodes"]]
        assert len(node_ids) == len(set(node_ids))
        assert node_ids.count("Component:paloaltonetworks:pan-os") == 1
        assert node_ids.count("Vulnerability:CVE-OVERVIEW-A") == 1
        # 未富化条目退化为「组件 + 补丁」，仍然建图
        assert "Vulnerability:CVE-OVERVIEW-C" in node_ids
        # 富化条目附带资产节点
        assert "Asset:device:edge-fw-a" in node_ids

        types = {item["type"] for item in payload["nodes"]}
        assert {"vulnerability", "component", "asset", "patch"} <= types

        reserved = set(node_ids)
        for edge in payload["edges"]:
            assert edge["source"] in reserved
            assert edge["target"] in reserved

    def test_limit_controls_merged_cves(self, engine: Any) -> None:
        """``limit`` 控制参与合并的漏洞条数（按风险分倒序取前 N）。"""
        with build_client(engine) as client:
            payload = client.get("/api/v1/graph", params={"limit": 1}).json()
        assert payload["cve_ids"] == ["CVE-OVERVIEW-A"]

    def test_truncation_keeps_vulnerabilities(self, engine: Any) -> None:
        """``max_nodes`` 很小时置 ``truncated=true``，但三个中心漏洞必须都在。"""
        with build_client(engine) as client:
            payload = client.get("/api/v1/graph", params={"limit": 10, "max_nodes": 4}).json()
        assert payload["truncated"] is True
        node_ids = {item["id"] for item in payload["nodes"]}
        assert len(node_ids) == 4
        assert {
            "Vulnerability:CVE-OVERVIEW-A",
            "Vulnerability:CVE-OVERVIEW-B",
            "Vulnerability:CVE-OVERVIEW-C",
        } <= node_ids
        for edge in payload["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids

    def test_empty_database_returns_empty_graph(self, empty_engine: Any) -> None:
        """库中无漏洞时返回空图（前端渲染空态，不报错）。"""
        with build_client(empty_engine) as client:
            payload = client.get("/api/v1/graph").json()
        assert payload["nodes"] == []
        assert payload["edges"] == []
        assert payload["cve_ids"] == []
        assert payload["node_count"] == 0

    def test_invalid_params_are_rejected(self, engine: Any) -> None:
        """``limit`` 为 0 / 超上限、``max_nodes`` 为 0 均返回 422。"""
        with build_client(engine) as client:
            assert client.get("/api/v1/graph", params={"limit": 0}).status_code == 422
            assert client.get("/api/v1/graph", params={"limit": 101}).status_code == 422
            assert client.get("/api/v1/graph", params={"max_nodes": 0}).status_code == 422
