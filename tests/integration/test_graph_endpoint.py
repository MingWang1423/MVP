"""Day15 任务 4：图谱子图端点集成测试（``GET /api/v1/graph/{cve_id}``）。

两条路径都覆盖，且**不需要真实 Neo4j**：

1. **PostgreSQL 降级路径**：``NEO4J_ENABLED=false``（构造 Settings）+ SQLite 内存库，
   由冻结契约现场推导子图（含未富化时的「组件 + 补丁」兜底）；
2. **Neo4j 路径**：注入假的 :class:`Neo4jClient`（只实现 ``run`` / ``aclose``），
   验证「原始行 → React Flow 节点/边」的映射与 ``backend=neo4j`` 标记。

另含 404（库中无该 CVE）与 ``limit`` 越界校验。
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
"""降级配置：``NEO4J_ENABLED=false`` → 强制走 PG 推导路径（用例与真实 Neo4j 解耦）。"""

NOW = utc_now()

NEO4J_ROWS: list[dict[str, Any]] = [
    {
        "center_key": "CVE-2024-3400",
        "center_title": "PAN-OS command injection",
        "center_severity": "CRITICAL",
        "relation": "AFFECTS",
        "node_labels": ["Component"],
        "node_props": {"key": "paloaltonetworks:pan-os", "name": "PAN-OS"},
    },
    {
        "center_key": "CVE-2024-3400",
        "center_title": "PAN-OS command injection",
        "center_severity": "CRITICAL",
        "relation": "EXPLOITS",
        "node_labels": ["AttackTechnique"],
        "node_props": {"technique_id": "T1190", "description": "Exploit Public-Facing App"},
    },
]


class FakeNeo4jClient:
    """假的 Neo4j 客户端：只实现 :class:`GraphService` 用到的两个方法。"""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        """保存待返回的行。

        Args:
            rows: ``subgraph`` 查询的预置返回行。
        """
        self.rows = rows
        self.queries: list[str] = []
        self.closed = False

    async def run(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """记录 Cypher 并返回预置行。"""
        self.queries.append(cypher)
        return list(self.rows)

    async def aclose(self) -> None:
        """标记为已关闭。"""
        self.closed = True


def make_vuln(vuln_id: str, **overrides: Any) -> UnifiedVuln:
    """构造事实层实体（含 CPE 与补丁引用）。"""
    payload: dict[str, Any] = {
        "vuln_id": vuln_id,
        "title": f"{vuln_id} title",
        "description": f"{vuln_id} description",
        "severity": "CRITICAL",
        "sources": ["nvd"],
        "cpe_matches": [CpeMatch(vendor="paloaltonetworks", product="pan-os")],
        "references": [
            Reference(
                url="https://security.paloaltonetworks.com/CVE-2024-3400",
                source="vendor",
                tags=["patch"],
            )
        ],
        "normalized_at": NOW,
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def make_enriched(vuln_id: str) -> EnrichedVuln:
    """构造富化实体（含资产，令子图出现 Asset 节点）。"""
    return EnrichedVuln(
        **make_vuln(vuln_id).model_dump(),
        affected_assets=[AffectedAsset(asset_type="device", name="edge-fw", confidence=0.9)],
        risk_score=95.0,
        risk_level="critical",
        confidence=0.9,
        model_used="deepseek-chat",
        enriched_at=NOW,
    )


async def seed(engine: Any) -> None:
    """写入三条漏洞。

    - ``CVE-GRAPH-A``：已富化（含资产）→ 子图出现 Asset 节点；
    - ``CVE-GRAPH-B``：未富化 → 降级为「组件 + 补丁」；
    - ``CVE-2024-3400``：仅用于 Neo4j 路径用例（图里的节点必须先在事实层存在，
      因为 :meth:`GraphService.subgraph` 先校验 CVE 是否在库中）。
    """
    async with session_scope(engine) as session:
        repo = VulnRepository(session)
        await repo.upsert(make_vuln("CVE-GRAPH-A"))
        await repo.upsert(make_vuln("CVE-GRAPH-B"))
        await repo.upsert(make_vuln("CVE-2024-3400"))
        await repo.upsert_enriched(make_enriched("CVE-GRAPH-A"))


def build_client(engine: Any, *, client: Any | None = None, settings: Settings | None = None) -> TestClient:
    """构造注入了图谱服务的测试客户端。

    Args:
        engine: SQLite 内存库引擎。
        client: 注入的假 Neo4j 客户端（``None`` 时走 PG 推导路径）。
        settings: 覆盖配置（默认 ``NEO4J_ENABLED=false``）。

    Returns:
        已装配依赖覆盖的 :class:`TestClient`。
    """
    factory = create_session_factory(engine)
    resolved = settings or DEGRADED_SETTINGS

    async def override_service() -> AsyncIterator[GraphService]:
        async with factory() as session:
            yield GraphService(session, settings=resolved, client=client)

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


class TestPostgresFallbackPath:
    """``NEO4J_ENABLED=false``：由冻结契约现场推导子图。"""

    def test_enriched_vulnerability_covers_five_node_types(self, engine: Any) -> None:
        with build_client(engine) as client:
            # 大小写不敏感：小写路径同样命中
            payload = client.get("/api/v1/graph/cve-graph-a").json()

        assert payload["cve_id"] == "CVE-GRAPH-A"
        assert payload["backend"] == "postgres"
        assert payload["truncated"] is False
        assert payload["node_count"] == len(payload["nodes"])
        assert payload["edge_count"] == len(payload["edges"])

        types = {node["type"] for node in payload["nodes"]}
        assert {"vulnerability", "component", "asset", "patch"} <= types
        ids = {node["id"] for node in payload["nodes"]}
        assert "Vulnerability:CVE-GRAPH-A" in ids
        assert "Component:paloaltonetworks:pan-os" in ids
        assert "Asset:device:edge-fw" in ids
        assert "Patch:https://security.paloaltonetworks.com/CVE-2024-3400" in ids

        relations = {edge["relation"] for edge in payload["edges"]}
        assert {"AFFECTS", "INSTALLED_ON", "FIXED_BY"} <= relations
        # 每条边的两端都能在节点集合中找到（React Flow 渲染前置约束）
        for edge in payload["edges"]:
            assert edge["source"] in ids and edge["target"] in ids
            assert edge["id"] == f"{edge['source']}-{edge['relation']}->{edge['target']}"

    def test_not_enriched_falls_back_to_facts_only(self, engine: Any) -> None:
        with build_client(engine) as client:
            payload = client.get("/api/v1/graph/CVE-GRAPH-B").json()

        types = {node["type"] for node in payload["nodes"]}
        assert types == {"vulnerability", "component", "patch"}
        assert {edge["relation"] for edge in payload["edges"]} == {"AFFECTS", "FIXED_BY"}

    def test_unknown_cve_returns_404(self, engine: Any) -> None:
        with build_client(engine) as client:
            response = client.get("/api/v1/graph/CVE-1999-0001")
        assert response.status_code == 404
        assert "未找到漏洞" in response.json()["detail"]

    def test_limit_validation(self, engine: Any) -> None:
        with build_client(engine) as client:
            assert client.get("/api/v1/graph/CVE-GRAPH-A", params={"limit": 0}).status_code == 422
            assert client.get("/api/v1/graph/CVE-GRAPH-A", params={"limit": 999}).status_code == 422


class TestNeo4jPath:
    """注入假 Neo4j 客户端：验证映射与 ``backend`` 标记（无需真实图数据库）。"""

    def test_uses_neo4j_rows_and_orients_edges(self, engine: Any) -> None:
        fake = FakeNeo4jClient(NEO4J_ROWS)
        with build_client(engine, client=fake, settings=Settings(neo4j_enabled=True)) as client:
            payload = client.get("/api/v1/graph/CVE-2024-3400").json()

        assert payload["backend"] == "neo4j"
        assert {node["id"] for node in payload["nodes"]} == {
            "Vulnerability:CVE-2024-3400",
            "Component:paloaltonetworks:pan-os",
            "AttackTechnique:T1190",
        }
        assert payload["edges"] == [
            {
                "id": "Vulnerability:CVE-2024-3400-AFFECTS->Component:paloaltonetworks:pan-os",
                "source": "Vulnerability:CVE-2024-3400",
                "target": "Component:paloaltonetworks:pan-os",
                "relation": "AFFECTS",
            },
            {
                "id": "Vulnerability:CVE-2024-3400-EXPLOITS->AttackTechnique:T1190",
                "source": "Vulnerability:CVE-2024-3400",
                "target": "AttackTechnique:T1190",
                "relation": "EXPLOITS",
            },
        ]
        # Cypher 走白名单 + 参数化（标签从 schema 常量拼入，键值走参数）
        assert len(fake.queries) == 1
        assert "MATCH (v:Vulnerability {cve_id: $cve_id})" in fake.queries[0]
        assert "$labels" in fake.queries[0]
        # 注入的客户端由调用方持有，不应被服务关闭
        assert fake.closed is False

    def test_falls_back_when_graph_has_no_node(self, engine: Any) -> None:
        """图中没有该漏洞时降级为 PG 推导（``backend=postgres``）。"""
        fake = FakeNeo4jClient([])
        with build_client(engine, client=fake, settings=Settings(neo4j_enabled=True)) as client:
            payload = client.get("/api/v1/graph/CVE-GRAPH-A").json()

        assert payload["backend"] == "postgres"
        assert "Vulnerability:CVE-GRAPH-A" in {node["id"] for node in payload["nodes"]}
