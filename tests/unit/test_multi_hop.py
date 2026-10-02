"""Day10 多跳遍历单元测试（``aisec_intel.qa.multi_hop``，PROJECT_PLAN.md §5.8）。

三类断言：
    1. 纯函数（组件 / 资产 / 技术条目抽取，路径组装，Cypher 行解析）；
    2. PG 降级路径（SQLite 内存库灌入事实层 + 富化层，走真实 2 跳集合运算）；
    3. Neo4j 路径（用桩客户端替换驱动，验证 Cypher 结果解析与降级判定）。
**不连接任何外部服务**。

Note:
    Day12 任务 2 合并：原 26 个用例压到 10 个（同类断言合并 + 同一夹具内串联多场景）。
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("sqlalchemy", reason="需要 sqlalchemy：pip install 'sqlalchemy[asyncio]' aiosqlite")

from aisec_intel.models.base import utc_now  # noqa: E402
from aisec_intel.models.enriched_vuln import (  # noqa: E402
    AffectedAsset,
    AttackChain,
    AttackChainStep,
    EnrichedVuln,
)
from aisec_intel.models.unified_vuln import CpeMatch, UnifiedVuln  # noqa: E402
from aisec_intel.qa import multi_hop as mh  # noqa: E402

GRAPH_ASSET_ROWS: list[dict[str, Any]] = [
    {
        "component_key": "paloaltonetworks:pan-os",
        "component": "PAN-OS",
        "vendor": "paloaltonetworks",
        "version_range": "<10.2.9-h1",
        "asset_key": "service:PAN-OS Firewall",
        "asset_name": "PAN-OS Firewall",
        "asset_type": "service",
        "link_source": mh.COOCCURRENCE_SOURCE,
        "asset_confidence": 0.8,
    },
    {"component_key": "php:php", "component": "PHP", "asset_key": None},
]
"""``CVE → Component → Asset`` 的 Cypher 预置行（含未匹配资产的 1 跳分支）。"""


class FakeNeo4jClient:
    """Neo4j 客户端桩：按 Cypher 关键字返回预置行。"""

    def __init__(
        self,
        *,
        asset_rows: list[dict[str, Any]] | None = None,
        technique_rows: list[dict[str, Any]] | None = None,
        alive: bool = True,
    ) -> None:
        """初始化桩。

        Args:
            asset_rows: ``CVE → Component → Asset`` 查询的预置返回行。
            technique_rows: ``CVE → AttackTechnique → CVE`` 查询的预置返回行。
            alive: ``ping()`` 的返回值（``False`` 用于验证降级分支）。
        """
        self.asset_rows = asset_rows or []
        self.technique_rows = technique_rows or []
        self.alive = alive
        self.calls: list[str] = []
        self.closed = False

    async def ping(self) -> bool:
        """探活（桩）。"""
        return self.alive

    async def run(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """按语句关键字返回预置行。"""
        self.calls.append(cypher)
        return self.technique_rows if "EXPLOITS" in cypher else self.asset_rows

    async def aclose(self) -> None:
        """关闭（桩，记录调用）。"""
        self.closed = True


class TestPureFunctions:
    """CVE 抽取、条目抽取、路径组装与 Cypher 行解析（纯函数）。"""

    def test_extract_cve_ids(self) -> None:
        """CVE 编号抽取：大写规范化 + 去重 + 无编号返回空。"""
        assert mh.extract_cve_ids("cve-2024-3400 与 CVE-2021-44228 的关系") == [
            "CVE-2024-3400",
            "CVE-2021-44228",
        ]
        assert mh.extract_cve_ids("CVE-2024-3400 / CVE-2024-3400") == ["CVE-2024-3400"]
        assert mh.extract_cve_ids("没有编号") == []

    def test_entry_extractors(
        self,
        sample_unified_vuln: UnifiedVuln,
        sample_enriched_vuln: EnrichedVuln,
    ) -> None:
        """组件 / 资产 / 技术条目：键口径、排序、无数据时的空结果。"""
        vuln = sample_unified_vuln.model_copy(update={"ecosystem_packages": ["PyPI:django"]})
        entries = mh.component_entries(vuln)
        assert [key for key, _, _ in entries] == ["PyPI:django", "paloaltonetworks:pan-os"]
        pan = dict((key, (name, props)) for key, name, props in entries)["paloaltonetworks:pan-os"]
        assert pan[0] == "pan-os" and "10.2.0" in str(pan[1]["version_range"])
        assert mh.component_key_of(CpeMatch(vendor="PaloAltoNetworks", product="PAN-OS")) == (
            "paloaltonetworks:pan-os"
        )

        assets = mh.asset_entries(sample_enriched_vuln)
        assert assets[0][0] == "service:PAN-OS Firewall" and assets[0][2]["asset_type"] == "service"
        assert mh.asset_entries(None) == []

        assert mh.technique_entries(sample_enriched_vuln) == [
            ("T1190", {"tactic": "initial-access", "stage": "Delivery", "order": 1})
        ]
        assert mh.technique_entries(None) == []
        chainless = UnifiedVuln(vuln_id="CVE-2020-0003", description="d", normalized_at=utc_now())
        payload = chainless.model_dump()
        payload.update(
            risk_score=0.0, risk_level="low", confidence=0.0, model_used="t", enriched_at=utc_now()
        )
        assert mh.technique_entries(EnrichedVuln(**payload)) == []

    def test_build_asset_paths(
        self, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``Component → Asset`` 边带共现标记；无资产时退化为 1 跳路径。"""
        components = mh.component_entries(sample_unified_vuln)
        assets = mh.asset_entries(sample_enriched_vuln)
        paths = mh.build_asset_paths("CVE-2024-3400", components, assets, source="postgres")
        assert len(paths) == 1 and paths[0].hops == 2
        assert paths[0].steps[0].relation == "AFFECTS"
        assert paths[0].steps[1].relation == "INSTALLED_ON"
        assert paths[0].steps[1].properties["derived_from"] == mh.COOCCURRENCE_SOURCE
        assert paths[0].end_key == "service:PAN-OS Firewall"
        degraded = mh.build_asset_paths("CVE-2024-3400", components, [], source="postgres")
        assert [path.hops for path in degraded] == [1]

    def test_build_technique_paths(self, sample_enriched_vuln: EnrichedVuln) -> None:
        """技术路径：相关漏洞按风险分降序、跳过自环；无匹配时保留 1 跳。"""
        techniques = mh.technique_entries(sample_enriched_vuln)
        related = [
            {"technique_id": "T1190", "cve_id": "CVE-2024-3400", "risk_score": 99.0, "title": "self"},
            {"technique_id": "T1190", "cve_id": "CVE-2024-1111", "risk_score": 40.0, "title": "low"},
            {"technique_id": "T1190", "cve_id": "CVE-2024-2222", "risk_score": 90.0, "title": "high"},
        ]
        paths = mh.build_technique_paths("CVE-2024-3400", techniques, related, source="postgres")
        assert [path.end_key for path in paths] == ["CVE-2024-2222", "CVE-2024-1111"]
        assert all(path.hops == 2 for path in paths)
        lonely = mh.build_technique_paths("CVE-2024-3400", techniques, [])
        assert [path.hops for path in lonely] == [1]

    def test_render_and_graph_row_parsing(self) -> None:
        """路径文本渲染 / 跳数 / 终点键，以及 Cypher 行 → 路径的解析。"""
        step = mh.MultiHopStep(
            relation="AFFECTS",
            from_label="Vulnerability",
            from_key="CVE-1",
            to_label="Component",
            to_key="v:p",
            to_name="p",
        )
        path = mh.MultiHopPath(pattern=mh.PATTERN_CVE_ASSET, start_key="CVE-1", steps=[step])
        assert path.render() == "CVE-1 -[AFFECTS]-> p"
        assert path.hops == 1 and path.end_key == "v:p"
        assert mh.MultiHopPath(pattern=mh.PATTERN_CVE_ASSET, start_key="CVE-1").render() == "CVE-1（无路径）"

        asset_paths = mh.paths_from_graph_asset_rows("CVE-2024-3400", GRAPH_ASSET_ROWS, source="neo4j")
        assert [item.hops for item in asset_paths] == [2, 1]
        assert all(item.source == "neo4j" for item in asset_paths)

        technique_paths = mh.paths_from_graph_technique_rows(
            "CVE-2024-3400",
            [
                {
                    "technique_id": "t1190",
                    "tactic": "initial-access",
                    "cve_id": "CVE-2024-1111",
                    "risk_score": 50.0,
                },
                {"technique_id": "", "cve_id": "CVE-X"},
                {"technique_id": "T1190", "cve_id": "CVE-2024-3400"},
            ],
            source="neo4j",
        )
        assert len(technique_paths) == 2
        assert technique_paths[0].steps[-1].to_key == "CVE-2024-1111"
        assert technique_paths[1].hops == 1  # 自环被跳过，仅保留技术节点


def _neighbour(base: UnifiedVuln) -> EnrichedVuln:
    """构造「共享 T1190 的邻居漏洞」（用于验证第 2 跳的集合运算）。"""
    payload = base.model_dump()
    payload.update(vuln_id="CVE-2024-9999", title="Neighbour Vulnerability", kev=False)
    neighbour = UnifiedVuln(**payload)
    enriched_payload = neighbour.model_dump()
    enriched_payload.update(
        affected_assets=[
            AffectedAsset(asset_type="service", name="Another Firewall", confidence=0.6).model_dump()
        ],
        related_papers=[],
        exploits=[],
        risk_score=50.0,
        risk_level="high",
        risk_breakdown={},
        attack_chain=AttackChain(
            steps=[
                AttackChainStep(
                    order=1,
                    technique_id="T1190",
                    tactic="initial-access",
                    stage="Delivery",
                    description="同类入口利用",
                )
            ]
        ).model_dump(),
        confidence=0.8,
        model_used="test",
        enriched_at=utc_now(),
    )
    return EnrichedVuln(**enriched_payload)


async def _seed(session: Any, vuln: UnifiedVuln, enriched: EnrichedVuln) -> None:
    """写入事实层 + 富化层（图谱节点的事实来源）。"""
    from aisec_intel.storage.repositories.vuln_repo import VulnRepository

    repo = VulnRepository(session)
    await repo.upsert(vuln)
    await repo.upsert_enriched(enriched)
    await session.flush()


class TestPostgresFallback:
    """PG JSON 降级路径（SQLite 内存库，真实 2 跳集合运算）。"""

    async def test_cve_to_assets_two_hop_and_notes(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """2 跳路径 + 降级标记 + 渲染；未知 CVE 与「仅事实层」两类说明。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        result = await traversal.cve_to_assets("cve-2024-3400")
        assert result.source == "postgres" and result.degraded is True
        assert result.pattern == mh.PATTERN_CVE_ASSET
        assert result.paths and result.paths[0].hops == 2
        assert result.paths[0].end_key == "service:PAN-OS Firewall"
        assert result.render_lines()[0].startswith("CVE-2024-3400")

        unknown = await traversal.cve_to_assets("CVE-1999-0001")
        assert unknown.paths == [] and unknown.note and "不存在" in unknown.note

        from aisec_intel.storage.repositories.vuln_repo import VulnRepository

        fact_only = UnifiedVuln(**{**sample_unified_vuln.model_dump(), "vuln_id": "CVE-2024-8888"})
        await VulnRepository(db_session).upsert(fact_only)
        await db_session.flush()
        not_enriched = await traversal.cve_to_assets("CVE-2024-8888")
        assert [path.hops for path in not_enriched.paths] == [1]
        assert not_enriched.note and "未富化" in not_enriched.note

    async def test_related_cves_by_technique_finds_neighbour(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``CVE → AttackTechnique → CVE`` 能找到共享 T1190 的邻居漏洞。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        neighbour_vuln = UnifiedVuln(**{**sample_unified_vuln.model_dump(), "vuln_id": "CVE-2024-9999"})
        await _seed(db_session, neighbour_vuln, _neighbour(sample_unified_vuln))

        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        result = await traversal.related_cves_by_technique("CVE-2024-3400")
        assert result.source == "postgres"
        assert [path.end_key for path in result.paths] == ["CVE-2024-9999"]
        assert result.paths[0].hops == 2

    async def test_traverse_patterns_and_technique_rows(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``traverse`` 默认双模式、``patterns`` 白名单生效；技术维度扫描函数命中 / 未命中 / 空输入。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        assert [item.pattern for item in await traversal.traverse("CVE-2024-3400")] == [
            mh.PATTERN_CVE_ASSET,
            mh.PATTERN_CVE_TECHNIQUE,
        ]
        filtered = await traversal.traverse("CVE-2024-3400", patterns=[mh.PATTERN_CVE_TECHNIQUE])
        assert [item.pattern for item in filtered] == [mh.PATTERN_CVE_TECHNIQUE]

        rows = await mh.collect_technique_rows(db_session, ["t1190", "T9999"])
        assert [(row["cve_id"], row["technique_id"]) for row in rows] == [("CVE-2024-3400", "T1190")]
        assert await mh.collect_technique_rows(db_session, []) == []
        assert await mh.collect_technique_rows(db_session, ["T9999"]) == []


class TestNeo4jRoute:
    """Neo4j 路径（桩客户端）。"""

    async def test_graph_rows_are_used_when_available(self, db_session: Any) -> None:
        """客户端可用时直接采用 Cypher 结果（资产 2 跳 + 技术邻居）。"""
        client = FakeNeo4jClient(
            asset_rows=[
                {
                    "component_key": "paloaltonetworks:pan-os",
                    "component": "PAN-OS",
                    "asset_key": "service:PAN-OS Firewall",
                    "asset_name": "PAN-OS Firewall",
                }
            ],
            technique_rows=[{"technique_id": "T1190", "cve_id": "CVE-2024-1111", "risk_score": 88.0}],
        )
        traversal = mh.MultiHopTraversal(db_session, graph_client=client, prefer_graph=True)  # type: ignore[arg-type]
        assets = await traversal.cve_to_assets("CVE-2024-3400")
        techniques = await traversal.related_cves_by_technique("CVE-2024-3400")
        assert assets.source == "neo4j" and assets.degraded is False
        assert assets.paths[0].hops == 2
        assert techniques.source == "neo4j" and techniques.paths[0].end_key == "CVE-2024-1111"

    async def test_degradation_and_client_lifecycle(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """探活失败 / 关闭图谱偏好时不触碰客户端，且不越权关闭外部客户端。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        dead = FakeNeo4jClient(alive=False)
        traversal = mh.MultiHopTraversal(db_session, graph_client=dead, prefer_graph=True)  # type: ignore[arg-type]
        result = await traversal.cve_to_assets("CVE-2024-3400")
        assert result.source == "postgres" and result.degraded is True
        assert dead.calls == []

        ignored = FakeNeo4jClient(alive=True)
        off = mh.MultiHopTraversal(db_session, graph_client=ignored, prefer_graph=False)  # type: ignore[arg-type]
        assert await off.graph_available() is False
        assert ignored.calls == []

        external = FakeNeo4jClient()
        owner = mh.MultiHopTraversal(db_session, graph_client=external, prefer_graph=True)  # type: ignore[arg-type]
        await owner.aclose()
        assert external.closed is False
