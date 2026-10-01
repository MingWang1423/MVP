"""Day10 多跳遍历单元测试（``aisec_intel.qa.multi_hop``，PROJECT_PLAN.md §5.8）。

三类断言：
    1. 纯函数（组件 / 资产 / 技术条目抽取，路径组装，Cypher 行解析）；
    2. PG 降级路径（SQLite 内存库灌入事实层 + 富化层，走真实 2 跳集合运算）；
    3. Neo4j 路径（用桩客户端替换驱动，验证 Cypher 结果解析与降级判定）。
**不连接任何外部服务**。
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


class TestExtractCveIds:
    """CVE 编号抽取。"""

    def test_extracts_and_normalizes(self) -> None:
        assert mh.extract_cve_ids("cve-2024-3400 与 CVE-2021-44228 的关系") == ["CVE-2024-3400", "CVE-2021-44228"]

    def test_dedupes_and_handles_empty(self) -> None:
        assert mh.extract_cve_ids("CVE-2024-3400 / CVE-2024-3400") == ["CVE-2024-3400"]
        assert mh.extract_cve_ids("没有编号") == []


class TestEntries:
    """组件 / 资产 / 技术条目抽取（纯函数）。"""

    def test_component_entries_from_cpe_and_packages(self, sample_unified_vuln: UnifiedVuln) -> None:
        """CPE 生成 ``vendor:product`` 键，生态包用包标识作键，结果按 key 排序。"""
        vuln = sample_unified_vuln.model_copy(update={"ecosystem_packages": ["PyPI:django"]})
        entries = mh.component_entries(vuln)
        keys = [key for key, _, _ in entries]
        assert keys == ["PyPI:django", "paloaltonetworks:pan-os"]
        pan = dict((key, (name, props)) for key, name, props in entries)["paloaltonetworks:pan-os"]
        assert pan[0] == "pan-os"
        assert "10.2.0" in str(pan[1]["version_range"])

    def test_component_key_lowercased(self) -> None:
        """组件键统一小写（与图谱抽取器一致）。"""
        match = CpeMatch(vendor="PaloAltoNetworks", product="PAN-OS")
        assert mh.component_key_of(match) == "paloaltonetworks:pan-os"

    def test_asset_entries(self, sample_enriched_vuln: EnrichedVuln) -> None:
        entries = mh.asset_entries(sample_enriched_vuln)
        assert entries[0][0] == "service:PAN-OS Firewall"
        assert entries[0][2]["asset_type"] == "service"

    def test_asset_entries_none_when_not_enriched(self) -> None:
        assert mh.asset_entries(None) == []

    def test_technique_entries(self, sample_enriched_vuln: EnrichedVuln) -> None:
        entries = mh.technique_entries(sample_enriched_vuln)
        assert entries == [("T1190", {"tactic": "initial-access", "stage": "Delivery", "order": 1})]

    def test_technique_entries_without_chain(self) -> None:
        assert mh.technique_entries(None) == []
        vuln = UnifiedVuln(vuln_id="CVE-2020-0003", description="d", normalized_at=utc_now())
        payload = vuln.model_dump()
        payload.update(risk_score=0.0, risk_level="low", confidence=0.0, model_used="t", enriched_at=utc_now())
        assert mh.technique_entries(EnrichedVuln(**payload)) == []


class TestBuildPaths:
    """路径组装（纯函数）。"""

    def test_asset_paths_use_cooccurrence_marker(
        self, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``Component → Asset`` 边带 ``derived_from=cve-cooccurrence``（与图谱抽取器同口径）。"""
        components = mh.component_entries(sample_unified_vuln)
        assets = mh.asset_entries(sample_enriched_vuln)
        paths = mh.build_asset_paths("CVE-2024-3400", components, assets, source="postgres")
        assert len(paths) == 1
        assert paths[0].hops == 2
        assert paths[0].steps[0].relation == "AFFECTS"
        assert paths[0].steps[1].relation == "INSTALLED_ON"
        assert paths[0].steps[1].properties["derived_from"] == mh.COOCCURRENCE_SOURCE
        assert paths[0].end_key == "service:PAN-OS Firewall"

    def test_asset_paths_one_hop_without_assets(self, sample_unified_vuln: UnifiedVuln) -> None:
        """未富化（无资产）时退化为 1 跳路径，仍保留组件信息。"""
        paths = mh.build_asset_paths("CVE-2024-3400", mh.component_entries(sample_unified_vuln), [], source="postgres")
        assert [path.hops for path in paths] == [1]

    def test_technique_paths_sorted_and_skip_self(self, sample_enriched_vuln: EnrichedVuln) -> None:
        """同一技术下的相关漏洞按风险分降序，且跳过起点自身。"""
        techniques = mh.technique_entries(sample_enriched_vuln)
        related = [
            {"technique_id": "T1190", "cve_id": "CVE-2024-3400", "risk_score": 99.0, "title": "self"},
            {"technique_id": "T1190", "cve_id": "CVE-2024-1111", "risk_score": 40.0, "title": "low"},
            {"technique_id": "T1190", "cve_id": "CVE-2024-2222", "risk_score": 90.0, "title": "high"},
        ]
        paths = mh.build_technique_paths("CVE-2024-3400", techniques, related, source="postgres")
        assert [path.end_key for path in paths] == ["CVE-2024-2222", "CVE-2024-1111"]
        assert all(path.hops == 2 for path in paths)

    def test_technique_paths_without_matches_is_one_hop(self, sample_enriched_vuln: EnrichedVuln) -> None:
        """没有相关漏洞时保留 1 跳路径（技术本身仍是有效情报）。"""
        paths = mh.build_technique_paths("CVE-2024-3400", mh.technique_entries(sample_enriched_vuln), [])
        assert [path.hops for path in paths] == [1]

    def test_render_and_properties(self) -> None:
        """路径文本渲染、跳数与终点键。"""
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
        empty = mh.MultiHopPath(pattern=mh.PATTERN_CVE_ASSET, start_key="CVE-1")
        assert empty.render() == "CVE-1（无路径）"

    def test_graph_asset_rows_parsing(self) -> None:
        """Cypher 行 → 路径（含未匹配资产的 1 跳分支）。"""
        rows = [
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
        paths = mh.paths_from_graph_asset_rows("CVE-2024-3400", rows, source="neo4j")
        assert [path.hops for path in paths] == [2, 1]
        assert all(path.source == "neo4j" for path in paths)

    def test_graph_technique_rows_parsing(self) -> None:
        """攻击技术 Cypher 行 → 路径（跳过空行与自环）。"""
        rows = [
            {"technique_id": "t1190", "tactic": "initial-access", "cve_id": "CVE-2024-1111", "risk_score": 50.0},
            {"technique_id": "", "cve_id": "CVE-X"},
            {"technique_id": "T1190", "cve_id": "CVE-2024-3400"},
        ]
        paths = mh.paths_from_graph_technique_rows("CVE-2024-3400", rows, source="neo4j")
        assert len(paths) == 2
        assert paths[0].steps[-1].to_key == "CVE-2024-1111"
        assert paths[1].hops == 1  # 自环被跳过，仅保留技术节点


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

    async def test_cve_to_assets_two_hop(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``CVE → Component → Asset`` 得到 2 跳路径，并标记为降级来源。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        result = await traversal.cve_to_assets("cve-2024-3400")
        assert result.source == "postgres" and result.degraded is True
        assert result.pattern == mh.PATTERN_CVE_ASSET
        assert result.paths and result.paths[0].hops == 2
        assert result.paths[0].end_key == "service:PAN-OS Firewall"
        assert result.render_lines()[0].startswith("CVE-2024-3400")

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

    async def test_unknown_cve_returns_note(self, db_session: Any) -> None:
        """起点不存在时返回空路径 + 说明（不抛异常）。"""
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        result = await traversal.cve_to_assets("CVE-1999-0001")
        assert result.paths == []
        assert result.note and "不存在" in result.note

    async def test_not_enriched_gives_one_hop_and_note(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln
    ) -> None:
        """仅事实层（未富化）时返回 1 跳路径并提示原因。"""
        from aisec_intel.storage.repositories.vuln_repo import VulnRepository

        await VulnRepository(db_session).upsert(sample_unified_vuln)
        await db_session.flush()
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        result = await traversal.cve_to_assets("CVE-2024-3400")
        assert [path.hops for path in result.paths] == [1]
        assert result.note and "未富化" in result.note

    async def test_traverse_runs_both_patterns(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``traverse`` 默认跑两条路径模式，顺序稳定。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        results = await traversal.traverse("CVE-2024-3400")
        assert [item.pattern for item in results] == [mh.PATTERN_CVE_ASSET, mh.PATTERN_CVE_TECHNIQUE]

    async def test_traverse_with_pattern_filter(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """``patterns`` 白名单生效。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        traversal = mh.MultiHopTraversal(db_session, prefer_graph=False)
        results = await traversal.traverse("CVE-2024-3400", patterns=[mh.PATTERN_CVE_TECHNIQUE])
        assert [item.pattern for item in results] == [mh.PATTERN_CVE_TECHNIQUE]

    async def test_collect_technique_rows_helper(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """公开的技术维度扫描函数（图谱路复用）：命中 / 未命中 / 空输入。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        rows = await mh.collect_technique_rows(db_session, ["t1190", "T9999"])
        assert [(row["cve_id"], row["technique_id"]) for row in rows] == [("CVE-2024-3400", "T1190")]
        assert await mh.collect_technique_rows(db_session, []) == []
        assert await mh.collect_technique_rows(db_session, ["T9999"]) == []


class TestNeo4jRoute:
    """Neo4j 路径（桩客户端）。"""

    async def test_graph_rows_are_used_when_available(self, db_session: Any) -> None:
        """客户端可用时直接采用 Cypher 结果。"""
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
        assert techniques.source == "neo4j"
        assert techniques.paths[0].end_key == "CVE-2024-1111"
        assert len(client.calls) == 2

    async def test_unavailable_client_falls_back(
        self, db_session: Any, sample_unified_vuln: UnifiedVuln, sample_enriched_vuln: EnrichedVuln
    ) -> None:
        """探活失败 → 自动降级 PG（不抛异常、不中断链路）。"""
        await _seed(db_session, sample_unified_vuln, sample_enriched_vuln)
        client = FakeNeo4jClient(alive=False)
        traversal = mh.MultiHopTraversal(db_session, graph_client=client, prefer_graph=True)  # type: ignore[arg-type]
        result = await traversal.cve_to_assets("CVE-2024-3400")
        assert result.source == "postgres" and result.degraded is True
        assert client.calls == []

    async def test_prefer_graph_false_never_pings(self, db_session: Any) -> None:
        """``prefer_graph=False`` 时完全不触碰客户端。"""
        client = FakeNeo4jClient(alive=True)
        traversal = mh.MultiHopTraversal(db_session, graph_client=client, prefer_graph=False)  # type: ignore[arg-type]
        assert await traversal.graph_available() is False
        assert client.calls == []

    async def test_external_client_is_not_closed(self, db_session: Any) -> None:
        """外部注入的客户端由调用方负责关闭（``aclose`` 不越权）。"""
        client = FakeNeo4jClient()
        traversal = mh.MultiHopTraversal(db_session, graph_client=client, prefer_graph=True)  # type: ignore[arg-type]
        await traversal.aclose()
        assert client.closed is False
