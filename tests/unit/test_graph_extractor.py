"""Day9 图谱抽取器单元测试（``aisec_intel.graph.extractor``，PROJECT_PLAN.md §5.7）。

抽取器是**纯函数**（零 IO、零 LLM），因此全部用例离线：

1. ``EnrichedVuln`` → 6 类节点 + 5 类关系映射正确；
2. 幂等 / 确定性：同一输入两次抽取结果完全一致，且不修改入参；
3. 边界：缺维度时只产出对应节点/边；``None`` 属性被剔除（Neo4j 不接受 ``None``）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.graph import schema
from aisec_intel.graph.extractor import (
    COOCCURRENCE_SOURCE,
    ExtractionResult,
    GraphEdge,
    GraphNode,
    extract_graph,
    is_patch_reference,
    render_version_range,
    split_ecosystem_package,
    summarize_properties,
)
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import (
    AffectedAsset,
    AttackChain,
    AttackChainStep,
    EnrichedVuln,
    ExploitRecord,
)
from aisec_intel.models.paper import PaperVulnLink
from aisec_intel.models.unified_vuln import CpeMatch, CVSSVector, Reference

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

PATCH_URL = "https://security.paloaltonetworks.com/CVE-2024-3400"
BLOG_URL = "https://example.test/blog-post"
ADVISORY_URL = "https://github.com/advisories/GHSA-abc-123"


def make_enriched(**overrides: Any) -> EnrichedVuln:
    """构造测试用富化实体（默认覆盖全部 5 类关系）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "title": "PAN-OS Command Injection",
        "description": "Command injection in PAN-OS GlobalProtect.",
        "severity": "CRITICAL",
        "cvss": [CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")],
        "cwe_ids": ["CWE-77"],
        "cpe_matches": [
            CpeMatch(vendor="paloaltonetworks", product="pan-os", version_end_excl="10.2.9-h1")
        ],
        "ecosystem_packages": ["PyPI:ollama"],
        "affected_versions": ["paloaltonetworks:pan-os <10.2.9-h1"],
        "references": [
            Reference(url=PATCH_URL, source="vendor", tags=["vendor-advisory"]),
            Reference(url=BLOG_URL, source="nvd", tags=["exploit"]),
            Reference(url=ADVISORY_URL, source="ghsa", tags=[]),
        ],
        "kev": True,
        "epss_score": 0.94,
        "sources": ["nvd", "kev"],
        "trace_ids": ["trace-1"],
        "normalized_at": utc_now(),
        "affected_assets": [
            AffectedAsset(
                asset_type="service",
                name="GlobalProtect Gateway",
                vendor="Palo Alto Networks",
                version_range="<10.2.9-h1",
                confidence=0.6,
                evidence_refs=["trace-1"],
            )
        ],
        "related_papers": [
            PaperVulnLink(
                paper_id="2404.12345",
                vuln_id="CVE-2024-3400",
                relation="proposes-attack",
                confidence=0.8,
                evidence_refs=["trace-1"],
            )
        ],
        "exploits": [ExploitRecord(source="github", url="https://example.test/poc", maturity="poc")],
        "risk_score": 97.0,
        "risk_level": "critical",
        "risk_breakdown": {"cvss": 45.0, "epss": 23.5, "kev": 15.0, "poc": 7.5},
        "attack_chain": AttackChain(
            steps=[
                AttackChainStep(
                    order=1,
                    technique_id="t1190",
                    tactic="initial-access",
                    stage="Exploitation",
                    description="利用命令注入获得执行",
                    preconditions=["目标可达"],
                ),
                AttackChainStep(
                    order=2,
                    technique_id="T1059",
                    tactic="execution",
                    stage="Execution",
                    description="执行任意命令",
                ),
            ],
            entry_vector="GlobalProtect 接口",
            privileges_required="none",
        ),
        "confidence": 0.82,
        "review_status": "auto_pass",
        "agent_trace": [],
        "model_used": "deepseek-chat",
        "enriched_at": utc_now(),
    }
    payload.update(overrides)
    return EnrichedVuln(**payload)


def node_keys(result: ExtractionResult, label: str) -> set[str]:
    """返回某标签的节点键集合（测试辅助）。"""
    return {node.key for node in result.nodes if node.label == label}


def edge_tuples(result: ExtractionResult, relation: str) -> list[tuple[str, str]]:
    """返回某关系类型的 ``(起点键, 终点键)`` 列表（测试辅助）。"""
    return [(edge.start_key, edge.end_key) for edge in result.edges if edge.relation == relation]


class TestNodeExtraction:
    """节点抽取（6 类标签）。"""

    def test_node_counts(self) -> None:
        """默认夹具产出 6 类节点，数量符合各维度输入。"""
        result = extract_graph(make_enriched())
        assert result.node_counts() == {
            "Asset": 1,
            "AttackTechnique": 2,
            "Component": 2,
            "Paper": 1,
            "Patch": 2,
            "Vulnerability": 1,
        }

    def test_vulnerability_node_keeps_risk_fields(self) -> None:
        """``Vulnerability`` 节点带风险 / KEV 等关键属性，``None`` 属性被剔除。"""
        result = extract_graph(make_enriched())
        node = next(item for item in result.nodes if item.label == schema.NODE_VULNERABILITY)
        assert node.key == "CVE-2024-3400"
        assert node.properties["risk_level"] == "critical"
        assert node.properties["risk_score"] == 97.0
        assert node.properties["kev"] is True
        assert "published_at" not in node.properties

    def test_component_nodes_from_cpe_and_ecosystem(self) -> None:
        """组件节点来自 CPE（``vendor:product``）与生态包（``PyPI:ollama``）。"""
        result = extract_graph(make_enriched())
        assert node_keys(result, schema.NODE_COMPONENT) == {"paloaltonetworks:pan-os", "PyPI:ollama"}

    def test_asset_paper_and_technique_nodes(self) -> None:
        """资产 / 论文 / ATT&CK 技术节点键正确（技术 ID 统一大写）。"""
        result = extract_graph(make_enriched())
        assert node_keys(result, schema.NODE_ASSET) == {"service:GlobalProtect Gateway"}
        assert node_keys(result, schema.NODE_PAPER) == {"2404.12345"}
        assert node_keys(result, schema.NODE_ATTACK_TECHNIQUE) == {"T1190", "T1059"}

    def test_patch_nodes_only_for_patch_like_references(self) -> None:
        """补丁节点只来自 patch/advisory 标记或 URL 特征命中者。"""
        result = extract_graph(make_enriched())
        assert node_keys(result, schema.NODE_PATCH) == {PATCH_URL, ADVISORY_URL}

    def test_no_none_properties_anywhere(self) -> None:
        """任何节点/边属性都不含 ``None``（Neo4j 会拒绝写入）。"""
        result = extract_graph(make_enriched())
        for node in result.nodes:
            assert all(value is not None for value in node.properties.values()), node
        for edge in result.edges:
            assert all(value is not None for value in edge.properties.values()), edge

    def test_nodes_are_sorted_and_deduplicated(self) -> None:
        """节点按 ``(label, key)`` 排序且无重复键。"""
        result = extract_graph(make_enriched())
        keys = [(node.label, node.key) for node in result.nodes]
        assert keys == sorted(keys)
        assert len(keys) == len(set(keys))


class TestEdgeExtraction:
    """关系抽取（5 类）。"""

    def test_edge_counts(self) -> None:
        """默认夹具的 5 类关系数量正确（2 组件 × 1 资产 → 2 条 INSTALLED_ON）。"""
        result = extract_graph(make_enriched())
        assert result.edge_counts() == {
            "AFFECTS": 2,
            "EXPLOITS": 2,
            "FIXED_BY": 2,
            "INSTALLED_ON": 2,
            "RELATED_TO": 1,
        }

    def test_affects_edges_point_to_components(self) -> None:
        """``Vulnerability -[AFFECTS]-> Component`` 端点与版本区间属性正确。"""
        result = extract_graph(make_enriched())
        edges = [edge for edge in result.edges if edge.relation == schema.RELATION_AFFECTS]
        assert {edge.end_key for edge in edges} == {"paloaltonetworks:pan-os", "PyPI:ollama"}
        assert all(edge.start_label == "Vulnerability" and edge.end_label == "Component" for edge in edges)
        pan_os = next(edge for edge in edges if edge.end_key == "paloaltonetworks:pan-os")
        assert pan_os.properties["version_range"] == "<10.2.9-h1"

    def test_installed_on_edges_are_marked_as_inferred(self) -> None:
        """``Component -[INSTALLED_ON]-> Asset`` 边标注推断来源（非精确 SBOM）。"""
        result = extract_graph(make_enriched())
        edges = [edge for edge in result.edges if edge.relation == schema.RELATION_INSTALLED_ON]
        assert edge_tuples(result, schema.RELATION_INSTALLED_ON) == [
            ("PyPI:ollama", "service:GlobalProtect Gateway"),
            ("paloaltonetworks:pan-os", "service:GlobalProtect Gateway"),
        ]
        assert all(edge.properties["derived_from"] == COOCCURRENCE_SOURCE for edge in edges)

    def test_related_to_carries_relation_and_confidence(self) -> None:
        """``RELATED_TO`` 边携带关联类型与置信度（供查询排序）。"""
        result = extract_graph(make_enriched())
        edge = next(edge for edge in result.edges if edge.relation == schema.RELATION_RELATED_TO)
        assert edge.end_key == "2404.12345"
        assert edge.properties == {
            "relation": "proposes-attack",
            "confidence": 0.8,
            "evidence_refs": ["trace-1"],
        }

    def test_exploits_edges_are_ordered(self) -> None:
        """``EXPLOITS`` 边携带 ``order``（攻击链顺序）。"""
        result = extract_graph(make_enriched())
        orders = sorted(
            edge.properties["order"] for edge in result.edges if edge.relation == schema.RELATION_EXPLOITS
        )
        assert orders == [1, 2]

    def test_fixed_by_edges_point_to_patches(self) -> None:
        """``FIXED_BY`` 边指向补丁节点，标签属性被保留。"""
        result = extract_graph(make_enriched())
        edges = [edge for edge in result.edges if edge.relation == schema.RELATION_FIXED_BY]
        assert {edge.end_key for edge in edges} == {PATCH_URL, ADVISORY_URL}
        assert next(edge for edge in edges if edge.end_key == PATCH_URL).properties["tags"] == [
            "vendor-advisory"
        ]

    def test_edges_are_deduplicated(self) -> None:
        """同一 URL 被多渠道引用时不产生重复边/重复节点。"""
        enriched = make_enriched(
            references=[
                Reference(url=ADVISORY_URL, source="nvd", tags=["patch"]),
                Reference(url=ADVISORY_URL, source="ghsa", tags=[]),
            ]
        )
        result = extract_graph(enriched)
        assert result.edge_counts()["FIXED_BY"] == 1
        assert node_keys(result, schema.NODE_PATCH) == {ADVISORY_URL}

    def test_edges_are_sorted(self) -> None:
        """边按 ``(关系, 起点标签, 起点键, 终点标签, 终点键)`` 排序，结果可复现。"""
        result = extract_graph(make_enriched())
        keys = [
            (edge.relation, edge.start_label, edge.start_key, edge.end_label, edge.end_key)
            for edge in result.edges
        ]
        assert keys == sorted(keys)


class TestPurityAndEdgeCases:
    """纯函数性（可重复、不改入参）与缺维度边界。"""

    def test_extraction_is_deterministic(self) -> None:
        """同一输入两次抽取结果完全一致（无隐藏状态）。"""

        def snapshot(result: ExtractionResult) -> tuple[Any, Any]:
            nodes = [(node.label, node.key, sorted(node.properties.items())) for node in result.nodes]
            edges = [
                (
                    edge.relation,
                    edge.start_label,
                    edge.start_key,
                    edge.end_label,
                    edge.end_key,
                    sorted(edge.properties.items()),
                )
                for edge in result.edges
            ]
            return nodes, edges

        enriched = make_enriched()
        assert snapshot(extract_graph(enriched)) == snapshot(extract_graph(enriched))

    def test_input_is_not_mutated(self) -> None:
        """抽取不修改入参（纯函数契约）。"""
        enriched = make_enriched()
        before = enriched.model_dump(mode="json")
        extract_graph(enriched)
        assert enriched.model_dump(mode="json") == before

    def test_minimal_vuln_yields_only_root_node(self) -> None:
        """无任何富化维度时只产出 ``Vulnerability`` 节点、无边。"""
        enriched = make_enriched(
            cpe_matches=[],
            ecosystem_packages=[],
            affected_assets=[],
            related_papers=[],
            attack_chain=None,
            references=[],
        )
        result = extract_graph(enriched)
        assert result.node_counts() == {"Vulnerability": 1}
        assert result.edges == []
        assert result.vuln_id == "CVE-2024-3400"

    def test_summary_reports_counts(self) -> None:
        """``summary`` 同时给出节点与边的分类计数。"""
        summary = extract_graph(make_enriched()).summary()
        assert "节点=9" in summary and "边=9" in summary


class TestHelpers:
    """辅助纯函数。"""

    def test_summarize_properties_drops_none_and_empty(self) -> None:
        """``None`` / 空列表 / 空字典被剔除，其它值保留。"""
        assert summarize_properties({"a": None, "b": [], "c": {}, "d": 0, "e": [1]}) == {"d": 0, "e": [1]}

    def test_is_patch_reference_by_tag_and_url(self) -> None:
        """标签命中或 URL 特征命中都算补丁来源。"""
        assert is_patch_reference(Reference(url="https://example.test/x", source="nvd", tags=["PATCH"])) is True
        assert is_patch_reference(Reference(url=ADVISORY_URL, source="ghsa")) is True
        assert is_patch_reference(Reference(url=BLOG_URL, source="nvd", tags=["exploit"])) is False

    def test_render_version_range(self) -> None:
        """CPE 边界渲染为可读区间；全空返回 ``None``。"""
        cpe = CpeMatch(vendor="v", product="p", version_start_incl="1.0", version_end_excl="2.0")
        assert render_version_range(cpe) == ">=1.0, <2.0"
        assert render_version_range(CpeMatch(vendor="v", product="p")) is None

    def test_split_ecosystem_package(self) -> None:
        """``生态:包名`` 拆分；无前缀时生态为 ``None``。"""
        assert split_ecosystem_package("PyPI:ollama") == ("PyPI", "ollama")
        assert split_ecosystem_package("ollama") == (None, "ollama")

    def test_graph_node_and_edge_are_plain_dataclasses(self) -> None:
        """节点/边是简单数据类（方便仓储层与测试直接构造）。"""
        node = GraphNode(label="Paper", key="2404.1")
        edge = GraphEdge(
            relation="RELATED_TO",
            start_label="Vulnerability",
            start_key="CVE-2024-3400",
            end_label="Paper",
            end_key="2404.1",
        )
        assert node.properties == {} and edge.properties == {}


def _wide_assets(count: int) -> list[AffectedAsset]:
    """构造 ``count`` 个置信度递增的资产（模拟 Log4Shell 宽口径 CPE 场景）。"""
    return [
        AffectedAsset(
            asset_type="library",
            name=f"asset-{index:03d}",
            confidence=round(0.1 + index / 1000, 3),
            evidence_refs=["trace-1"],
        )
        for index in range(count)
    ]


class TestInstalledOnCap:
    """Day11 任务 1.2：``INSTALLED_ON`` 单组件边数上限（图谱边爆炸修复）。"""

    @pytest.mark.parametrize(
        ("asset_count", "limit", "expected_edges"),
        [(10, 50, 10), (60, 0, 50), (60, 5, 5), (144, 50, 50)],
    )
    def test_edges_capped_per_component(self, asset_count: int, limit: int, expected_edges: int) -> None:
        """单组件连出的 ``INSTALLED_ON`` 边数不超过上限（``0`` 表示用默认 50）。"""
        enriched = make_enriched(
            cpe_matches=[CpeMatch(vendor="apache", product="log4j", version_end_excl="2.16.0")],
            ecosystem_packages=[],
            affected_assets=_wide_assets(asset_count),
        )
        result = extract_graph(enriched, installed_on_max_per_component=limit)
        installed_on = [edge for edge in result.edges if edge.relation == "INSTALLED_ON"]
        assert len(installed_on) == expected_edges

    def test_cap_keeps_highest_confidence_assets(self) -> None:
        """截断保留置信度最高的资产（按 confidence 降序）。"""
        enriched = make_enriched(
            cpe_matches=[CpeMatch(vendor="apache", product="log4j")],
            ecosystem_packages=[],
            affected_assets=_wide_assets(20),
        )
        result = extract_graph(enriched, installed_on_max_per_component=3)
        keys = {edge.end_key for edge in result.edges if edge.relation == "INSTALLED_ON"}
        assert keys == {"library:asset-019", "library:asset-018", "library:asset-017"}

    def test_nodes_not_truncated_only_edges(self) -> None:
        """上限只作用于边：``Asset`` 节点仍完整保留（保留审计能力）。"""
        enriched = make_enriched(
            cpe_matches=[CpeMatch(vendor="apache", product="log4j")],
            ecosystem_packages=[],
            affected_assets=_wide_assets(20),
        )
        counts = extract_graph(enriched, installed_on_max_per_component=2).node_counts()
        assert counts["Asset"] == 20

    def test_top_assets_helper_is_deterministic(self) -> None:
        """辅助纯函数：同置信度时按节点键升序，保证可复现。"""
        from aisec_intel.graph.extractor import top_assets_for_component

        nodes = [
            GraphNode(label="Asset", key=f"library:a{index}", properties={"confidence": 0.5}) for index in range(5)
        ]
        picked = top_assets_for_component(nodes, limit=2)
        assert [node.key for node in picked] == ["library:a0", "library:a1"]
