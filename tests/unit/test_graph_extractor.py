"""Day9 图谱抽取器单元测试（``aisec_intel.graph.extractor``，PROJECT_PLAN.md §5.7）。

抽取器是**纯函数**（零 IO、零 LLM），因此全部用例离线：

1. ``EnrichedVuln`` → 6 类节点 + 5 类关系映射正确；
2. 幂等 / 确定性：同一输入两次抽取结果完全一致，且不修改入参；
3. 边界：缺维度时只产出对应节点/边；``None`` 属性被剔除（Neo4j 不接受 ``None``）；
4. Day11 容量保护：单组件 ``INSTALLED_ON`` 边上限；
5. **Day12 任务 1.1**：单漏洞 ``Component`` 上限（默认 5）+ 厂商一致性过滤。

Note:
    Day12 任务 2 合并：原 31 个用例按「同类行为一个函数 + 多组输入循环」压到 14 个，
    覆盖率口径不变（节点/边映射、排序去重、纯函数性、两处限流全部保留）。
"""

from __future__ import annotations

from typing import Any

from aisec_intel.graph import schema
from aisec_intel.graph.extractor import (
    COOCCURRENCE_SOURCE,
    CPE_COMPONENT_CONFIDENCE,
    DEFAULT_COMPONENT_MAX_PER_VULN,
    ECOSYSTEM_COMPONENT_CONFIDENCE,
    ExtractionResult,
    GraphEdge,
    GraphNode,
    component_nodes,
    cpe_vendors,
    extract_graph,
    is_patch_reference,
    render_version_range,
    select_components,
    split_ecosystem_package,
    summarize_properties,
    top_assets_for_component,
    vendor_consistent,
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
    }

    payload.update(
        {
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
            "exploits": [
                ExploitRecord(source="github", url="https://example.test/poc", maturity="poc")
            ],
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
    )
    payload.update(overrides)
    return EnrichedVuln(**payload)


def node_keys(result: ExtractionResult, label: str) -> set[str]:
    """返回某标签的节点键集合（测试辅助）。"""
    return {node.key for node in result.nodes if node.label == label}


def edge_tuples(result: ExtractionResult, relation: str) -> list[tuple[str, str]]:
    """返回某关系类型的 ``(起点键, 终点键)`` 列表（测试辅助）。"""
    return [(edge.start_key, edge.end_key) for edge in result.edges if edge.relation == relation]


def snapshot(result: ExtractionResult) -> tuple[Any, Any]:
    """把抽取结果转成可比较的快照（测试辅助）。"""
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


def _wide_cpes(count: int, *, vendor: str = "apache") -> list[CpeMatch]:
    """构造 ``count`` 个同厂商 CPE（模拟 NVD ``configurations`` 展开的宽口径组件）。"""
    return [CpeMatch(vendor=vendor, product=f"log4j-{index:03d}") for index in range(count)]


class TestExtraction:
    """节点 / 边映射与结果不变式（原 12 个用例合并为 7 个）。"""

    def test_node_and_edge_counts_match_inputs(self) -> None:
        """默认夹具的 6 类节点、5 类关系数量与 ``summary`` 文本一致。"""
        result = extract_graph(make_enriched())
        assert result.node_counts() == {
            "Asset": 1,
            "AttackTechnique": 2,
            "Component": 2,
            "Paper": 1,
            "Patch": 2,
            "Vulnerability": 1,
        }
        assert result.edge_counts() == {
            "AFFECTS": 2,
            "EXPLOITS": 2,
            "FIXED_BY": 2,
            "INSTALLED_ON": 2,
            "RELATED_TO": 1,
        }
        assert "节点=9" in result.summary() and "边=9" in result.summary()

    def test_node_keys_by_label(self) -> None:
        """各标签节点键正确：CPE / 生态包 / 资产 / 论文 / ATT&CK（大写）/ 补丁。"""
        result = extract_graph(make_enriched())
        expected: dict[str, set[str]] = {
            schema.NODE_VULNERABILITY: {"CVE-2024-3400"},
            schema.NODE_COMPONENT: {"paloaltonetworks:pan-os", "PyPI:ollama"},
            schema.NODE_ASSET: {"service:GlobalProtect Gateway"},
            schema.NODE_PAPER: {"2404.12345"},
            schema.NODE_ATTACK_TECHNIQUE: {"T1190", "T1059"},
            schema.NODE_PATCH: {PATCH_URL, ADVISORY_URL},
        }
        for label, keys in expected.items():
            assert node_keys(result, label) == keys, label

    def test_vulnerability_node_properties(self) -> None:
        """``Vulnerability`` 节点带风险 / KEV 等关键属性，``None`` 属性被剔除。"""
        node = next(
            item
            for item in extract_graph(make_enriched()).nodes
            if item.label == schema.NODE_VULNERABILITY
        )
        assert node.key == "CVE-2024-3400"
        assert node.properties["risk_level"] == "critical"
        assert node.properties["risk_score"] == 97.0
        assert node.properties["kev"] is True
        assert "published_at" not in node.properties

    def test_no_none_property_anywhere(self) -> None:
        """任何节点/边属性都不含 ``None``（Neo4j 会拒绝写入）。"""
        result = extract_graph(make_enriched())
        for node in result.nodes:
            assert all(value is not None for value in node.properties.values()), node
        for edge in result.edges:
            assert all(value is not None for value in edge.properties.values()), edge

    def test_nodes_and_edges_sorted_and_deduplicated(self) -> None:
        """节点/边排序可复现、键唯一；同一 URL 多渠道引用不产生重复边。"""
        result = extract_graph(make_enriched())
        node_pairs = [(node.label, node.key) for node in result.nodes]
        assert node_pairs == sorted(node_pairs)
        assert len(node_pairs) == len(set(node_pairs))
        edge_keys = [
            (edge.relation, edge.start_label, edge.start_key, edge.end_label, edge.end_key)
            for edge in result.edges
        ]
        assert edge_keys == sorted(edge_keys)
        deduped = extract_graph(
            make_enriched(
                references=[
                    Reference(url=ADVISORY_URL, source="nvd", tags=["patch"]),
                    Reference(url=ADVISORY_URL, source="ghsa", tags=[]),
                ]
            )
        )
        assert deduped.edge_counts()["FIXED_BY"] == 1
        assert node_keys(deduped, schema.NODE_PATCH) == {ADVISORY_URL}

    def test_edge_endpoints_and_properties(self) -> None:
        """5 类关系的端点与属性：版本区间 / 推断来源 / 关联类型 / order / 标签。"""
        result = extract_graph(make_enriched())
        affects = [edge for edge in result.edges if edge.relation == schema.RELATION_AFFECTS]
        assert {edge.end_key for edge in affects} == {"paloaltonetworks:pan-os", "PyPI:ollama"}
        assert all(
            edge.start_label == "Vulnerability" and edge.end_label == "Component" for edge in affects
        )
        pan_os = next(edge for edge in affects if edge.end_key == "paloaltonetworks:pan-os")
        assert pan_os.properties["version_range"] == "<10.2.9-h1"

        installed_on = [edge for edge in result.edges if edge.relation == schema.RELATION_INSTALLED_ON]
        assert edge_tuples(result, schema.RELATION_INSTALLED_ON) == [
            ("PyPI:ollama", "service:GlobalProtect Gateway"),
            ("paloaltonetworks:pan-os", "service:GlobalProtect Gateway"),
        ]
        assert all(edge.properties["derived_from"] == COOCCURRENCE_SOURCE for edge in installed_on)

        related = next(edge for edge in result.edges if edge.relation == schema.RELATION_RELATED_TO)
        assert related.end_key == "2404.12345"
        assert related.properties == {
            "relation": "proposes-attack",
            "confidence": 0.8,
            "evidence_refs": ["trace-1"],
        }

        orders = sorted(
            edge.properties["order"]
            for edge in result.edges
            if edge.relation == schema.RELATION_EXPLOITS
        )
        assert orders == [1, 2]

        fixed_by = [edge for edge in result.edges if edge.relation == schema.RELATION_FIXED_BY]
        assert {edge.end_key for edge in fixed_by} == {PATCH_URL, ADVISORY_URL}
        assert next(edge for edge in fixed_by if edge.end_key == PATCH_URL).properties["tags"] == [
            "vendor-advisory"
        ]

    def test_deterministic_and_pure(self) -> None:
        """同一输入两次抽取结果完全一致，且不修改入参（纯函数契约）。"""
        enriched = make_enriched()
        before = enriched.model_dump(mode="json")
        assert snapshot(extract_graph(enriched)) == snapshot(extract_graph(enriched))
        assert enriched.model_dump(mode="json") == before


class TestEdgeCasesAndHelpers:
    """缺维度边界与辅助纯函数。"""

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

    def test_helper_pure_functions(self) -> None:
        """辅助纯函数与数据类行为。

        覆盖 ``summarize_properties`` / ``is_patch_reference`` / ``render_version_range`` /
        ``split_ecosystem_package`` 以及 ``GraphNode`` / ``GraphEdge`` 默认属性。
        """
        assert summarize_properties({"a": None, "b": [], "c": {}, "d": 0, "e": [1]}) == {
            "d": 0,
            "e": [1],
        }
        assert is_patch_reference(Reference(url="https://example.test/x", source="nvd", tags=["PATCH"]))
        assert is_patch_reference(Reference(url=ADVISORY_URL, source="ghsa"))
        assert not is_patch_reference(Reference(url=BLOG_URL, source="nvd", tags=["exploit"]))
        cpe = CpeMatch(vendor="v", product="p", version_start_incl="1.0", version_end_excl="2.0")
        assert render_version_range(cpe) == ">=1.0, <2.0"
        assert render_version_range(CpeMatch(vendor="v", product="p")) is None
        assert split_ecosystem_package("PyPI:ollama") == ("PyPI", "ollama")
        assert split_ecosystem_package("ollama") == (None, "ollama")
        node = GraphNode(label="Paper", key="2404.1")
        edge = GraphEdge(
            relation="RELATED_TO",
            start_label="Vulnerability",
            start_key="CVE-2024-3400",
            end_label="Paper",
            end_key="2404.1",
        )
        assert node.properties == {} and edge.properties == {}


class TestInstalledOnCap:
    """Day11 任务 1.2：``INSTALLED_ON`` 单组件边数上限（图谱边爆炸修复）。"""

    def test_installed_on_edges_capped_per_component(self) -> None:
        """单组件连出的边数不超过上限（``0`` 回退默认 50）。"""
        cases: list[tuple[int, int, int]] = [(10, 50, 10), (60, 0, 50), (60, 5, 5), (144, 50, 50)]
        for asset_count, limit, expected in cases:
            enriched = make_enriched(
                cpe_matches=[CpeMatch(vendor="apache", product="log4j", version_end_excl="2.16.0")],
                ecosystem_packages=[],
                affected_assets=_wide_assets(asset_count),
            )
            result = extract_graph(enriched, installed_on_max_per_component=limit)
            assert len(edge_tuples(result, schema.RELATION_INSTALLED_ON)) == expected, (asset_count, limit)

    def test_cap_keeps_top_confidence_and_full_nodes(self) -> None:
        """截断只作用于边：保留置信度最高的资产，``Asset`` 节点仍完整保留。"""
        enriched = make_enriched(
            cpe_matches=[CpeMatch(vendor="apache", product="log4j")],
            ecosystem_packages=[],
            affected_assets=_wide_assets(20),
        )
        result = extract_graph(enriched, installed_on_max_per_component=3)
        assert {
            edge.end_key for edge in result.edges if edge.relation == schema.RELATION_INSTALLED_ON
        } == {"library:asset-019", "library:asset-018", "library:asset-017"}
        assert extract_graph(enriched, installed_on_max_per_component=2).node_counts()["Asset"] == 20
        nodes = [
            GraphNode(label="Asset", key=f"library:a{index}", properties={"confidence": 0.5})
            for index in range(5)
        ]
        assert [node.key for node in top_assets_for_component(nodes, limit=2)] == [
            "library:a0",
            "library:a1",
        ]


class TestComponentCap:
    """Day12 任务 1.1：单漏洞 ``Component`` 上限 + 厂商一致性过滤。"""

    def test_components_capped_per_vuln(self) -> None:
        """144 个 CPE 组件被截断到 5 个，且 Log4Shell 规模子图的边数 < 100。"""
        assert DEFAULT_COMPONENT_MAX_PER_VULN == 5
        wide = make_enriched(
            cpe_matches=_wide_cpes(144),
            ecosystem_packages=[],
            affected_assets=_wide_assets(10),
        )
        assert len(component_nodes(wide)) == DEFAULT_COMPONENT_MAX_PER_VULN
        assert len(component_nodes(wide, max_components=3)) == 3
        result = extract_graph(wide)
        assert len(edge_tuples(result, schema.RELATION_AFFECTS)) == DEFAULT_COMPONENT_MAX_PER_VULN
        assert len(result.edges) < 100

    def test_vendor_consistency_filter(self) -> None:
        """厂商与 CVE 的 ``cpe_matches`` 不一致的组件被丢弃；无厂商信息者不可判定保留。"""
        enriched = make_enriched(cpe_matches=[CpeMatch(vendor="Apache", product="log4j")])
        assert cpe_vendors(enriched) == frozenset({"apache"})
        apache = GraphNode(label="Component", key="k", properties={"vendor": "apache"})
        oracle = GraphNode(label="Component", key="k", properties={"vendor": "oracle"})
        assert vendor_consistent(apache, frozenset({"apache"}))
        assert not vendor_consistent(oracle, frozenset({"apache"}))
        assert vendor_consistent(GraphNode(label="Component", key="PyPI:ollama"), frozenset({"apache"}))
        assert vendor_consistent(oracle, frozenset())

    def test_component_confidence_and_asset_vendor_priority(self) -> None:
        """组件置信度确定性（CPE=1.0 / 生态包=0.5）；排序优先命中资产厂商者。"""
        enriched = make_enriched(
            cpe_matches=[CpeMatch(vendor="paloaltonetworks", product="pan-os")],
            ecosystem_packages=["PyPI:ollama"],
        )
        nodes = {node.key: node for node in component_nodes(enriched)}
        assert nodes["paloaltonetworks:pan-os"].properties["confidence"] == CPE_COMPONENT_CONFIDENCE
        assert nodes["PyPI:ollama"].properties["confidence"] == ECOSYSTEM_COMPONENT_CONFIDENCE
        picked = select_components(
            list(nodes.values()),
            asset_vendors=frozenset({"paloaltonetworks"}),
            limit=1,
        )
        assert [node.key for node in picked] == ["paloaltonetworks:pan-os"]

