"""Day9 图谱 schema 单元测试（``aisec_intel.graph.schema``，PROJECT_PLAN.md §5.7）。

纯常量与纯函数断言，**不连接 Neo4j**。
"""

from __future__ import annotations

import pytest

from aisec_intel.graph import schema


class TestLabelsAndRelations:
    """节点标签 / 关系类型白名单。"""

    def test_six_node_labels(self) -> None:
        """节点共 6 类：Vulnerability / Component / Asset / Paper / AttackTechnique / Patch。"""
        assert schema.NODE_LABELS == (
            "Vulnerability",
            "Component",
            "Asset",
            "Paper",
            "AttackTechnique",
            "Patch",
        )

    def test_five_relation_types(self) -> None:
        """关系共 5 类（AFFECTS / INSTALLED_ON / RELATED_TO / EXPLOITS / FIXED_BY）。"""
        assert schema.RELATION_TYPES == (
            "AFFECTS",
            "INSTALLED_ON",
            "RELATED_TO",
            "EXPLOITS",
            "FIXED_BY",
        )

    def test_edge_matrix_matches_spec(self) -> None:
        """关系端点与 §5.7 图谱模型一致。"""
        assert schema.EDGE_MATRIX["AFFECTS"] == ("Vulnerability", "Component")
        assert schema.EDGE_MATRIX["INSTALLED_ON"] == ("Component", "Asset")
        assert schema.EDGE_MATRIX["RELATED_TO"] == ("Vulnerability", "Paper")
        assert schema.EDGE_MATRIX["EXPLOITS"] == ("Vulnerability", "AttackTechnique")
        assert schema.EDGE_MATRIX["FIXED_BY"] == ("Vulnerability", "Patch")

    def test_every_relation_endpoint_is_declared(self) -> None:
        """关系两端标签必须都在节点白名单内。"""
        for start, end in schema.EDGE_MATRIX.values():
            assert schema.is_known_label(start) and schema.is_known_label(end)

    def test_whitelist_functions(self) -> None:
        """白名单判定：合法返回 True，非法返回 False。"""
        assert schema.is_known_label("Vulnerability") is True
        assert schema.is_known_label("Vulnerability') DETACH DELETE n //") is False
        assert schema.is_known_relation("FIXED_BY") is True
        assert schema.is_known_relation("DELETES") is False


class TestKeysAndSchema:
    """唯一键、约束与索引。"""

    def test_key_properties_cover_all_labels(self) -> None:
        """每个节点标签都有唯一键属性。"""
        assert set(schema.NODE_KEY_PROPERTIES) == set(schema.NODE_LABELS)
        assert schema.key_property_of("Vulnerability") == "cve_id"
        assert schema.key_property_of("AttackTechnique") == "technique_id"

    def test_unknown_label_raises(self) -> None:
        """未声明标签取键属性时报错（防止拼错标签静默建错节点）。"""
        with pytest.raises(ValueError, match="未声明的节点标签"):
            schema.key_property_of("Bug")

    def test_uniqueness_constraint_per_label(self) -> None:
        """每个标签各有一条唯一性约束，且键属性与 ``NODE_KEY_PROPERTIES`` 一致。"""
        statements = " ".join(schema.CONSTRAINTS)
        for label, key in schema.NODE_KEY_PROPERTIES.items():
            assert f"FOR (n:{label}) REQUIRE n.{key} IS UNIQUE" in statements

    def test_all_statements_are_idempotent(self) -> None:
        """约束与索引都带 ``IF NOT EXISTS``（可重复执行）。"""
        assert all("IF NOT EXISTS" in statement for statement in schema.schema_statements())

    def test_indexes_cover_query_columns(self) -> None:
        """索引覆盖关联查询用到的列（组件名/资产名/风险级别/战术）。"""
        joined = " ".join(schema.INDEXES)
        expected = (
            "(n:Component) ON (n.name)",
            "(n:Asset) ON (n.name)",
            "(n:Vulnerability) ON (n.risk_level)",
            "(n:AttackTechnique) ON (n.tactic)",
        )
        for token in expected:
            assert token in joined

    def test_schema_statements_order(self) -> None:
        """``schema_statements`` 返回「约束在前、索引在后」的完整序列。"""
        statements = schema.schema_statements()
        assert len(statements) == len(schema.CONSTRAINTS) + len(schema.INDEXES)
        assert statements[: len(schema.CONSTRAINTS)] == schema.CONSTRAINTS