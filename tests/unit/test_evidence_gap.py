"""Day25 阶段 1：证据缺口检测单元测试（``aisec_intel.qa.evidence_gap``）。

覆盖「测试范围硬约束」要求的两类：
    1. **纯函数算法**：事实抽取（标记 / 结构化 token / 元数据键）、必需事实推导、缺口判定；
    2. **Agent 编排逻辑**：``GapChecker`` 节点的状态增量与异常兜底（无 LLM、无网络）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.qa import evidence_gap as eg
from aisec_intel.qa.state import QueryEntities, QueryIntent, RetrievalResult, new_qa_state


def _intent(
    query: str,
    *,
    intent: str = "vuln_lookup",
    cve_ids: list[str] | None = None,
    components: list[str] | None = None,
    keywords: list[str] | None = None,
) -> QueryIntent:
    """构造查询意图（测试夹具）。"""
    return QueryIntent(
        query=query,
        intent=intent,  # type: ignore[arg-type]
        entities=QueryEntities(
            cve_ids=cve_ids or [],
            components=components or [],
            keywords=keywords or [],
        ),
        rewritten_query=query,
        confidence=0.8,
    )


def _result(
    *, content: str = "", cve: str | None = None, doc_id: str | None = None, **metadata: Any
) -> RetrievalResult:
    """构造检索结果（测试夹具）。"""
    payload: dict[str, Any] = dict(metadata)
    if cve:
        payload["cve_id"] = cve
    return RetrievalResult(
        source="graph",
        doc_id=doc_id or f"doc:{cve or 'x'}",
        content=content,
        metadata=payload,
    )


class TestFactExtraction:
    """纯函数：文本标记 / 结构化 token / 元数据键三路事实抽取。"""

    def test_text_markers_and_tokens(self) -> None:
        """渲染口径标记与结构化 token 都能命中（URL 不误判为组件）。"""
        assert eg.facts_in_text("修复版本: 0.2.72") == {"fixed_version"}
        assert eg.facts_in_text("官方补丁/公告: https://x/patch") == {"vendor_advisory"}
        assert eg.facts_in_text("受影响版本: paloaltonetworks:pan-os ==10.2.0") == {
            "affected_components",
            "affected_versions",
        }
        assert eg.facts_in_text("攻击技术: T1190(initial-access)") == {"attack_techniques"}
        assert eg.facts_in_text("CISA KEV: exploited in the wild") == {"kev"}
        assert eg.facts_in_text("EPSS: 0.94") == {"epss"}
        assert eg.facts_in_text("") == set()
        assert "affected_components" not in eg.facts_in_text("见 https://github.com/advisories/x")

    def test_metadata_channel(self) -> None:
        """元数据键（高精度通道）：``kev`` / ``cpe_matches`` / 修复版本字段。"""
        assert eg.facts_in_evidence([_result(kev="true")]) == {"kev"}
        assert eg.facts_in_evidence([_result(cpe_matches=[{"product": "pan-os"}])]) == {"affected_components"}
        assert eg.facts_in_evidence([_result(fixed_versions=["0.2.72"])]) == {"fixed_version"}
        assert eg.facts_in_evidence([_result(kev="false", epss_score=0.0)]) == set()

    def test_metadata_and_content_union(self) -> None:
        """元数据与正文取并集（同一批证据汇总）。"""
        items = [
            _result(content="受影响版本: pan-os >=10.2.0", cve="CVE-2024-3400"),
            _result(content="攻击技术: T1190", cve="CVE-2024-3400"),
        ]
        assert eg.facts_in_evidence(items) == {"affected_versions", "attack_techniques"}


class TestRequiredFacts:
    """纯函数：按意图 / 问法推导必需事实。"""

    @pytest.mark.parametrize(
        ("query", "intent", "cve_ids", "expected"),
        [
            (
                "CVE-2024-34359 应升级到哪个版本",
                "remediation",
                ["CVE-2024-34359"],
                ["fixed_version", "vendor_advisory"],
            ),
            (
                "CVE-2024-3400 影响哪些资产",
                "asset_lookup",
                ["CVE-2024-3400"],
                ["affected_components", "affected_versions"],
            ),
            ("CVE-2024-3400 的攻击链是什么", "attack_chain", ["CVE-2024-3400"], ["attack_techniques"]),
            ("CVE-2024-3400 是否在野被利用", "vuln_lookup", ["CVE-2024-3400"], ["kev", "epss"]),
            ("介绍一下这个漏洞", "general", [], []),
        ],
    )
    def test_rules(self, query: str, intent: str, cve_ids: list[str], expected: list[str]) -> None:
        """四类问法 + 通用问句的必需事实（顺序稳定）。"""
        assert eg.required_facts_for(_intent(query, intent=intent, cve_ids=cve_ids)) == expected

    def test_intent_and_keywords_union(self) -> None:
        """意图与关键词取并集（问「影响哪些资产，怎么修复」时两类事实都要）。"""
        intent = _intent("CVE-2024-3400 影响哪些资产，应该怎么修复", intent="remediation")
        assert eg.required_facts_for(intent) == [
            "fixed_version",
            "vendor_advisory",
            "affected_components",
            "affected_versions",
        ]


class TestDetectGaps:
    """纯函数：缺口判定与 ``has_enough`` 口径。"""

    def test_remediation_gap_then_filled(self) -> None:
        """缺修复版本 → has_enough=False；补上修复文本后 → True。"""
        intent = _intent("CVE-2024-34359 应升级到哪个版本", intent="remediation", cve_ids=["CVE-2024-34359"])
        empty = eg.detect_gaps(intent, [])
        assert empty.missing == ["fixed_version", "vendor_advisory"]
        assert empty.has_enough is False and empty.missing_labels == ["修复版本", "厂商公告/补丁"]
        assert empty.lacks_fixed_version is True

        partial = eg.detect_gaps(intent, [_result(content="CVE-2024-34359 fsspec 模板注入")])
        assert partial.missing == ["fixed_version", "vendor_advisory"]

        filled = eg.detect_gaps(
            intent,
            [_result(content="修复版本: 0.2.72\n官方补丁/公告: https://github.com/advisories/GHSA-x")],
        )
        assert filled.has_enough is True
        assert filled.satisfied == ["fixed_version", "vendor_advisory"]

    def test_asset_question_local_sufficient(self) -> None:
        """本地同时有组件与版本 → 资产类问题不缺证据（不触发外部检索）。"""
        intent = _intent("CVE-2024-3400 影响哪些资产", intent="asset_lookup", cve_ids=["CVE-2024-3400"])
        local = _result(content="受影响版本: paloaltonetworks:pan-os ==10.2.0", cve="CVE-2024-3400")
        report = eg.detect_gaps(intent, [local])
        assert report.has_enough is True and report.missing == []

    def test_no_requirement_paths(self) -> None:
        """无强制事实：有证据即足够；无证据但有 CVE 实体 → 不足；两者皆无 → 足够。"""
        assert eg.detect_gaps(_intent("随便问问"), [_result(content="x")]).has_enough is True
        assert eg.detect_gaps(_intent("CVE-2024-3400 怎么样", cve_ids=["CVE-2024-3400"]), []).has_enough is False
        assert eg.detect_gaps(_intent("你好"), []).has_enough is True

    def test_union_of_fused_and_raw_evidence(self) -> None:
        """融合代表会遮蔽结构化事实：缺口检测必须看「融合 + 各路原始」的并集。"""
        fused = _result(
            content="CVE-2024-3400 -[EXPLOITS]-> execution（多跳路径，较长文本）", doc_id="multi_hop:CVE-2024-3400"
        )
        raw_graph = _result(
            content="CVE-2024-3400 结构摘要\\n受影响版本: paloaltonetworks:pan-os ==10.2.0",
            doc_id="graph:CVE-2024-3400",
        )
        merged = eg.unique_evidence([fused, raw_graph, raw_graph])
        assert len(merged) == 2  # ``doc_id`` 去重

        intent = _intent("CVE-2024-3400 影响哪些资产", intent="asset_lookup", cve_ids=["CVE-2024-3400"])
        assert eg.detect_gaps(intent, [fused]).has_enough is False  # 只看融合代表 → 缺版本
        assert eg.detect_gaps(intent, merged).has_enough is True  # 看全量 → 事实齐备


class TestGapCheckerNode:
    """节点行为：状态增量 / 缺口留痕 / 开关。"""

    async def test_node_payload_and_trace(self) -> None:
        """写入 ``gap_report`` 并在缺口时留痕（errors）。"""
        state = new_qa_state("CVE-2024-34359 应升级到哪个版本")
        state["intent"] = _intent(
            "CVE-2024-34359 应升级到哪个版本", intent="remediation", cve_ids=["CVE-2024-34359"]
        )
        state["fused"] = [_result(content="CVE-2024-34359 fsspec 模板注入", cve="CVE-2024-34359")]
        payload = await eg.GapChecker()(state)
        report = payload["gap_report"]
        assert report.has_enough is False and report.evidence_count == 1
        assert payload["errors"][0].startswith(eg.AGENT_NAME)

    async def test_node_missing_intent_and_disabled(self) -> None:
        """缺 intent 时报错；关闭开关时恒判「足够」。"""
        assert "缺少 intent" in (await eg.GapChecker()(new_qa_state("q")))["errors"][0]
        state = new_qa_state("x")
        state["intent"] = _intent("x", intent="remediation", cve_ids=["CVE-2024-34359"])
        payload = await eg.GapChecker(enabled=False)(state)
        assert payload["gap_report"].has_enough is True
        assert payload["gap_report"].rationale == "缺口检测未启用"

