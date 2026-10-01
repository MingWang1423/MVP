"""Day10 查询理解 Agent 单元测试（``aisec_intel.qa.agents.query_understander``，§5.8）。

LLM 路径用 conftest 的 ``stub_structured_model`` 桩替换（**不联网**），规则路径为纯函数断言。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.llm.provider import LLMError
from aisec_intel.qa.agents import query_understander as qu
from aisec_intel.qa.state import QueryEntities, QueryFilters, QueryIntent, new_qa_state

CVE_QUERY = "CVE-2024-3400 的攻击链是什么？涉及哪些 ATT&CK 技术 T1190？"
FILTER_QUERY = "最近 30 天有哪些严重的 PAN-OS 命令注入漏洞被在野利用？"
REMEDIATION_QUERY = "Palo Alto Networks 的 PAN-OS 漏洞影响了哪些资产，怎么修复？"


def _settings(**overrides: object) -> Settings:
    """测试配置（不依赖真实密钥 / 网络）。"""
    base: dict[str, object] = {"degraded_mode": False, "llm_api_key": "sk-test-key"}
    base.update(overrides)
    return Settings(**base)


class TestRuleParsing:
    """规则解析（纯函数，离线可复现）。"""

    def test_attack_chain_query(self) -> None:
        """攻击链查询：意图 + CVE + ATT&CK 技术都被抽出。"""
        intent = qu.parse_intent_rules(CVE_QUERY)
        assert intent.intent == "attack_chain"
        assert intent.entities.cve_ids == ["CVE-2024-3400"]
        assert intent.entities.techniques == ["T1190"]
        assert intent.retrieval_plan == ["graph", "multi_hop", "vector"]
        assert intent.parser == "rules"

    def test_filter_query(self) -> None:
        """带时间 / 严重度 / KEV 过滤的漏洞查询（关键词含空格也能匹配）。"""
        intent = qu.parse_intent_rules(FILTER_QUERY)
        assert intent.intent == "vuln_lookup"
        assert intent.entities.components == ["PAN-OS"]
        assert intent.filters.time_range == "recent_30d"
        assert intent.filters.severity == ["CRITICAL"]
        assert intent.filters.kev_only is True

    def test_remediation_query_with_vendor(self) -> None:
        """修复建议查询：厂商（多词大写序列）与组件都被抽出。"""
        intent = qu.parse_intent_rules(REMEDIATION_QUERY)
        assert intent.intent == "remediation"
        assert "Palo Alto Networks" in intent.entities.vendors
        assert "PAN-OS" in intent.entities.components
        assert intent.retrieval_plan == ["vector", "fulltext", "graph"]

    def test_source_filter(self) -> None:
        """来源过滤器（``nvd`` / ``kev`` 等）。"""
        intent = qu.parse_intent_rules("CVE-2024-4577 的修复建议，只看 NVD 和 KEV 来源")
        assert intent.filters.sources == ["nvd", "kev"]
        assert intent.intent == "remediation"

    def test_asset_lookup_query(self) -> None:
        """资产查询意图优先级（资产 > 漏洞）。"""
        intent = qu.parse_intent_rules("CVE-2024-3400 影响了哪些资产和设备？")
        assert intent.intent == "asset_lookup"
        assert intent.retrieval_plan == ["graph", "multi_hop", "fulltext"]

    def test_general_fallback(self) -> None:
        """无任何信号时落到 ``general`` 且置信度为下限。"""
        intent = qu.parse_intent_rules("你好")
        assert intent.intent == "general"
        assert intent.confidence == qu.DEFAULT_MIN_CONFIDENCE
        assert intent.retrieval_plan == list(qu.PLAN_BY_INTENT["general"])

    def test_rewritten_query_keeps_entities(self) -> None:
        """改写 query 保留实体（供检索层使用），不含纯停用词。"""
        intent = qu.parse_intent_rules(CVE_QUERY)
        assert "CVE-2024-3400" in intent.rewritten_query
        assert "T1190" in intent.rewritten_query

    def test_component_detection_rules(self) -> None:
        """组件启发式：PAN-OS（含连字符）/ PHP（全大写）/ log4j（含数字）命中，普通词不命中。"""
        assert qu.looks_like_component("PAN-OS") is True
        assert qu.looks_like_component("log4j") is True
        assert qu.looks_like_component("PHP") is True
        assert qu.looks_like_component("the") is False
        assert qu.looks_like_component("cve-2024-3400") is False

    def test_unique_in_order(self) -> None:
        """去重保序（大小写不敏感）。"""
        assert qu.unique_in_order(["Palo", "palo", "NVD "]) == ["Palo", "NVD"]


class TestPromptAndConstants:
    """提示词与常量（§3.2：``json_mode`` 依赖提示词含 json 字样）。"""

    def test_system_prompt_mentions_json(self) -> None:
        assert "json" in qu.SYSTEM_PROMPT.lower()

    def test_build_prompt_lists_plans(self) -> None:
        prompt = qu.build_prompt(CVE_QUERY)
        assert CVE_QUERY in prompt
        assert "retrieval_plan" in prompt and "vector" in prompt

    def test_contains_any_is_space_insensitive(self) -> None:
        assert qu.contains_any("最近 30 天", ("最近30天",)) is True
        assert qu.contains_any("abc", ("xyz",)) is False


class TestNormalizeIntent:
    """LLM 输出与规则结果的合并（纯函数）。"""

    def test_rule_entities_fill_llm_gaps(self) -> None:
        """LLM 漏抽的 CVE（强格式实体）由规则补齐。"""
        llm = QueryIntent(
            query=CVE_QUERY,
            intent="attack_chain",
            entities=QueryEntities(components=["PAN-OS"]),
            filters=QueryFilters(),
            retrieval_plan=["graph"],
            rewritten_query="",
            confidence=0.7,
            parser="llm",
        )
        merged = qu.normalize_intent(llm, CVE_QUERY)
        assert merged.entities.cve_ids == ["CVE-2024-3400"]
        assert merged.entities.techniques == ["T1190"]
        assert merged.entities.components == ["PAN-OS"]
        assert merged.parser == "llm"

    def test_llm_filters_take_priority(self) -> None:
        """LLM 显式给出的过滤器优先，规则仅兜底。"""
        llm = QueryIntent(
            query=FILTER_QUERY,
            intent="vuln_lookup",
            filters=QueryFilters(time_range="recent_7d", severity=["HIGH"], kev_only=False),
            confidence=0.9,
            parser="llm",
        )
        merged = qu.normalize_intent(llm, FILTER_QUERY)
        assert merged.filters.time_range == "recent_7d"
        assert merged.filters.severity == ["HIGH"]
        assert merged.filters.kev_only is True  # 规则兜底（问题里含「在野」）

    def test_invalid_intent_falls_back_to_rules(self) -> None:
        """非法意图值回退到规则判定（白名单保护）。"""
        llm = QueryIntent(query=REMEDIATION_QUERY, intent="hack_the_planet", confidence=0.9, parser="llm")
        assert qu.normalize_intent(llm, REMEDIATION_QUERY).intent == "remediation"

    def test_empty_plan_filled_from_intent(self) -> None:
        """计划为空时用意图默认计划填满。"""
        llm = QueryIntent(query=CVE_QUERY, intent="attack_chain", retrieval_plan=[], confidence=0.9, parser="llm")
        merged = qu.normalize_intent(llm, CVE_QUERY)
        assert merged.retrieval_plan == list(qu.PLAN_BY_INTENT["attack_chain"])

    def test_illegal_plan_routes_filtered(self) -> None:
        """非法通路被剔除、重复项去重。"""
        llm = QueryIntent(
            query=CVE_QUERY,
            intent="attack_chain",
            retrieval_plan=["graph", "sql", "graph"],
            confidence=0.9,
            parser="llm",
        )
        assert qu.normalize_intent(llm, CVE_QUERY).retrieval_plan == ["graph"]


class TestQueryUnderstander:
    """LLM 优先 + 规则兜底的实际行为（桩模型）。"""

    async def test_llm_success_returns_llm_intent(self, stub_structured_model: type) -> None:
        """LLM 成功时采用其意图，但仍补齐强格式实体。"""
        llm_intent = QueryIntent(
            query=CVE_QUERY,
            intent="attack_chain",
            entities=QueryEntities(components=["PAN-OS"]),
            retrieval_plan=["graph", "multi_hop"],
            rewritten_query="PAN-OS 攻击链",
            confidence=0.85,
            parser="llm",
        )
        model = stub_structured_model([llm_intent])
        agent = qu.QueryUnderstander(structured_llm=model)
        intent = await agent.understand(CVE_QUERY)
        assert intent.parser == "llm" and intent.confidence == 0.85
        assert intent.entities.cve_ids == ["CVE-2024-3400"]  # 规则补齐
        assert agent.last_error is None
        assert model.call_count == 1

    async def test_structured_failure_falls_back_to_rules(self, stub_structured_model: type) -> None:
        """结构化 / 网络失败时回退规则路径，且不抛异常。"""
        model = stub_structured_model([ValueError("模拟解析失败")])
        agent = qu.QueryUnderstander(structured_llm=model, max_retries=0)
        intent = await agent.understand(CVE_QUERY)
        assert intent.parser == "rules"
        assert agent.last_error is not None and "失败" in agent.last_error

    async def test_low_confidence_falls_back(self, stub_structured_model: type) -> None:
        """LLM 置信度低于阈值时回退规则（保持可解释性）。"""
        model = stub_structured_model([QueryIntent(query=CVE_QUERY, intent="general", confidence=0.1, parser="llm")])
        agent = qu.QueryUnderstander(structured_llm=model, min_confidence=0.9)
        intent = await agent.understand(CVE_QUERY)
        assert intent.parser == "rules" and intent.intent == "attack_chain"

    async def test_without_llm_uses_rules(self) -> None:
        """未注入 LLM 时直接走规则路径。"""
        agent = qu.QueryUnderstander(structured_llm=None, use_llm=True)
        assert agent.llm_enabled is False
        assert (await agent.understand(FILTER_QUERY)).parser == "rules"

    async def test_blank_question_uses_rules(self, stub_structured_model: type) -> None:
        """空白问题不调用 LLM（省额度）。"""
        model = stub_structured_model([QueryIntent(query="x")])
        agent = qu.QueryUnderstander(structured_llm=model)
        await agent.understand("   ")
        assert model.call_count == 0

    async def test_langgraph_node_payload(self, stub_structured_model: type) -> None:
        """LangGraph 节点：返回 ``intent`` / ``degraded`` / ``errors`` 增量。"""
        model = stub_structured_model([ValueError("失败")])
        agent = qu.QueryUnderstander(structured_llm=model, max_retries=0)
        payload = await agent.__call__(new_qa_state(REMEDIATION_QUERY))
        assert payload["intent"].intent == "remediation"
        assert payload["degraded"] is True
        assert payload["errors"][0].startswith(qu.AGENT_NAME)


class TestFactory:
    """工厂：开关判定与降级。"""

    def test_disabled_without_llm(self) -> None:
        """``use_llm=False`` 时纯规则路径。"""
        assert qu.build_query_understander(_settings(), use_llm=False).llm_enabled is False

    def test_disabled_in_degraded_mode(self) -> None:
        """降级模式（断网演练）强制规则路径。"""
        assert qu.build_query_understander(_settings(degraded_mode=True)).llm_enabled is False

    def test_disabled_with_placeholder_key(self) -> None:
        """占位 / 空 Key 视为未配置，走规则路径。"""
        assert qu.build_query_understander(_settings(llm_api_key="")).llm_enabled is False

    def test_provider_error_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """provider 构建失败（缺依赖 / 配置非法）时回退规则，不抛异常。"""

        def _boom(settings: Settings) -> Any:
            raise LLMError("模拟缺少 langchain-openai")

        monkeypatch.setattr(qu, "build_provider", _boom)
        assert qu.build_query_understander(_settings()).llm_enabled is False
