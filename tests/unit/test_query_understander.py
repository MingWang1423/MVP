"""Day10 查询理解 Agent 单元测试（``aisec_intel.qa.agents.query_understander``，§5.8）。

LLM 路径用 conftest 的 ``stub_structured_model`` 桩替换（**不联网**），规则路径为纯函数断言。

Note:
    Day12 任务 2 合并：原 27 个用例压到 7 个（多组输入循环 + 同类断言合并），
    并补上 Day12 任务 6 的会话上下文注入断言。
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

    def test_rule_intents_filters_and_plans(self) -> None:
        """五类意图判定、实体抽取（CVE / 组件 / 厂商 / 技术 ID）、过滤与检索计划。"""
        cases: list[tuple[str, str, list[str]]] = [
            (CVE_QUERY, "attack_chain", list(qu.PLAN_BY_INTENT["attack_chain"])),
            (FILTER_QUERY, "vuln_lookup", list(qu.PLAN_BY_INTENT["vuln_lookup"])),
            (REMEDIATION_QUERY, "remediation", list(qu.PLAN_BY_INTENT["remediation"])),
            ("CVE-2024-3400 影响了哪些资产和设备？", "asset_lookup", list(qu.PLAN_BY_INTENT["asset_lookup"])),
            ("你好", "general", list(qu.PLAN_BY_INTENT["general"])),
        ]
        for question, expected_intent, expected_plan in cases:
            intent = qu.parse_intent_rules(question)
            assert intent.intent == expected_intent, question
            assert intent.retrieval_plan == expected_plan, question
            assert intent.parser == "rules"

        attack = qu.parse_intent_rules(CVE_QUERY)
        assert attack.entities.cve_ids == ["CVE-2024-3400"]
        assert attack.entities.techniques == ["T1190"]
        filtered = qu.parse_intent_rules(FILTER_QUERY)
        assert filtered.entities.components == ["PAN-OS"]
        assert filtered.filters.time_range == "recent_30d"
        assert filtered.filters.severity == ["CRITICAL"]
        assert filtered.filters.kev_only is True
        remediation = qu.parse_intent_rules(REMEDIATION_QUERY)
        assert "Palo Alto Networks" in remediation.entities.vendors
        assert "PAN-OS" in remediation.entities.components
        assert qu.parse_intent_rules("CVE-2024-4577 的修复建议，只看 NVD 和 KEV 来源").filters.sources == [
            "nvd",
            "kev",
        ]
        assert qu.parse_intent_rules("你好").confidence == qu.DEFAULT_MIN_CONFIDENCE

    def test_rewritten_query_and_helpers(self) -> None:
        """改写 query 保留实体；组件启发式与去重保序。"""
        intent = qu.parse_intent_rules(CVE_QUERY)
        assert "CVE-2024-3400" in intent.rewritten_query and "T1190" in intent.rewritten_query
        for token, expected in (
            ("PAN-OS", True),
            ("log4j", True),
            ("PHP", True),
            ("the", False),
            ("cve-2024-3400", False),
        ):
            assert qu.looks_like_component(token) is expected, token
        assert qu.unique_in_order(["Palo", "palo", "NVD "]) == ["Palo", "NVD"]

    def test_prompt_helpers_and_session_context(self) -> None:
        """提示词含 json 与计划说明；``contains_any`` 忽略空格；会话上下文注入（Day12 任务 6）。"""
        assert "json" in qu.SYSTEM_PROMPT.lower()
        prompt = qu.build_prompt(CVE_QUERY)
        assert CVE_QUERY in prompt and "retrieval_plan" in prompt and "vector" in prompt
        assert qu.contains_any("最近 30 天", ("最近30天",)) is True
        assert qu.contains_any("abc", ("xyz",)) is False
        assert qu.normalize_session_context(["  ", "", "a"]) == ["a"]
        assert qu.normalize_session_context([f"h{index}" for index in range(10)]) == [
            f"h{index}" for index in range(10 - qu.SESSION_CONTEXT_MAX_ITEMS, 10)
        ]
        assert len(qu.normalize_session_context(["x" * 500])[0]) == qu.SESSION_CONTEXT_ITEM_CHARS
        contextual = qu.build_prompt(CVE_QUERY, context=["上一轮问题：PAN-OS 漏洞"])
        assert "会话历史" in contextual and "上一轮问题：PAN-OS 漏洞" in contextual
        assert "会话历史" not in prompt


class TestNormalizeIntent:
    """LLM 输出与规则结果的合并（纯函数）。"""

    def test_merge_rules_and_llm(self) -> None:
        """规则补齐强格式实体；LLM 过滤器优先且规则兜底；非法意图 / 通路被白名单拦下。"""
        llm = QueryIntent(
            query=CVE_QUERY,
            intent="attack_chain",
            entities=QueryEntities(components=["PAN-OS"]),
            filters=QueryFilters(),
            retrieval_plan=["graph", "sql", "graph"],
            rewritten_query="",
            confidence=0.7,
            parser="llm",
        )
        merged = qu.normalize_intent(llm, CVE_QUERY)
        assert merged.entities.cve_ids == ["CVE-2024-3400"]
        assert merged.entities.techniques == ["T1190"]
        assert merged.entities.components == ["PAN-OS"]
        assert merged.parser == "llm"
        assert merged.retrieval_plan == ["graph"]  # 非法通路剔除 + 去重

        filtered = qu.normalize_intent(
            QueryIntent(
                query=FILTER_QUERY,
                intent="vuln_lookup",
                filters=QueryFilters(time_range="recent_7d", severity=["HIGH"], kev_only=False),
                confidence=0.9,
                parser="llm",
            ),
            FILTER_QUERY,
        )
        assert filtered.filters.time_range == "recent_7d"
        assert filtered.filters.severity == ["HIGH"]
        assert filtered.filters.kev_only is True  # 规则兜底（问题里含「在野」）

        illegal = QueryIntent(query=REMEDIATION_QUERY, intent="hack_the_planet", confidence=0.9, parser="llm")
        assert qu.normalize_intent(illegal, REMEDIATION_QUERY).intent == "remediation"
        empty_plan = QueryIntent(query=CVE_QUERY, intent="attack_chain", retrieval_plan=[], parser="llm")
        assert qu.normalize_intent(empty_plan, CVE_QUERY).retrieval_plan == list(
            qu.PLAN_BY_INTENT["attack_chain"]
        )


class TestQueryUnderstander:
    """LLM 优先 + 规则兜底的实际行为（桩模型）。"""

    async def test_llm_success_backfills_entities(self, stub_structured_model: Any) -> None:
        """LLM 成功时采用其意图，但仍补齐强格式实体。"""
        model = stub_structured_model(
            [
                QueryIntent(
                    query=CVE_QUERY,
                    intent="attack_chain",
                    entities=QueryEntities(components=["PAN-OS"]),
                    retrieval_plan=["graph", "multi_hop"],
                    rewritten_query="PAN-OS 攻击链",
                    confidence=0.85,
                    parser="llm",
                )
            ]
        )
        agent = qu.QueryUnderstander(structured_llm=model)
        intent = await agent.understand(CVE_QUERY)
        assert intent.parser == "llm" and intent.confidence == 0.85
        assert intent.entities.cve_ids == ["CVE-2024-3400"]
        assert agent.last_error is None

    async def test_fallback_paths(self, stub_structured_model: Any) -> None:
        """结构化失败 / 低置信度 / 未注入 LLM / 空问题 均回退规则且不抛异常。"""
        failing = qu.QueryUnderstander(
            structured_llm=stub_structured_model([ValueError("模拟解析失败")]), max_retries=0
        )
        intent = await failing.understand(CVE_QUERY)
        assert intent.parser == "rules" and "失败" in str(failing.last_error)

        low = qu.QueryUnderstander(
            structured_llm=stub_structured_model(
                [QueryIntent(query=CVE_QUERY, intent="general", confidence=0.1, parser="llm")]
            ),
            min_confidence=0.9,
        )
        assert (await low.understand(CVE_QUERY)).intent == "attack_chain"

        no_llm = qu.QueryUnderstander(structured_llm=None, use_llm=True)
        assert no_llm.llm_enabled is False
        assert (await no_llm.understand(FILTER_QUERY)).parser == "rules"

        blank = qu.QueryUnderstander(structured_llm=stub_structured_model([QueryIntent(query="x")]))
        assert (await blank.understand("   ")).parser == "rules"

    async def test_node_payload_and_context(self, stub_structured_model: Any) -> None:
        """LangGraph 节点返回 ``intent`` / ``degraded`` / ``errors``；会话上下文进入提示词构建路径。"""
        model = stub_structured_model([ValueError("失败")])
        agent = qu.QueryUnderstander(structured_llm=model, max_retries=0)
        state = new_qa_state(REMEDIATION_QUERY)
        state["session_context"] = ["上一轮问题：PAN-OS 漏洞"]
        payload = await agent.__call__(state)
        assert payload["intent"].intent == "remediation"
        assert payload["degraded"] is True
        assert payload["errors"][0].startswith(qu.AGENT_NAME)


class TestFactory:
    """工厂：开关判定与降级。"""

    def test_factory_switches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """显式关 / 降级模式 / 空 Key 均走规则；provider 构建失败同样回退且不抛异常。"""
        assert qu.build_query_understander(_settings(), use_llm=False).llm_enabled is False
        assert qu.build_query_understander(_settings(degraded_mode=True)).llm_enabled is False
        assert qu.build_query_understander(_settings(llm_api_key="")).llm_enabled is False

        def _boom(settings: Settings) -> Any:
            raise LLMError("模拟缺少 langchain-openai")

        monkeypatch.setattr(qu, "build_provider", _boom)
        assert qu.build_query_understander(_settings()).llm_enabled is False
