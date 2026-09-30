"""Day9 攻击链模型门控测试（``attack_mapper`` + ``LLM_SMART_GATE``）。

门控规则：``kev=True`` 或 ``risk_level ∈ {high, critical}`` → ``deepseek-reasoner``（smart）；
其余 → ``deepseek-chat``（fast）。**全部离线**（``conftest.StubStructuredModel``）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.config import Settings
from aisec_intel.enrich.agents.attack_mapper import (
    SMART_RISK_LEVELS,
    ATTACKMapperAgent,
    needs_smart_model,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.models.agent_io import AttackChainDraft, AttackChainStepDraft
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import ExploitRecord
from aisec_intel.models.unified_vuln import CVSSVector, UnifiedVuln

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
SMART_TAG = "deepseek-reasoner"
FAST_TAG = "deepseek-chat"

DRAFT = AttackChainDraft(
    steps=[
        AttackChainStepDraft(
            order=1,
            technique_id="T1190",
            tactic="initial-access",
            stage="Exploitation",
            description="利用命令注入",
            preconditions=["目标可达"],
        )
    ],
    entry_vector="GlobalProtect 接口",
    privileges_required="none",
)


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体（默认低风险：无 CVSS / 无 KEV / 无 EPSS）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-3400",
        "title": "PAN-OS Command Injection",
        "description": "Command injection in GlobalProtect.",
        "cwe_ids": ["CWE-77"],
        "sources": ["nvd"],
        "trace_ids": ["trace-1"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


def critical_vuln() -> UnifiedVuln:
    """构造「critical 风险但非 KEV」的漏洞（CVSS 10 + EPSS 1.0 → 70 分，加 2 条 PoC 后 85 分）。"""
    return make_vuln(
        cvss=[CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")],
        epss_score=1.0,
    )


def two_pocs() -> list[ExploitRecord]:
    """两条「实战级」PoC（用于把风险分推到 critical）。"""
    return [
        ExploitRecord(source="github", url="https://example.test/a", maturity="functional", reliability=0.8),
        ExploitRecord(source="nuclei", url="https://example.test/b", maturity="poc", reliability=0.8),
    ]


def make_agent(smart_stub: Any, fast_stub: Any = None, **overrides: Any) -> ATTACKMapperAgent:
    """构造带 smart/fast 两个桩的门控 Agent。"""
    payload: dict[str, Any] = {
        "structured_llm": smart_stub,
        "fast_llm": fast_stub,
        "model_tag": SMART_TAG,
        "fast_model_tag": FAST_TAG,
        "smart_gate": True,
    }
    payload.update(overrides)
    return ATTACKMapperAgent(**payload)


class TestNeedsSmartModel:
    """门控纯函数。"""

    def test_smart_risk_levels_are_high_and_critical(self) -> None:
        """门控白名单只含 high / critical。"""
        assert set(SMART_RISK_LEVELS) == {"high", "critical"}

    def test_kev_always_needs_smart(self) -> None:
        """``kev=True``（已在野利用）无论风险级别都用推理模型。"""
        assert needs_smart_model(make_vuln(kev=True), risk_level="low") is True

    @pytest.mark.parametrize("level", ["high", "critical", "HIGH", " Critical "])
    def test_high_risk_needs_smart(self, level: str) -> None:
        """高危 / 严重级别命中推理模型（大小写与空白不敏感）。"""
        assert needs_smart_model(make_vuln(), risk_level=level) is True

    @pytest.mark.parametrize("level", ["low", "medium", None, "unknown"])
    def test_others_use_fast(self, level: str | None) -> None:
        """medium / low / 未评分 → 用轻量模型（省 token）。"""
        assert needs_smart_model(make_vuln(), risk_level=level) is False

    def test_gate_disabled_always_smart(self) -> None:
        """``gate_enabled=False`` 时保持 P5 行为：无条件 smart。"""
        assert needs_smart_model(make_vuln(), risk_level="low", gate_enabled=False) is True


class TestAgentModelSelection:
    """Agent 实际选择哪个 Runnable / 写什么 ``model_used``。"""

    async def test_low_risk_uses_fast_model(self, stub_structured_model: Any) -> None:
        """低风险 → 只调用 fast 桩，轨迹标注 ``deepseek-chat``。"""
        smart_stub = stub_structured_model([DRAFT])
        fast_stub = stub_structured_model([DRAFT])

        result = await make_agent(smart_stub, fast_stub)(new_state(make_vuln()))

        assert fast_stub.call_count == 1 and smart_stub.call_count == 0
        assert result["attack_chain"] is not None
        step = result["agent_steps"][0]
        assert step.model_used == FAST_TAG
        assert "gate=fast" in step.output_digest and "risk=low" in step.output_digest

    async def test_kev_uses_smart_model(self, stub_structured_model: Any) -> None:
        """``kev=True`` → 调用 smart 桩，轨迹标注 ``deepseek-reasoner``。"""
        smart_stub = stub_structured_model([DRAFT])
        fast_stub = stub_structured_model([DRAFT])

        result = await make_agent(smart_stub, fast_stub)(new_state(make_vuln(kev=True)))

        assert smart_stub.call_count == 1 and fast_stub.call_count == 0
        assert result["agent_steps"][0].model_used == SMART_TAG
        assert "gate=smart" in result["agent_steps"][0].output_digest

    async def test_critical_risk_uses_smart_model(self, stub_structured_model: Any) -> None:
        """risk_level=critical（非 KEV，靠 CVSS+EPSS+PoC 达标）→ smart。"""
        smart_stub = stub_structured_model([DRAFT])
        fast_stub = stub_structured_model([DRAFT])
        state = new_state(critical_vuln())
        state["exploits"] = two_pocs()

        result = await make_agent(smart_stub, fast_stub)(state)

        assert smart_stub.call_count == 1 and fast_stub.call_count == 0
        assert result["agent_steps"][0].model_used == SMART_TAG

    async def test_gate_disabled_restores_p5_behaviour(self, stub_structured_model: Any) -> None:
        """``smart_gate=False`` → 低风险也用 smart（对照实验用）。"""
        smart_stub = stub_structured_model([DRAFT])
        fast_stub = stub_structured_model([DRAFT])

        await make_agent(smart_stub, fast_stub, smart_gate=False)(new_state(make_vuln()))

        assert smart_stub.call_count == 1 and fast_stub.call_count == 0

    async def test_without_fast_llm_falls_back_to_smart_tag(self, stub_structured_model: Any) -> None:
        """未注入 fast Runnable 时退回 smart，且 ``model_used`` 不误标为 fast。"""
        smart_stub = stub_structured_model([DRAFT])

        result = await make_agent(smart_stub, None)(new_state(make_vuln()))

        assert smart_stub.call_count == 1
        assert result["agent_steps"][0].model_used == SMART_TAG


class TestConfigSwitch:
    """``LLM_SMART_GATE`` 配置项。"""

    def test_defaults_to_true(self) -> None:
        """默认开启门控（Day9 任务 2）。"""
        assert Settings(_env_file=None).llm_smart_gate is True

    def test_env_can_disable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``LLM_SMART_GATE=false`` 可关闭门控（回落 P5 行为）。"""
        monkeypatch.setenv("LLM_SMART_GATE", "false")
        assert Settings(_env_file=None).llm_smart_gate is False

    def test_masked_snapshot_includes_gate(self) -> None:
        """配置快照（日志用）包含门控开关。"""
        assert Settings(_env_file=None).masked()["llm_smart_gate"] is True
