"""Day8 新增 Agent 测试（CVSS 推断 / 资产映射 / ATT&CK / 修复建议）。

**全部离线**：LLM 用 ``conftest.StubStructuredModel``，资产清单用注入的 mock，
HTTP 用 ``httpx.MockTransport`` 桩。

Note:
    Day12 任务 2 合并：原 29 个用例按维度压到 11 个（同类行为一个函数 + 多组输入循环），
    断言口径不变（公式复算、清洗、兜底、留痕全部保留）。
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.enrich.agents.asset_mapper import (
    INVENTORY_CONFIDENCE,
    AssetMapperAgent,
    MockAssetInventory,
    cpe_keys,
    query_assets,
    version_range_of,
)
from aisec_intel.enrich.agents.attack_mapper import (
    TACTICS,
    ATTACKMapperAgent,
    fallback_chain,
    is_valid_step,
    normalize_privileges,
    normalize_tactic,
    sanitize_chain,
    to_attack_chain,
)
from aisec_intel.enrich.agents.cvss_enricher import (
    CVSSEnricherAgent,
    derive_severity,
    needs_inference,
    validate_inference,
)
from aisec_intel.enrich.agents.remediation import (
    RemediationAgent,
    fallback_remediation,
    patch_references,
    sanitize_remediation,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.models.agent_io import AttackChainDraft, AttackChainStepDraft, CVSSInference, Remediation
from aisec_intel.models.base import utc_now
from aisec_intel.models.enriched_vuln import AttackChain, AttackChainStep
from aisec_intel.models.unified_vuln import CpeMatch, CVSSVector, Reference, UnifiedVuln

CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def make_vuln(**overrides: Any) -> UnifiedVuln:
    """构造测试用漏洞实体（默认无 CVSS，用于触发推断）。"""
    payload: dict[str, Any] = {
        "vuln_id": "CVE-2024-37032",
        "title": "Ollama Server Path Traversal",
        "description": "A path traversal in the model upload API allows remote code execution.",
        "cwe_ids": ["CWE-22"],
        "cpe_matches": [CpeMatch(vendor="ollama", product="ollama", version_end_excl="0.1.34")],
        "ecosystem_packages": ["PyPI:ollama"],
        "affected_versions": ["ollama:ollama <0.1.34"],
        "sources": ["nvd"],
        "trace_ids": ["trace-1"],
        "normalized_at": utc_now(),
    }
    payload.update(overrides)
    return UnifiedVuln(**payload)


class TestCvssEnricher:
    """维度⑥：CVSS 推断（数值必须由公式复算）。"""

    def test_needs_inference_and_validation(self) -> None:
        """已事实 → 不推断；推断结果必须经 L2 公式复算；非法 / 非 v3.1 向量拒绝。"""
        with_cvss = make_vuln(
            cvss=[CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")]
        )
        assert needs_inference(with_cvss) is False
        assert needs_inference(make_vuln()) is True
        vector = validate_inference(CVSSInference(vector=CVSS_CRITICAL, confidence=0.8))
        assert vector.base_score == 10.0
        assert derive_severity(vector) == "CRITICAL"
        for bad in (
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",
            "not-a-vector",
        ):
            with pytest.raises(ValueError):
                validate_inference(CVSSInference(vector=bad, confidence=0.9))

    async def test_llm_inference_outcomes(self, stub_structured_model: Any) -> None:
        """LLM 三类结果：成功采纳 / 低置信度丢弃 / 非法向量记错误。"""
        cases: list[tuple[CVSSInference, str]] = [
            (CVSSInference(vector=CVSS_CRITICAL, confidence=0.85, rationale="网络可达+高影响"), "ok"),
            (CVSSInference(vector=CVSS_CRITICAL, confidence=0.2), "reject"),
            (CVSSInference(vector="CVSS:3.1/AV:Z", confidence=0.9), "复算失败"),
        ]
        for inference, outcome in cases:
            agent = CVSSEnricherAgent(
                structured_llm=stub_structured_model([inference]), model_tag="deepseek-chat"
            )
            result = await agent(new_state(make_vuln()))
            if outcome == "ok":
                assert len(result["cvss_inferred"]) == 1
                assert result["cvss_inferred"][0].base_score == 10.0
                assert "base_score=10.0" in result["agent_steps"][0].output_digest
                assert result["errors"] == []
            elif outcome == "reject":
                assert result["cvss_inferred"] == []
                assert "reject" in result["agent_steps"][0].output_digest
            else:
                assert result["cvss_inferred"] == []
                assert outcome in result["errors"][0]

    async def test_offline_and_existing_facts_skip(self) -> None:
        """无 LLM / 已有 CVSS → 跳过（不报错、不产出）。"""
        offline = await CVSSEnricherAgent()(new_state(make_vuln()))
        assert offline["cvss_inferred"] == []
        assert offline["agent_steps"][0].model_used == "no-llm"
        existing = make_vuln(
            cvss=[CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")]
        )
        skipped = await CVSSEnricherAgent()(new_state(existing))
        assert "已有 CVSS" in skipped["agent_steps"][0].output_digest


class TestAssetMapper:
    """维度①：资产映射（mock 清单 + 查表接口）。"""

    async def test_helper_pure_functions(self) -> None:
        """``cpe_keys`` 优先级、``version_range_of`` 回退、``query_assets`` 查表。"""
        assert cpe_keys(make_vuln()) == ["ollama:ollama"]
        assert cpe_keys(make_vuln(cpe_matches=[], ecosystem_packages=["PyPI:vllm"])) == ["vllm"]
        assert cpe_keys(make_vuln(cpe_matches=[], ecosystem_packages=[])) == []
        match = CpeMatch(vendor="vllm", product="vllm", version_start_incl="0.6.0", version_end_excl="0.6.4")
        assert version_range_of(match, affected_versions=[]) == ">=0.6.0,<0.6.4"
        assert version_range_of(None, affected_versions=["vllm <0.6.4"]) == "vllm <0.6.4"
        assert version_range_of(None, affected_versions=[]) is None
        assert len(await query_assets("ollama:ollama")) == 2
        assert await query_assets("unknown:thing") == []

    async def test_inventory_hit_miss_and_type_normalization(self) -> None:
        """清单命中产出证据完整的资产；未命中按 CPE 兜底；未知类型归一化。"""
        hit = await AssetMapperAgent()(new_state(make_vuln()))
        assets = hit["affected_assets"]
        assert len(assets) == 2
        assert all(asset.confidence == INVENTORY_CONFIDENCE for asset in assets)
        assert {asset.asset_type for asset in assets} == {"service", "library"}
        assert "trace-1" in assets[0].evidence_refs

        miss = await AssetMapperAgent()(
            new_state(make_vuln(cpe_matches=[CpeMatch(vendor="acme", product="widget")], ecosystem_packages=[]))
        )
        assert len(miss["affected_assets"]) == 1
        assert miss["affected_assets"][0].confidence < INVENTORY_CONFIDENCE
        assert "清单未命中" in miss["affected_assets"][0].evidence_refs[-1]

        inventory = MockAssetInventory({"widget": [{"name": "w", "asset_type": "weird"}]})
        odd = await AssetMapperAgent(inventory=inventory)(
            new_state(make_vuln(cpe_matches=[CpeMatch(vendor="acme", product="widget")]))
        )
        assert odd["affected_assets"][0].asset_type == "other"

    async def test_no_cpe_and_inventory_error(self) -> None:
        """无 CPE → 错误留痕；清单异常 → 降级兜底且不阻断链路。"""

        class BrokenInventory:
            """模拟 CMDB 故障的清单桩。"""

            async def query(self, cpe: str) -> list[dict[str, Any]]:
                """固定抛出异常。"""
                raise RuntimeError("cmdb down")

        empty = await AssetMapperAgent()(new_state(make_vuln(cpe_matches=[], ecosystem_packages=[])))
        assert empty["affected_assets"] == []
        assert "无法映射资产" in empty["errors"][0]
        broken = await AssetMapperAgent(inventory=BrokenInventory())(new_state(make_vuln()))
        assert any("查询" in error for error in broken["errors"])
        assert broken["affected_assets"]


class TestAttackMapper:
    """维度⑤：ATT&CK 攻击链（非法步骤清洗 + 离线兜底）。"""

    @staticmethod
    def _step(**overrides: Any) -> AttackChainStep:
        """构造合法攻击链步骤（可覆盖字段）。"""
        payload: dict[str, Any] = {
            "order": 1,
            "technique_id": "T1190",
            "tactic": "initial-access",
            "stage": "Exploitation",
            "description": "利用路径穿越",
        }
        payload.update(overrides)
        return AttackChainStep(**payload)

    def test_step_validation_and_normalizers(self) -> None:
        """技术 ID / 战术白名单校验；战术 slug 化与权限归一化。"""
        assert is_valid_step(self._step()) is True
        assert is_valid_step(self._step(technique_id="T1059.004")) is True
        assert is_valid_step(self._step(technique_id="1190")) is False
        assert is_valid_step(self._step(tactic="not-a-tactic")) is False
        assert "initial-access" in TACTICS
        assert normalize_tactic("Initial Access") == "initial-access"
        assert normalize_tactic("COMMAND_AND_CONTROL") == "command-and-control"
        assert normalize_tactic("persistence") == "persistence"
        for raw, expected in (
            ("None (unauthenticated)", "none"),
            ("root", "high"),
            ("低权限", "low"),
            ("whatever", "unknown"),
        ):
            assert normalize_privileges(raw) == expected

    def test_draft_conversion_sanitize_and_fallback(self) -> None:
        """草稿归一化（切分前置条件 / 重排 order / 大写技术 ID）、非法步骤清洗、CWE 兜底。"""
        draft = AttackChainDraft(
            steps=[
                AttackChainStepDraft(
                    order=9,
                    technique_id="t1059.004",
                    tactic="Execution",
                    stage="Execution",
                    description="执行命令",
                    preconditions="条件A；条件B",
                )
            ],
            entry_vector="网络",
            privileges_required="admin",
        )
        chain = to_attack_chain(draft)
        assert chain.steps[0].technique_id == "T1059.004"
        assert chain.steps[0].order == 1
        assert chain.steps[0].preconditions == ["条件A", "条件B"]
        assert chain.privileges_required == "high"
        assert is_valid_step(chain.steps[0]) is True

        dirty = AttackChain(
            steps=[
                self._step(order=5),
                self._step(order=6, technique_id="BAD"),
                self._step(order=7, tactic="nope"),
            ],
            entry_vector="网络",
        )
        cleaned = sanitize_chain(dirty)
        assert [step.order for step in cleaned.steps] == [1]
        assert cleaned.entry_vector == "网络"

        fallback = fallback_chain(make_vuln())
        assert fallback is not None and fallback.steps[0].technique_id == "T1190"
        assert fallback_chain(make_vuln(cwe_ids=["CWE-99999"])) is None

    async def test_llm_path_and_offline_fallbacks(self, stub_structured_model: Any) -> None:
        """LLM 成功归一化采纳；步骤全非法回退兜底；无 LLM 且 CWE 未登记 → 留痕。"""
        stub = stub_structured_model(
            [
                AttackChainDraft(
                    steps=[
                        AttackChainStepDraft(
                            order=2,
                            technique_id="t1190",
                            tactic="Initial Access",
                            stage="Exploitation",
                            description="利用路径穿越",
                            preconditions="目标可达；组件版本在受影响区间",
                        ),
                        AttackChainStepDraft(
                            order=5,
                            technique_id="T1059.004",
                            tactic="execution",
                            stage="Execution",
                            description="执行命令",
                            preconditions=["已获得写入能力"],
                        ),
                    ],
                    entry_vector="公开的 /api/push 接口",
                    privileges_required="None (unauthorized)",
                )
            ]
        )
        result = await ATTACKMapperAgent(structured_llm=stub, model_tag="deepseek-reasoner")(
            new_state(make_vuln())
        )
        chain = result["attack_chain"]
        assert chain is not None and len(chain.steps) == 2
        assert [step.order for step in chain.steps] == [1, 2]
        assert chain.steps[0].technique_id == "T1190" and chain.steps[0].tactic == "initial-access"
        assert chain.steps[0].preconditions == ["目标可达", "组件版本在受影响区间"]
        assert chain.privileges_required == "none"
        assert result["agent_steps"][0].confidence == 0.75
        assert result["errors"] == []

        bad_stub = stub_structured_model(
            [
                AttackChainDraft(
                    steps=[
                        AttackChainStepDraft(
                            technique_id="T99999", tactic="bogus-tactic", description="x", preconditions="y"
                        )
                    ]
                )
            ]
        )
        rejected = await ATTACKMapperAgent(structured_llm=bad_stub, model_tag="m")(new_state(make_vuln()))
        assert rejected["attack_chain"] is not None
        assert any("全部非法" in error for error in rejected["errors"])
        assert "fallback" in rejected["agent_steps"][0].output_digest

        offline = await ATTACKMapperAgent()(new_state(make_vuln(cwe_ids=["CWE-99999"])))
        assert offline["attack_chain"] is None
        assert "无法映射 ATT&CK" in offline["errors"][0]


class TestRemediationAgent:
    """维度⑦：修复建议（补丁链接白名单 + 确定性兜底）。"""

    @staticmethod
    def _vuln_with_patches() -> UnifiedVuln:
        """构造带补丁 / 公告链接的漏洞实体。"""
        return make_vuln(
            references=[
                Reference(
                    url="https://github.com/ollama/ollama/releases/tag/v0.1.34", source="nvd", tags=["patch"]
                ),
                Reference(url="https://example.test/advisory", source="nvd", tags=["vendor-advisory"]),
            ]
        )

    def test_patch_references_and_sanitize(self) -> None:
        """只挑 ``tags`` 含 patch 的链接（保序）；LLM 幻觉链接被剔除。"""
        vuln = self._vuln_with_patches()
        refs = patch_references(vuln)
        assert [ref.url for ref in refs] == ["https://github.com/ollama/ollama/releases/tag/v0.1.34"]
        raw = Remediation(
            summary="升级到 0.1.34",
            patch_urls=[
                "https://evil.test/fake",
                "https://github.com/ollama/ollama/releases/tag/v0.1.34",
            ],
        )
        cleaned = sanitize_remediation(raw, allowed_urls={ref.url for ref in vuln.references})
        assert cleaned.patch_urls == ["https://github.com/ollama/ollama/releases/tag/v0.1.34"]

    async def test_llm_path_and_offline_fallback(self, stub_structured_model: Any) -> None:
        """LLM 修复建议生效且非法链接被清洗；无 LLM → 确定性兜底（含缓解措施与置信度基线）。"""
        vuln = self._vuln_with_patches()
        stub = stub_structured_model(
            [
                Remediation(
                    summary="升级 ollama 至 0.1.34",
                    fixed_versions=["0.1.34"],
                    mitigations=["限制 /api/push 访问"],
                    patch_urls=[
                        "https://github.com/ollama/ollama/releases/tag/v0.1.34",
                        "https://fake.test/x",
                    ],
                    confidence=0.8,
                )
            ]
        )
        result = await RemediationAgent(structured_llm=stub, model_tag="deepseek-chat")(new_state(vuln))
        remediation = result["remediation"]
        assert remediation is not None and remediation.fixed_versions == ["0.1.34"]
        assert remediation.patch_urls == ["https://github.com/ollama/ollama/releases/tag/v0.1.34"]
        assert result["agent_steps"][0].confidence == 0.8

        offline = await RemediationAgent()(new_state(vuln))
        fallback = offline["remediation"]
        assert fallback is not None and fallback.mitigations
        assert "fallback" in offline["agent_steps"][0].output_digest
        facts = fallback_remediation(vuln, patches=patch_references(vuln))
        assert facts.patch_urls
        assert any("ollama" in mitigation for mitigation in facts.mitigations)
        assert facts.confidence == 0.5
