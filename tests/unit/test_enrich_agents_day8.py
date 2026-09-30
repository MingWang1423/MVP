"""Day8 新增 Agent 测试（CVSS 推断 / 资产映射 / ATT&CK / 修复建议）。

**全部离线**：LLM 用 ``conftest.StubStructuredModel``，资产清单用注入的 mock，
HTTP 用 ``httpx.MockTransport`` 桩。
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

    def test_skips_when_cvss_present(self) -> None:
        """事实层已有 CVSS → 不推断（不覆写事实）。"""
        with_cvss = make_vuln(
            cvss=[CVSSVector(version="3.1", vector=CVSS_CRITICAL, base_score=10.0, severity="CRITICAL")]
        )
        assert needs_inference(with_cvss) is False
        assert needs_inference(make_vuln()) is True

    def test_validate_recomputes_score(self) -> None:
        """复算出的分数与严重度来自 L2 公式（LLM 不给分）。"""
        vector = validate_inference(CVSSInference(vector=CVSS_CRITICAL, confidence=0.8))
        assert vector.base_score == 10.0
        assert derive_severity(vector) == "CRITICAL"

    def test_validate_rejects_wrong_version(self) -> None:
        """非 v3.1 向量被拒绝（v3.0 可解析但版本不符 → 命中版本校验分支）。"""
        with pytest.raises(ValueError, match="仅支持推断"):
            validate_inference(
                CVSSInference(vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", confidence=0.9)
            )
        with pytest.raises(ValueError):
            validate_inference(CVSSInference(vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", confidence=0.9))

    def test_validate_rejects_invalid_vector(self) -> None:
        """非法向量被拒绝。"""
        with pytest.raises(ValueError):
            validate_inference(CVSSInference(vector="not-a-vector", confidence=0.9))

    async def test_inference_path(self, stub_structured_model: Any) -> None:
        """LLM 推断成功 → 产出经复算的向量 + 轨迹。"""
        stub = stub_structured_model(
            [CVSSInference(vector=CVSS_CRITICAL, confidence=0.85, rationale="网络可达+高影响")]
        )
        result = await CVSSEnricherAgent(structured_llm=stub, model_tag="deepseek-chat")(new_state(make_vuln()))

        assert len(result["cvss_inferred"]) == 1
        assert result["cvss_inferred"][0].base_score == 10.0
        assert result["errors"] == []
        assert "base_score=10.0" in result["agent_steps"][0].output_digest

    async def test_low_confidence_is_rejected(self, stub_structured_model: Any) -> None:
        """置信度低于阈值 → 丢弃（不写脏数据）。"""
        stub = stub_structured_model([CVSSInference(vector=CVSS_CRITICAL, confidence=0.2)])
        result = await CVSSEnricherAgent(structured_llm=stub)(new_state(make_vuln()))
        assert result["cvss_inferred"] == []
        assert "reject" in result["agent_steps"][0].output_digest

    async def test_invalid_vector_is_discarded(self, stub_structured_model: Any) -> None:
        """非法向量 → 记错误且不产出。"""
        stub = stub_structured_model([CVSSInference(vector="CVSS:3.1/AV:Z", confidence=0.9)])
        result = await CVSSEnricherAgent(structured_llm=stub)(new_state(make_vuln()))
        assert result["cvss_inferred"] == []
        assert "复算失败" in result["errors"][0]

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

    def test_cpe_keys_prefers_cpe_then_packages(self) -> None:
        """CPE 键优先，其后是生态包名（去重保序）。"""
        assert cpe_keys(make_vuln()) == ["ollama:ollama"]
        assert cpe_keys(make_vuln(cpe_matches=[], ecosystem_packages=["PyPI:vllm"])) == ["vllm"]
        assert cpe_keys(make_vuln(cpe_matches=[], ecosystem_packages=[])) == []

    def test_version_range_from_bounds(self) -> None:
        """CPE 区间转为可读描述；无区间时回退受影响版本。"""
        match = CpeMatch(vendor="vllm", product="vllm", version_start_incl="0.6.0", version_end_excl="0.6.4")
        assert version_range_of(match, affected_versions=[]) == ">=0.6.0,<0.6.4"
        assert version_range_of(None, affected_versions=["vllm <0.6.4"]) == "vllm <0.6.4"
        assert version_range_of(None, affected_versions=[]) is None

    async def test_query_assets_tool(self) -> None:
        """``query_assets`` 命中 mock 清单 / 未命中返回空。"""
        assert len(await query_assets("ollama:ollama")) == 2
        assert await query_assets("unknown:thing") == []

    async def test_inventory_hit_produces_assets(self) -> None:
        """清单命中 → 产出资产（confidence 0.9，证据含 cpe 与 trace）。"""
        result = await AssetMapperAgent()(new_state(make_vuln()))
        assets = result["affected_assets"]
        assert len(assets) == 2
        assert all(asset.confidence == INVENTORY_CONFIDENCE for asset in assets)
        assert {asset.asset_type for asset in assets} == {"service", "library"}
        assert "trace-1" in assets[0].evidence_refs

    async def test_inventory_miss_falls_back_to_cpe(self) -> None:
        """清单未命中 → 按 CPE 产出低置信度占位资产（不静默返回空）。"""
        vuln = make_vuln(cpe_matches=[CpeMatch(vendor="acme", product="widget")], ecosystem_packages=[])
        result = await AssetMapperAgent()(new_state(vuln))
        assert len(result["affected_assets"]) == 1
        assert result["affected_assets"][0].confidence < INVENTORY_CONFIDENCE
        assert "清单未命中" in result["affected_assets"][0].evidence_refs[-1]

    async def test_no_cpe_reports_error(self) -> None:
        """无 CPE / 生态包 → 空资产 + 错误留痕。"""
        result = await AssetMapperAgent()(new_state(make_vuln(cpe_matches=[], ecosystem_packages=[])))
        assert result["affected_assets"] == []
        assert "无法映射资产" in result["errors"][0]

    async def test_inventory_error_is_isolated(self) -> None:
        """清单查询异常 → 降级为按 CPE 兜底并记错误（不阻断链路）。"""

        class BrokenInventory:
            async def query(self, cpe: str) -> list[dict[str, Any]]:
                raise RuntimeError("cmdb down")

        result = await AssetMapperAgent(inventory=BrokenInventory())(new_state(make_vuln()))
        assert any("查询" in error for error in result["errors"])
        assert result["affected_assets"]

    async def test_asset_type_normalization(self) -> None:
        """未知资产类型归一化为 ``other``。"""
        inventory = MockAssetInventory({"widget": [{"name": "w", "asset_type": "weird"}]})
        result = await AssetMapperAgent(inventory=inventory)(
            new_state(make_vuln(cpe_matches=[CpeMatch(vendor="acme", product="widget")]))
        )
        assert result["affected_assets"][0].asset_type == "other"


class TestAttackMapper:
    """维度⑤：ATT&CK 攻击链（非法步骤清洗 + 离线兜底）。"""

    @staticmethod
    def _step(**overrides: Any) -> AttackChainStep:
        payload: dict[str, Any] = {
            "order": 1,
            "technique_id": "T1190",
            "tactic": "initial-access",
            "stage": "Exploitation",
            "description": "利用路径穿越",
        }
        payload.update(overrides)
        return AttackChainStep(**payload)

    def test_step_validation(self) -> None:
        """技术 ID 格式与战术白名单双重校验。"""
        assert is_valid_step(self._step()) is True
        assert is_valid_step(self._step(technique_id="T1059.004")) is True
        assert is_valid_step(self._step(technique_id="1190")) is False
        assert is_valid_step(self._step(tactic="not-a-tactic")) is False
        assert "initial-access" in TACTICS

    def test_normalizers(self) -> None:
        """战术名 slug 化、权限文本归一化（LLM 自由文本 → 契约字面量）。"""
        assert normalize_tactic("Initial Access") == "initial-access"
        assert normalize_tactic("COMMAND_AND_CONTROL") == "command-and-control"
        assert normalize_tactic("persistence") == "persistence"
        assert normalize_privileges("None (unauthenticated)") == "none"
        assert normalize_privileges("root") == "high"
        assert normalize_privileges("低权限") == "low"
        assert normalize_privileges("whatever") == "unknown"

    def test_to_attack_chain_normalizes_draft(self) -> None:
        """草稿 → 冻结模型：字符串前置条件切分、order 重排、技术 ID 大写。"""
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

    def test_sanitize_drops_invalid_and_renumbers(self) -> None:
        """非法步骤被剔除，``order`` 从 1 重排。"""
        chain = AttackChain(
            steps=[
                self._step(order=5),
                self._step(order=6, technique_id="BAD"),
                self._step(order=7, tactic="nope"),
            ],
            entry_vector="网络",
        )
        cleaned = sanitize_chain(chain)
        assert [step.order for step in cleaned.steps] == [1]
        assert cleaned.entry_vector == "网络"

    def test_fallback_chain_from_cwe(self) -> None:
        """CWE 兜底表生成确定性攻击链；未登记 CWE 返回 ``None``。"""
        chain = fallback_chain(make_vuln())
        assert chain is not None and chain.steps[0].technique_id == "T1190"
        assert fallback_chain(make_vuln(cwe_ids=["CWE-99999"])) is None

    async def test_llm_path(self, stub_structured_model: Any) -> None:
        """LLM 草稿（显示名战术 / 字符串前置条件）→ 归一化为合法攻击链并采纳。"""
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
        result = await ATTACKMapperAgent(structured_llm=stub, model_tag="deepseek-reasoner")(new_state(make_vuln()))
        chain = result["attack_chain"]
        assert chain is not None and len(chain.steps) == 2
        assert [step.order for step in chain.steps] == [1, 2]
        assert chain.steps[0].technique_id == "T1190" and chain.steps[0].tactic == "initial-access"
        assert chain.steps[0].preconditions == ["目标可达", "组件版本在受影响区间"]
        assert chain.privileges_required == "none"
        assert result["agent_steps"][0].confidence == 0.75
        assert "deepseek-reasoner" in result["agent_steps"][0].model_used
        assert result["errors"] == []

    async def test_invalid_steps_fall_back(self, stub_structured_model: Any) -> None:
        """LLM 步骤全非法 → 记错误并回退 CWE 兜底表。"""
        stub = stub_structured_model(
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
        result = await ATTACKMapperAgent(structured_llm=stub, model_tag="m")(new_state(make_vuln()))
        assert result["attack_chain"] is not None  # 兜底生效
        assert any("全部非法" in error for error in result["errors"])
        assert "fallback" in result["agent_steps"][0].output_digest

    async def test_offline_without_cwe_reports_error(self) -> None:
        """无 LLM 且 CWE 未登记 → 无攻击链 + 错误留痕。"""
        result = await ATTACKMapperAgent()(new_state(make_vuln(cwe_ids=["CWE-99999"])))
        assert result["attack_chain"] is None
        assert "无法映射 ATT&CK" in result["errors"][0]


class TestRemediationAgent:
    """维度⑦：修复建议（补丁链接白名单 + 确定性兜底）。"""

    @staticmethod
    def _vuln_with_patches() -> UnifiedVuln:
        return make_vuln(
            references=[
                Reference(url="https://github.com/ollama/ollama/releases/tag/v0.1.34", source="nvd", tags=["patch"]),
                Reference(url="https://example.test/advisory", source="nvd", tags=["vendor-advisory"]),
            ]
        )

    def test_patch_references_filters_by_tag(self) -> None:
        """只挑 ``tags`` 含 patch 的链接（保序）。"""
        refs = patch_references(self._vuln_with_patches())
        assert [ref.url for ref in refs] == ["https://github.com/ollama/ollama/releases/tag/v0.1.34"]

    def test_sanitize_drops_hallucinated_urls(self) -> None:
        """LLM 生成的链接若不在 references 中 → 剔除（防幻觉）。"""
        raw = Remediation(
            summary="升级到 0.1.34",
            patch_urls=[
                "https://evil.test/fake",
                "https://github.com/ollama/ollama/releases/tag/v0.1.34",
            ],
        )
        allowed = {ref.url for ref in self._vuln_with_patches().references}
        cleaned = sanitize_remediation(raw, allowed_urls=allowed)
        assert cleaned.patch_urls == ["https://github.com/ollama/ollama/releases/tag/v0.1.34"]

    def test_fallback_remediation_uses_facts(self) -> None:
        """兜底建议引用真实组件、补丁链接与置信度基线。"""
        vuln = self._vuln_with_patches()
        remediation = fallback_remediation(vuln, patches=patch_references(vuln))
        assert remediation.patch_urls
        assert any("ollama" in mitigation for mitigation in remediation.mitigations)
        assert remediation.confidence == 0.5

    async def test_llm_path(self, stub_structured_model: Any) -> None:
        """LLM 修复建议生效，非法链接被清洗。"""
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
        result = await RemediationAgent(structured_llm=stub, model_tag="deepseek-chat")(
            new_state(self._vuln_with_patches())
        )
        remediation = result["remediation"]
        assert remediation is not None and remediation.fixed_versions == ["0.1.34"]
        assert remediation.patch_urls == ["https://github.com/ollama/ollama/releases/tag/v0.1.34"]
        assert result["agent_steps"][0].confidence == 0.8

    async def test_offline_fallback(self) -> None:
        """无 LLM → 确定性兜底建议（含缓解措施）。"""
        result = await RemediationAgent()(new_state(self._vuln_with_patches()))
        remediation = result["remediation"]
        assert remediation is not None and remediation.mitigations
        assert "fallback" in result["agent_steps"][0].output_digest
