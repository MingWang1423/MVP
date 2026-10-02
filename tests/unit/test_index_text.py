"""Day10 索引文本渲染单元测试（``aisec_intel.normalize.index_text``，纯函数层）。

断言：渲染确定性、可引用（含主键）、元数据扁平（无 ``None``、时间 ISO8601）。
"""

from __future__ import annotations

from aisec_intel.models.enriched_vuln import AffectedAsset
from aisec_intel.models.unified_vuln import Reference, UnifiedVuln
from aisec_intel.normalize import index_text as it


class TestClipping:
    """截断工具。"""

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_clipped_keeps_short_text()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_clipped_keeps_short_text: {type(exc).__name__}: {exc}")
        try:
            self._case_test_clipped_truncates_long_text()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_clipped_truncates_long_text: {type(exc).__name__}: {exc}")
        try:
            self._case_test_clipped_negative_limit_falls_back_to_default()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_clipped_negative_limit_falls_back_to_default: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_clipped_keeps_short_text(self) -> None:
        assert it.clipped("abc", limit=10) == "abc"

    def _case_test_clipped_truncates_long_text(self) -> None:
        assert it.clipped("abcdef", limit=3) == "abc"

    def _case_test_clipped_negative_limit_falls_back_to_default(self) -> None:
        """非法上限回退到默认值（不产生空文本）。"""
        assert len(it.clipped("x" * (it.MAX_INDEX_CHARS + 10), limit=0)) == it.MAX_INDEX_CHARS


class TestPatchReferences:
    """补丁 / 公告链接挑选（标签优先，URL 启发式兜底）。"""

    def _vuln(self, references: list[Reference]) -> UnifiedVuln:
        from aisec_intel.models.base import utc_now

        return UnifiedVuln(
            vuln_id="CVE-2024-3400",
            description="d",
            references=references,
            normalized_at=utc_now(),
        )

    def test_merged_batch1(self) -> None:
        """合并用例批次 1：顺序执行 3 个子用例并汇总失败。"""
        failures: list[str] = []
        try:
            self._case_test_tagged_references_win()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_tagged_references_win: {type(exc).__name__}: {exc}")
        try:
            self._case_test_heuristic_when_no_tags()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_heuristic_when_no_tags: {type(exc).__name__}: {exc}")
        try:
            self._case_test_dedupe_and_limit()
        except Exception as exc:  # noqa: BLE001 - 逐例汇总，保留原始失败信息
            failures.append(f"_case_test_dedupe_and_limit: {type(exc).__name__}: {exc}")
        assert not failures, "合并用例失败：" + " | ".join(failures)
    def _case_test_tagged_references_win(self) -> None:
        """有 ``patch`` 标签时只取带标签者（不混入启发式命中）。"""
        vuln = self._vuln(
            [
                Reference(url="https://nvd.nist.gov/vuln/detail/CVE-2024-3400", source="nvd", tags=[]),
                Reference(url="https://vendor.example/patches/x", source="vendor", tags=["patch"]),
                Reference(url="https://example.com/security-bulletin", source="vendor", tags=[]),
            ]
        )
        assert it.patch_references(vuln) == ["https://vendor.example/patches/x"]

    def _case_test_heuristic_when_no_tags(self) -> None:
        """无 patch 标签时回退到 URL 关键词启发式。"""
        vuln = self._vuln(
            [
                Reference(url="https://example.com/security/patch-note", source="vendor", tags=[]),
                Reference(url="https://example.com/blog/post", source="blog", tags=[]),
            ]
        )
        assert it.patch_references(vuln) == ["https://example.com/security/patch-note"]

    def _case_test_dedupe_and_limit(self) -> None:
        """URL 去重且受 ``limit`` 约束。"""
        references = [Reference(url="https://e.com/advisory", source="v", tags=["advisory"]) for _ in range(3)]
        assert it.patch_references(self._vuln(references), limit=5) == ["https://e.com/advisory"]
        assert it.patch_references(self._vuln(references), limit=0) == []


class TestVulnText:
    """漏洞描述文本与元数据。"""

    def test_render_contains_facts(self, sample_unified_vuln: UnifiedVuln) -> None:
        """渲染文本包含主键 / 标题 / CWE / 严重度 / 受影响版本 / KEV 标记。"""
        text = it.render_vuln_text(sample_unified_vuln)
        assert "CVE-2024-3400" in text
        assert "CWE-78" in text and "CRITICAL" in text
        assert "paloaltonetworks:pan-os" in text
        assert "CISA KEV" in text

    def test_render_is_deterministic(self, sample_unified_vuln: UnifiedVuln) -> None:
        """同一实体两次渲染结果一致（可复现）。"""
        assert it.render_vuln_text(sample_unified_vuln) == it.render_vuln_text(sample_unified_vuln)

    def test_metadata_is_flat_and_has_no_none(self, sample_unified_vuln: UnifiedVuln) -> None:
        """元数据只含扁平标量，且不写 ``None`` 值（Chroma 兼容）。"""
        metadata = it.vuln_index_metadata(sample_unified_vuln)
        assert metadata["cve_id"] == "CVE-2024-3400"
        assert metadata["severity"] == "CRITICAL"
        assert metadata["kev"] == "true"
        assert metadata["source"] == "kev,nvd"
        assert metadata["published_at"].endswith("Z")
        assert all(value is not None for value in metadata.values())

    def test_metadata_omits_missing_optional_fields(self) -> None:
        """缺省字段不写入键（而不是写空串）。"""
        from aisec_intel.models.base import utc_now

        vuln = UnifiedVuln(vuln_id="CVE-2020-0001", description="d", normalized_at=utc_now())
        metadata = it.vuln_index_metadata(vuln)
        assert set(metadata) == {"cve_id"}


class TestRemediationText:
    """处置要点文本与元数据（由已落库事实确定性拼装）。"""

    def test_render_includes_versions_patch_and_risk(self, sample_enriched_vuln: object) -> None:
        """含受影响版本、处置动作、官方补丁链接、风险级别。"""
        text = it.render_remediation_text(sample_enriched_vuln)  # type: ignore[arg-type]
        assert "处置要点" in text
        assert "受影响版本" in text and "升级至受影响区间之外的版本" in text
        assert "https://security.paloaltonetworks.com/CVE-2024-3400" in text
        assert "PAN-OS Firewall" in text
        assert "风险级别: critical" in text

    def test_fallback_to_components_without_versions(self, sample_enriched_vuln: object) -> None:
        """无 ``affected_versions`` 时以 ``cpe_matches`` 组件口径给出处置动作。"""
        enriched = sample_enriched_vuln.model_copy(update={"affected_versions": []})  # type: ignore[attr-defined]
        text = it.render_remediation_text(enriched)
        assert "受影响组件: paloaltonetworks:pan-os" in text
        assert "确认在用版本是否落在受影响区间" in text

    def test_minimal_entity_still_renders(self, sample_enriched_vuln: object) -> None:
        """无版本、无 CPE、无资产时仍返回带主键与风险级别的文本（不抛异常）。"""
        enriched = sample_enriched_vuln.model_copy(  # type: ignore[attr-defined]
            update={"affected_versions": [], "cpe_matches": [], "affected_assets": [], "references": []}
        )
        text = it.render_remediation_text(enriched)
        assert text.splitlines()[0] == "CVE-2024-3400 处置要点"
        assert "风险级别: critical" in text

    def test_affected_assets_render_without_name_noise(self) -> None:
        """资产名去重排序（同名资产只出现一次）。"""
        from aisec_intel.models.base import utc_now

        enriched = UnifiedVuln(vuln_id="CVE-2020-0002", description="d", normalized_at=utc_now())
        assets = [
            AffectedAsset(asset_type="service", name="Web Server", confidence=0.6),
            AffectedAsset(asset_type="os", name="Web Server", confidence=0.6),
        ]
        payload = enriched.model_dump()
        payload.update(
            affected_assets=[item.model_dump() for item in assets],
            risk_score=10.0,
            risk_level="low",
            confidence=0.5,
            model_used="test",
            enriched_at=utc_now(),
        )
        from aisec_intel.models.enriched_vuln import EnrichedVuln

        text = it.render_remediation_text(EnrichedVuln(**payload))
        assert "受影响资产: Web Server" in text

    def test_metadata_has_source_marker(self, sample_enriched_vuln: object) -> None:
        """元数据标明来源为富化层且含风险级别。"""
        metadata = it.remediation_index_metadata(sample_enriched_vuln)  # type: ignore[arg-type]
        assert metadata["cve_id"] == "CVE-2024-3400"
        assert metadata["source"] == "enriched_vuln"
        assert metadata["risk_level"] == "critical"
        assert metadata["published_at"].endswith("Z")

    def test_render_is_deterministic(self, sample_enriched_vuln: object) -> None:
        """同一实体两次渲染一致。"""
        first = it.render_remediation_text(sample_enriched_vuln)  # type: ignore[arg-type]
        second = it.render_remediation_text(sample_enriched_vuln)  # type: ignore[arg-type]
        assert first == second

    def test_render_includes_persisted_remediation(self, sample_enriched_vuln: object) -> None:
        """Day17 v1.2：已落库的 ``remediation_json`` 会进入检索文本（问答可引用修复结论）。"""
        enriched = sample_enriched_vuln.model_copy(  # type: ignore[attr-defined]
            update={
                "remediation_json": {
                    "summary": "升级 PAN-OS 至 10.2.9-h1",
                    "fixed_versions": ["10.2.9-h1"],
                    "mitigations": ["禁用 GlobalProtect 设备遥测"],
                    "patch_urls": ["https://security.paloaltonetworks.com/CVE-2024-3400"],
                    "confidence": 0.8,
                }
            }
        )
        text = it.render_remediation_text(enriched)
        assert "修复结论: 升级 PAN-OS 至 10.2.9-h1" in text
        assert "修复版本: 10.2.9-h1" in text
        assert "缓解措施: 禁用 GlobalProtect 设备遥测" in text
        assert "富化补丁链接: https://security.paloaltonetworks.com/CVE-2024-3400" in text

    def test_render_tolerates_missing_remediation(self, sample_enriched_vuln: object) -> None:
        """``remediation_json`` 为 ``None`` 时行为与旧版一致（不出现修复结论行）。"""
        enriched = sample_enriched_vuln.model_copy(update={"remediation_json": None})  # type: ignore[attr-defined]
        text = it.render_remediation_text(enriched)
        assert "修复结论:" not in text
        assert "受影响版本" in text