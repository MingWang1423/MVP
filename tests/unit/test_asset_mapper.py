"""Day11 任务 1.1：资产映射限流（``aisec_intel.enrich.agents.asset_mapper``）。

覆盖公开接口：``vendor_matches`` / ``asset_relevance`` / ``select_assets`` / ``AssetMapperAgent``。
（图谱「边爆炸」修复的核心口径：厂商一致 + 相关性排序 + 单漏洞上限。）
"""

from __future__ import annotations

from typing import Any

import pytest

from aisec_intel.enrich.agents.asset_mapper import (
    DEFAULT_MAX_ASSETS,
    AssetMapperAgent,
    asset_allowed,
    asset_relevance,
    select_assets,
    vendor_matches,
)
from aisec_intel.enrich.state import new_state
from aisec_intel.models.enriched_vuln import AffectedAsset
from aisec_intel.models.unified_vuln import CpeMatch


def _asset(name: str, *, confidence: float = 0.5, vendor: str | None = None) -> AffectedAsset:
    """构造资产条目（测试夹具工厂）。"""
    return AffectedAsset(
        asset_type="library",
        name=name,
        vendor=vendor,
        confidence=confidence,
        evidence_refs=["test"],
    )


def _cpes(count: int, *, vendor: str = "vendor", prefix: str = "product") -> list[CpeMatch]:
    """构造 ``count`` 个 CPE 匹配项（模拟 NVD 宽口径配置）。"""
    return [CpeMatch(vendor=vendor, product=f"{prefix}-{index}") for index in range(count)]


def _vuln_with(sample: Any, cpes: list[CpeMatch]) -> Any:
    """基于样例漏洞替换 CPE 列表（走真实校验，避免 dict 绕过 Pydantic）。"""
    return sample.model_copy(update={"cpe_matches": cpes})


class TestVendorMatches:
    """厂商一致性（纯函数）。"""

    @pytest.mark.parametrize(
        ("asset_vendor", "cpe_vendor", "expected"),
        [
            ("paloaltonetworks", "paloaltonetworks", True),
            ("Palo Alto Networks", "paloaltonetworks", True),  # 去空格后双向包含
            ("apache", "oracle", False),
            (None, "apache", True),  # 信息不足 → 保留（由上限兜底）
            ("apache", "", True),
        ],
    )
    def test_vendor_match_matrix(self, asset_vendor: str | None, cpe_vendor: str | None, expected: bool) -> None:
        assert vendor_matches(asset_vendor, cpe_vendor) is expected


class TestSelectAssets:
    """筛选与截断（纯函数）。"""

    def test_caps_and_sorts_by_confidence(self) -> None:
        """按置信度降序截断到上限。"""
        candidates = [_asset(f"asset-{index}", confidence=index / 100) for index in range(1, 21)]
        kept = select_assets(candidates, max_assets=10)
        assert len(kept) == 10
        assert kept[0].name == "asset-20"
        assert [item.confidence for item in kept] == sorted((item.confidence for item in kept), reverse=True)

    def test_vendor_mismatch_is_dropped_unless_name_matches_product(self) -> None:
        """厂商不一致的资产被丢弃；但名称含产品名者保留（内部归属团队的常见形态）。"""
        candidates = [
            _asset("keep", vendor="apache", confidence=0.9),
            _asset("drop", vendor="oracle", confidence=0.9),
            _asset("unknown", vendor=None, confidence=0.4),
            _asset("log4j-internal-service", vendor="内部平台组", confidence=0.8),
        ]
        kept = select_assets(candidates, cpe_vendor="apache", product="log4j", max_assets=10)
        assert [item.name for item in kept] == ["keep", "log4j-internal-service", "unknown"]
        assert asset_allowed(_asset("x", vendor="oracle"), cpe_vendor="apache", product="log4j") is False
        assert asset_allowed(_asset("log4j-core", vendor="oracle"), cpe_vendor="apache", product="log4j") is True

    def test_name_hit_beats_alphabetical(self) -> None:
        """同置信度时，名称命中产品名的排前面。"""
        candidates = [_asset("aaa-generic", confidence=0.5), _asset("zzz-log4j-core", confidence=0.5)]
        kept = select_assets(candidates, product="log4j", max_assets=10)
        assert [item.name for item in kept] == ["zzz-log4j-core", "aaa-generic"]

    def test_non_positive_limit_falls_back_to_default(self) -> None:
        kept = select_assets([_asset(f"a{index}") for index in range(DEFAULT_MAX_ASSETS + 5)], max_assets=0)
        assert len(kept) == DEFAULT_MAX_ASSETS

    def test_empty_candidates(self) -> None:
        assert select_assets([], max_assets=5) == []

    def test_relevance_tuple_shape(self) -> None:
        """``asset_relevance`` 返回 ``(置信度, 命中标志, 名称)``。"""
        assert asset_relevance(_asset("log4j-core", confidence=0.8), product="log4j") == (0.8, 1, "log4j-core")
        assert asset_relevance(_asset("other", confidence=0.8), product=None) == (0.8, 0, "other")


class TestAssetMapperAgent:
    """Agent 端到端行为（公开出参）。"""

    async def test_caps_assets_for_wide_cpe_set(self, sample_unified_vuln: Any) -> None:
        """144 个 CPE 的宽口径漏洞：资产数被压到上限以内（边爆炸根因修复）。"""
        vuln = sample_unified_vuln.model_copy(update={"cpe_matches": _cpes(144)})
        result = await AssetMapperAgent(max_assets=10)(new_state(vuln))
        assets = result["affected_assets"]
        assert len(assets) == 10
        assert "dropped=134" in result["agent_steps"][0].output_digest

    async def test_inventory_vendor_mismatch_is_dropped(self, sample_unified_vuln: Any) -> None:
        """清单命中但厂商与 CPE 不符的行被丢弃（保留 CPE 占位资产）。"""
        inventory_rows = [
            {"name": "wrong-vendor-asset", "vendor": "oracle", "asset_type": "library"},
            {"name": "right-vendor-asset", "vendor": "apache", "asset_type": "library"},
        ]

        class StubInventory:
            """固定返回两条清单行。"""

            async def query(self, cpe: str) -> list[dict[str, Any]]:
                return list(inventory_rows)

        vuln = _vuln_with(sample_unified_vuln, [CpeMatch(vendor="apache", product="log4j")])
        result = await AssetMapperAgent(inventory=StubInventory(), max_assets=10)(new_state(vuln))
        assert [asset.name for asset in result["affected_assets"]] == ["right-vendor-asset"]

    async def test_no_cpe_reports_error_and_returns_empty(self, sample_unified_vuln: Any) -> None:
        """无 CPE / 生态包时返回空资产并给出可观测错误。"""
        vuln = sample_unified_vuln.model_copy(update={"cpe_matches": [], "ecosystem_packages": []})
        result = await AssetMapperAgent()(new_state(vuln))
        assert result["affected_assets"] == []
        assert result["errors"] and "无法映射资产" in result["errors"][0]

    async def test_inventory_failure_degrades_to_fallback(self, sample_unified_vuln: Any) -> None:
        """清单不可用时降级为 CPE 占位资产（低置信度 + 证据留痕）。"""

        class BrokenInventory:
            """查询即抛异常。"""

            async def query(self, cpe: str) -> list[dict[str, Any]]:
                raise RuntimeError("CMDB 不可用")

        vuln = _vuln_with(sample_unified_vuln, [CpeMatch(vendor="paloaltonetworks", product="pan-os")])
        result = await AssetMapperAgent(inventory=BrokenInventory())(new_state(vuln))
        assets = result["affected_assets"]
        assert len(assets) == 1 and assets[0].vendor == "paloaltonetworks"
        assert result["errors"]
