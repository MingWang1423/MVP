"""资产映射 Agent（富化维度①，PROJECT_PLAN.md §5.6 ``asset_mapper.py``）。

从 ``UnifiedVuln.cpe_matches`` / ``affected_versions`` 出发，查询**资产清单**（CMDB / SBOM），
产出 :class:`~aisec_intel.models.enriched_vuln.AffectedAsset` 列表。

设计：
    - 资产来源抽象为 :class:`AssetInventory` 协议（``query(cpe) -> list[dict]``），
      当前提供 :class:`MockAssetInventory`（**内存 mock，接口已定型**）；
      生产接入只需实现同一协议（CMDB REST / SBOM 文件），Agent 代码零改动；
    - **不调用 LLM**：资产匹配是确定性查表；
    - 查不到资产时按 CPE 产出低置信度占位条目（明确标注证据），而不是静默返回空
      —— 让下游知道「组件已知、清单缺失」。
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from aisec_intel.enrich.state import EnrichmentState
from aisec_intel.logging_config import get_logger
from aisec_intel.models.enriched_vuln import AffectedAsset, AgentStep
from aisec_intel.models.unified_vuln import CpeMatch, UnifiedVuln

logger = get_logger(__name__)

AGENT_NAME: str = "asset_mapper"
"""节点名（写入 ``agent_trace.agent``）。"""

MODEL_TAG: str = "no-llm"
"""本节点不使用 LLM（确定性查表）。"""

INVENTORY_CONFIDENCE: float = 0.9
"""命中资产清单时的置信度。"""

FALLBACK_CONFIDENCE: float = 0.35
"""清单缺失、仅依据 CPE 推断时的置信度。"""

DEFAULT_MAX_ASSETS: int = 10
"""单条漏洞最多保留的资产数（Day11 容量保护，可用 ``ASSET_MAX_PER_VULN`` 覆盖）。

背景（Day11 P0 修复）：NVD 的 configurations 常含上百个 CPE（如 Log4Shell 有 144 个组件），
旧实现为**每个组件**都产出占位资产，随后图谱抽取器做「组件 × 资产」笛卡尔积，
最终产生 2 万+ ``INSTALLED_ON`` 边（实测 143×144≈20600）——图谱因此失去可读性。
"""

ASSET_TYPE_MAP: Mapping[str, str] = {
    "library": "library",
    "python": "library",
    "pypi": "library",
    "npm": "library",
    "golang": "library",
    "maven": "library",
    "cargo": "library",
    "application": "framework",
    "framework": "framework",
    "os": "os",
    "operating_system": "os",
    "hardware": "device",
    "device": "device",
    "service": "service",
    "cloud": "cloud",
}
"""资产类型归一化映射（清单侧取值 → ``AffectedAsset.asset_type``）。"""

DEFAULT_INVENTORY: dict[str, list[dict[str, Any]]] = {
    "ollama": [
        {
            "asset_type": "service",
            "name": "ollama-inference-gateway",
            "vendor": "内部 AI 平台组",
            "version_range": "<0.1.34",
            "ecosystem": "PyPI",
        },
        {
            "asset_type": "library",
            "name": "ollama-python-sdk",
            "vendor": "内部 AI 平台组",
            "version_range": "<0.1.34",
            "ecosystem": "PyPI",
        },
    ],
    "vllm": [
        {
            "asset_type": "service",
            "name": "vllm-inference-cluster",
            "vendor": "内部 AI 平台组",
            "version_range": ">=0.6.0,<0.6.4",
            "ecosystem": "PyPI",
        }
    ],
    "transformers": [
        {
            "asset_type": "library",
            "name": "hf-transformers-runtime",
            "vendor": "内部 NLP 组",
            "version_range": "<4.48.0",
            "ecosystem": "PyPI",
        }
    ],
    "langchain": [
        {
            "asset_type": "framework",
            "name": "langchain-agent-service",
            "vendor": "内部 Agent 平台",
            "version_range": "<0.3.15",
            "ecosystem": "PyPI",
        }
    ],
    "torch": [
        {
            "asset_type": "library",
            "name": "pytorch-training-image",
            "vendor": "内部训练平台",
            "version_range": "<2.5.1",
            "ecosystem": "PyPI",
        }
    ],
    "triton": [
        {
            "asset_type": "library",
            "name": "triton-kernel-runtime",
            "vendor": "内部训练平台",
            "version_range": "==3.0.0",
            "ecosystem": "PyPI",
        }
    ],
}
"""内置 mock 资产清单（键为小写产品名；生产替换为 CMDB / SBOM 查询）。"""


class AssetInventory(Protocol):
    """资产清单查询协议（CMDB / SBOM 适配点）。"""

    async def query(self, cpe: str) -> list[dict[str, Any]]:
        """按 CPE 查询受影响资产。

        Args:
            cpe: ``vendor:product`` 形式（如 ``ollama:ollama``）。

        Returns:
            资产条目列表；每项至少含 ``name``，可选 ``asset_type`` / ``vendor`` /
            ``version_range`` / ``ecosystem``。
        """
        ...


class MockAssetInventory:
    """内存桩资产清单（默认数据见 :data:`DEFAULT_INVENTORY`）。

    Attributes:
        inventory: ``产品名 → 资产条目``。
    """

    def __init__(self, inventory: Mapping[str, Sequence[dict[str, Any]]] | None = None) -> None:
        """初始化清单。

        Args:
            inventory: 自定义清单；``None`` 时使用 :data:`DEFAULT_INVENTORY`。
        """
        source = dict(inventory) if inventory is not None else DEFAULT_INVENTORY
        self.inventory: dict[str, list[dict[str, Any]]] = {
            key.strip().lower(): [dict(item) for item in items] for key, items in source.items()
        }

    async def query(self, cpe: str) -> list[dict[str, Any]]:
        """按 CPE 查询资产（产品名精确匹配）。

        Args:
            cpe: ``vendor:product`` 或裸产品名。

        Returns:
            资产条目列表（副本，调用方可安全修改）。
        """
        product = cpe.split(":")[-1].strip().lower()
        return [dict(item) for item in self.inventory.get(product, [])]


async def query_assets(cpe: str, *, inventory: AssetInventory | None = None) -> list[dict[str, Any]]:
    """查询受影响资产（工具函数，供 Agent 与外部脚本复用）。

    Args:
        cpe: ``vendor:product`` 或裸产品名（如 ``"ollama:ollama"``）。
        inventory: 注入的资产清单；``None`` 时使用 :class:`MockAssetInventory`。

    Returns:
        ``list[dict]`` 资产条目（查不到时为空列表）。
    """
    return await (inventory or MockAssetInventory()).query(cpe)


def cpe_keys(vuln: UnifiedVuln) -> list[str]:
    """提取 CPE 查询键（纯函数，保序去重）。

    CPE 产品已出现的组件不再用生态包名重复查询（避免同一资产重复产出）。

    Args:
        vuln: 漏洞实体。

    Returns:
        ``vendor:product`` 列表；无 CPE 时回退 ``ecosystem_packages`` 的包名。
    """
    keys: list[str] = []
    products: set[str] = set()
    for match in vuln.cpe_matches:
        key = f"{match.vendor}:{match.product}".strip(":")
        product = match.product.strip().lower()
        if key and key not in keys:
            keys.append(key)
            products.add(product)
    for package in vuln.ecosystem_packages:
        name = package.split(":")[-1].strip()
        if name and name.lower() not in products and name not in keys:
            keys.append(name)
            products.add(name.lower())
    return keys


def version_range_of(match: CpeMatch | None, *, affected_versions: Sequence[str]) -> str | None:
    """把 CPE 版本区间转成可读描述（纯函数）。

    Args:
        match: CPE 匹配项；``None`` 时回退 ``affected_versions``。
        affected_versions: 归一化层派生的受影响版本描述。

    Returns:
        形如 ``>=0.6.0,<0.6.4`` 的描述；无法确定时返回 ``affected_versions`` 首项或 ``None``。
    """
    if match is not None:
        bounds: list[str] = []
        if match.version_start_incl:
            bounds.append(f">={match.version_start_incl}")
        if match.version_start_excl:
            bounds.append(f">{match.version_start_excl}")
        if match.version_end_excl:
            bounds.append(f"<{match.version_end_excl}")
        if match.version_end_incl:
            bounds.append(f"<={match.version_end_incl}")
        if bounds:
            return ",".join(bounds)
    return affected_versions[0] if affected_versions else None


def vendor_matches(asset_vendor: str | None, cpe_vendor: str | None) -> bool:
    """判断资产厂商是否与 CPE 厂商一致（纯函数，大小写/包含关系宽松匹配）。

    语义（Day11 任务 1.1）：资产**必须**与 CPE 的 vendor 对得上，否则丢弃。
        - 任一侧缺失（``None`` / 空串）→ 视为「信息不足，无法否证」，返回 ``True``
          （由置信度与数量上限兜底，避免把所有未标厂商的行一刀切掉）；
        - 双向包含匹配：``paloaltonetworks`` ↔ ``Palo Alto Networks`` 视为同一厂商。

    Args:
        asset_vendor: 清单侧厂商。
        cpe_vendor: CPE 侧厂商。

    Returns:
        匹配（或无法否证）返回 ``True``。
    """
    left = (asset_vendor or "").strip().lower().replace(" ", "")
    right = (cpe_vendor or "").strip().lower().replace(" ", "")
    if not left or not right:
        return True
    return left == right or left in right or right in left


def asset_relevance(asset: AffectedAsset, *, product: str | None) -> tuple[float, int, str]:
    """资产相关性排序键（纯函数，**降序**排序用：置信度 → 名称命中产品 → 名称）。

    Args:
        asset: 待排序资产。
        product: 目标产品名（如 ``log4j``）；``None`` 时不参与名称得分。

    Returns:
        ``(置信度, 名称命中标志, 名称)``；调用方按 ``(-confidence, -hit, name)`` 升序排序即可。
    """
    needle = (product or "").strip().lower()
    name = asset.name.strip().lower()
    hit = 1 if needle and needle in name else 0
    return (asset.confidence, hit, name)


def asset_allowed(asset: AffectedAsset, *, cpe_vendor: str | None, product: str | None) -> bool:
    """判断资产是否与目标组件「对得上」（纯函数，Day11 任务 1.1 的准入规则）。

    规则（满足其一即保留，否则丢弃）：
        1. 厂商一致（:func:`vendor_matches`）；
        2. 资产名与组件产品名互含（大小写不敏感）——覆盖「资产清单里的 vendor 写的是
           内部归属团队、而名称含产品名」的常见形态（如 ``ollama-inference-gateway``）。

    Args:
        asset: 候选资产。
        cpe_vendor: CPE 厂商。
        product: 组件产品名。

    Returns:
        允许保留返回 ``True``。
    """
    if vendor_matches(asset.vendor, cpe_vendor):
        return True
    needle = (product or "").strip().lower()
    name = asset.name.strip().lower()
    return bool(needle) and (needle in name or name in needle)


def select_assets(
    candidates: Sequence[AffectedAsset],
    *,
    cpe_vendor: str | None = None,
    product: str | None = None,
    max_assets: int = DEFAULT_MAX_ASSETS,
) -> list[AffectedAsset]:
    """按「组件一致性 → 相关性排序 → 截断」筛选资产（纯函数，确定性）。

    这是 Day11 图谱「边爆炸」修复的**核心口径**：一条漏洞最多保留 ``max_assets`` 个资产，
    排序键为「置信度 ↓ → 名称命中产品名 → 名称」，同分时按名称字典序稳定输出。

    Args:
        candidates: 候选资产（清单命中 + CPE 占位）。
        cpe_vendor: CPE 厂商（用于组件一致性校验；``None`` 表示不做该项校验）。
        product: 目标产品名（用于相关性打分与名称匹配）。
        max_assets: 保留上限（``<=0`` 时回退 :data:`DEFAULT_MAX_ASSETS`）。

    Returns:
        过滤并截断后的资产列表（保持相关度降序）。
    """
    cap = max_assets if max_assets > 0 else DEFAULT_MAX_ASSETS
    kept = [asset for asset in candidates if asset_allowed(asset, cpe_vendor=cpe_vendor, product=product)]
    kept.sort(key=lambda item: (-item.confidence, *(-value for value in asset_relevance(item, product=product)[:2])))
    return kept[:cap]


def to_asset(
    payload: Mapping[str, Any],
    *,
    default_name: str,
    confidence: float,
    refs: Sequence[str],
) -> AffectedAsset:
    """把资产清单条目转换为 :class:`AffectedAsset`（纯函数）。

    Args:
        payload: 清单条目。
        default_name: 缺失 ``name`` 时的回退名。
        confidence: 置信度。
        refs: 证据标识。

    Returns:
        :class:`AffectedAsset`。
    """
    raw_type = str(payload.get("asset_type") or "other").strip().lower()
    asset_type = ASSET_TYPE_MAP.get(raw_type, "other")
    return AffectedAsset(
        asset_type=asset_type,  # type: ignore[arg-type]
        name=str(payload.get("name") or default_name),
        vendor=(str(payload["vendor"]) if payload.get("vendor") else None),
        version_range=(str(payload["version_range"]) if payload.get("version_range") else None),
        ecosystem=(str(payload["ecosystem"]) if payload.get("ecosystem") else None),
        confidence=confidence,
        evidence_refs=[str(ref) for ref in refs],
    )


class AssetMapperAgent:
    """资产映射节点（可调用对象，供 LangGraph 直接注册）。

    Attributes:
        inventory: 注入的资产清单（默认 :class:`MockAssetInventory`）。
    """

    def __init__(
        self,
        *,
        inventory: AssetInventory | None = None,
        max_assets: int = DEFAULT_MAX_ASSETS,
    ) -> None:
        """初始化节点。

        Args:
            inventory: 资产清单实现；``None`` 时使用内置 mock（生产替换为 CMDB / SBOM 适配器）。
            max_assets: 单条漏洞最多保留的资产数（Day11 容量保护，来自 ``ASSET_MAX_PER_VULN``）。
        """
        self._inventory: AssetInventory = inventory or MockAssetInventory()
        self._max_assets = max_assets if max_assets > 0 else DEFAULT_MAX_ASSETS

    async def __call__(self, state: EnrichmentState) -> dict[str, Any]:
        """查询受影响资产并返回状态增量。

        Args:
            state: 富化图状态。

        Returns:
            含 ``affected_assets`` / ``agent_steps`` / ``errors`` 的增量字典。
        """
        started = time.perf_counter()
        vuln = state["unified_vuln"]
        keys = cpe_keys(vuln)
        errors: list[str] = []
        candidates: list[AffectedAsset] = []
        refs = [state.get("trace_id") or vuln.vuln_id]

        for key in keys:
            match = next(
                (item for item in vuln.cpe_matches if f"{item.vendor}:{item.product}" == key),
                None,
            )
            vendor = match.vendor if match else None
            product = key.split(":")[-1]
            version_range = version_range_of(match, affected_versions=vuln.affected_versions)
            try:
                rows = await query_assets(key, inventory=self._inventory)
            except Exception as exc:  # noqa: BLE001 - 清单不可用不阻断富化
                errors.append(f"{AGENT_NAME}: 查询 {key} 失败（{type(exc).__name__}: {exc}）")
                logger.warning(f"资产清单查询失败：{key} → {exc!r}")
                rows = []

            if rows:
                # 组件一致性（Day11 任务 1.1）：厂商不符且名称与产品无关的清单行 → 丢弃
                candidates.extend(
                    asset
                    for asset in (
                        to_asset(row, default_name=key, confidence=INVENTORY_CONFIDENCE, refs=[*refs, f"cpe:{key}"])
                        for row in rows
                    )
                    if asset_allowed(asset, cpe_vendor=vendor, product=product)
                )
            else:
                candidates.append(
                    AffectedAsset(
                        asset_type="library",
                        name=product,
                        vendor=vendor,
                        version_range=version_range,
                        ecosystem=("PyPI" if product in {p.split(":")[-1] for p in vuln.ecosystem_packages} else None),
                        confidence=FALLBACK_CONFIDENCE,
                        evidence_refs=[*refs, f"cpe:{key}", "清单未命中（按 CPE 推断）"],
                    )
                )

        # 相关性排序 + 截断（核心容量保护：一条漏洞最多 max_assets 个资产）
        assets = select_assets(candidates, max_assets=self._max_assets)
        dropped = len(candidates) - len(assets)
        if dropped > 0:
            logger.info(f"资产截断：candidates={len(candidates)} kept={len(assets)} dropped={dropped}")

        if not keys:
            errors.append(f"{AGENT_NAME}: 无 CPE / 生态包信息，无法映射资产")

        step = AgentStep(
            agent=AGENT_NAME,
            round=int(state.get("round", 0)),
            confidence=round(max((asset.confidence for asset in assets), default=0.0), 3),
            latency_ms=int((time.perf_counter() - started) * 1000),
            model_used=MODEL_TAG,
            output_digest=f"cpe={len(keys)} assets={len(assets)} dropped={dropped}",
            error=errors[0] if errors else None,
        )
        return {"affected_assets": assets, "agent_steps": [step], "errors": errors}

