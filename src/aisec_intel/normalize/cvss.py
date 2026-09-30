"""CVSS 向量解析（PROJECT_PLAN.md §2 normalize 层）。

**纯函数层**：无 IO、无全局状态、禁止 LLM（§0 约束 1）。

实现范围：
    - **CVSS v2.0 / v3.0 / v3.1**：按 FIRST 官方公式从向量串计算基础分（含 ``roundup``）。
    - **CVSS v4.0**：v4 评分依赖 MacroVector 查表，本阶段**不自行计算**；
      要求调用方提供 ``base_score``（源侧通常已给出），否则显式报错而非猜分。

评分公式来源：FIRST CVSS v3.1 Specification §7.4 / CVSS v2 Guide §3.2.1。
"""

from __future__ import annotations

import math
from typing import Any

from aisec_intel.models.unified_vuln import CVSSVector, Severity

CVSS_V2: str = "2.0"
CVSS_V3_0: str = "3.0"
CVSS_V3_1: str = "3.1"
CVSS_V4_0: str = "4.0"
SUPPORTED_VERSIONS: tuple[str, ...] = (CVSS_V2, CVSS_V3_0, CVSS_V3_1, CVSS_V4_0)
"""支持的 CVSS 版本。"""

_V3_PREFIXES: dict[str, str] = {"CVSS:3.0": CVSS_V3_0, "CVSS:3.1": CVSS_V3_1, "CVSS:4.0": CVSS_V4_0}

_AV: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_UI: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_V3: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.0}

_AV_V2: dict[str, float] = {"L": 0.395, "A": 0.646, "N": 1.0}
_AC_V2: dict[str, float] = {"H": 0.35, "M": 0.61, "L": 0.71}
_AU_V2: dict[str, float] = {"M": 0.45, "S": 0.56, "N": 0.704}
_CIA_V2: dict[str, float] = {"N": 0.0, "P": 0.275, "C": 0.660}


def _roundup(value: float) -> float:
    """CVSS v3.1 官方 ``roundup``（向上进位到 1 位小数）。

    Args:
        value: 原始分数。

    Returns:
        进位后的分数（保留 1 位小数）。
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _round1(value: float) -> float:
    """四舍五入到 1 位小数（CVSS v2 使用）。"""
    return math.floor(value * 10 + 0.5) / 10.0


def parse_vector_metrics(vector: str) -> dict[str, str]:
    """把向量串解析为 ``{metric: value}`` 字典（版本前缀作 ``PREFIX``）。

    Args:
        vector: 形如 ``CVSS:3.1/AV:N/AC:L/...`` 或 ``AV:N/AC:L/Au:N/...``。

    Returns:
        指标字典（键统一大写，如 ``AU``）；无法解析的片段被忽略。
    """
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        segment = part.strip()
        if not segment:
            continue
        if segment.upper().startswith("CVSS:"):
            metrics["PREFIX"] = segment.upper()
            continue
        if ":" not in segment:
            continue
        key, _, value = segment.partition(":")
        metrics[key.strip().upper()] = value.strip().upper()
    return metrics


def detect_version(vector: str) -> str | None:
    """判断向量串的 CVSS 版本。

    Args:
        vector: 向量串。

    Returns:
        ``2.0`` / ``3.0`` / ``3.1`` / ``4.0``；无法判断时返回 ``None``。
    """
    prefix = parse_vector_metrics(vector).get("PREFIX", "")
    if prefix in _V3_PREFIXES:
        return _V3_PREFIXES[prefix]
    metrics = parse_vector_metrics(vector)
    if "AU" in metrics:
        return CVSS_V2
    if {"AV", "AC", "PR", "UI", "S"} <= set(metrics):
        return CVSS_V3_1
    if {"AV", "AC", "AU", "C", "I", "A"} <= set(metrics):
        return CVSS_V2
    return None


def score_v3(vector: str) -> float:
    """按 CVSS v3.0/v3.1 公式计算基础分。

    Args:
        vector: v3.x 向量串。

    Returns:
        基础分（0.0–10.0，已 roundup）。

    Raises:
        ValueError: 缺少必需指标或指标取值非法。
    """
    metrics = parse_vector_metrics(vector)
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    missing = [key for key in required if key not in metrics]
    if missing:
        raise ValueError(f"CVSS v3 向量缺少指标 {missing}：{vector!r}")
    try:
        scope = metrics["S"]
        attack_vector = _AV[metrics["AV"]]
        attack_complexity = _AC[metrics["AC"]]
        privileges = _PR[scope][metrics["PR"]]
        user_interaction = _UI[metrics["UI"]]
        confidentiality = _CIA_V3[metrics["C"]]
        integrity = _CIA_V3[metrics["I"]]
        availability = _CIA_V3[metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"CVSS v3 向量指标取值非法 {exc}：{vector!r}") from exc

    iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    impact_scope_changed = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    impact = impact_scope_changed if scope == "C" else 6.42 * iss
    exploitability = 8.22 * attack_vector * attack_complexity * privileges * user_interaction
    if impact <= 0:
        return 0.0
    if scope == "C":
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def score_v2(vector: str) -> float:
    """按 CVSS v2 公式计算基础分。

    Args:
        vector: v2 向量串。

    Returns:
        基础分（0.0–10.0，四舍五入到 1 位小数）。

    Raises:
        ValueError: 缺少必需指标或指标取值非法。
    """
    metrics = parse_vector_metrics(vector)
    required = ("AV", "AC", "AU", "C", "I", "A")
    missing = [key for key in required if key not in metrics]
    if missing:
        raise ValueError(f"CVSS v2 向量缺少指标 {missing}：{vector!r}")
    try:
        attack_vector = _AV_V2[metrics["AV"]]
        attack_complexity = _AC_V2[metrics["AC"]]
        authentication = _AU_V2[metrics["AU"]]
        confidentiality = _CIA_V2[metrics["C"]]
        integrity = _CIA_V2[metrics["I"]]
        availability = _CIA_V2[metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"CVSS v2 向量指标取值非法 {exc}：{vector!r}") from exc

    impact = 10.41 * (1 - (1 - confidentiality) * (1 - integrity) * (1 - availability))
    exploitability = 20 * attack_vector * attack_complexity * authentication
    factor = 0.0 if impact == 0 else 1.176
    return _round1((0.6 * impact + 0.4 * exploitability - 1.5) * factor)


def severity_from_score(version: str, score: float) -> Severity:
    """按版本阈值把分数映射为严重度等级。

    Args:
        version: ``2.0`` / ``3.0`` / ``3.1`` / ``4.0``。
        score: 基础分（0.0–10.0）。

    Returns:
        ``NONE`` / ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``。

    Raises:
        ValueError: 版本不支持或分数越界。
    """
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"不支持的 CVSS 版本：{version!r}（可选 {SUPPORTED_VERSIONS}）")
    if not 0.0 <= score <= 10.0:
        raise ValueError(f"CVSS 分数越界：{score}")
    if version == CVSS_V2:
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def parse_cvss_vector(vector: str, *, base_score: float | None = None) -> CVSSVector:
    """把向量串解析为契约模型 :class:`~aisec_intel.models.unified_vuln.CVSSVector`。

    分数优先级：``base_score``（源侧提供） > 自行计算（v2/v3.x） > 报错（v4.0）。

    Args:
        vector: 向量串。
        base_score: 源侧提供的基础分（NVD/GHSA 通常提供，优先采用以避免口径差异）。

    Returns:
        ``CVSSVector``。

    Raises:
        ValueError: 版本无法识别；或 v4.0 未提供 ``base_score``；或向量非法。
    """
    version = detect_version(vector)
    if version is None:
        raise ValueError(f"无法识别 CVSS 版本：{vector!r}")
    if base_score is None:
        if version == CVSS_V4_0:
            raise ValueError("CVSS v4.0 评分需由源侧提供 base_score（本层不实现 v4 查表评分）")
        base_score = score_v2(vector) if version == CVSS_V2 else score_v3(vector)
    score = float(base_score)
    return CVSSVector(
        version=version,  # type: ignore[arg-type]
        vector=vector.strip(),
        base_score=round(score, 1),
        severity=severity_from_score(version, round(score, 1)),
    )


def _dedupe_vectors(vectors: list[CVSSVector]) -> list[CVSSVector]:
    """按 (version, vector) 去重并排序，保证输出确定。"""
    seen: set[tuple[str, str]] = set()
    unique: list[CVSSVector] = []
    for item in vectors:
        key = (item.version, item.vector)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return sorted(unique, key=lambda item: item.version)


def extract_cvss_vectors(payload: dict[str, Any]) -> list[CVSSVector]:
    """从源侧 payload 中抽取全部 CVSS 向量（兼容 NVD / GHSA / OSV）。

    支持的形态：
        - NVD：``metrics.cvssMetricV31/V30/V2[].cvssData.{vectorString,baseScore}``
        - GHSA：``cvss.{vectorString,score}``、``cvssSeverities.*.score``
        - OSV：``severity: [{type: "CVSS_V3", score: "CVSS:3.1/..."}]``

    Args:
        payload: 源侧 JSON 对象。

    Returns:
        去重并按版本升序排列的 ``CVSSVector`` 列表（无向量时为空列表）。
    """
    vectors: list[CVSSVector] = []

    metrics = payload.get("metrics")
    if isinstance(metrics, dict):
        for metric_name in ("cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for entry in metrics.get(metric_name) or []:
                data = entry.get("cvssData") if isinstance(entry, dict) else None
                if not isinstance(data, dict):
                    continue
                vectors.extend(_safe_vector(data.get("vectorString"), data.get("baseScore")))

    cvss = payload.get("cvss")
    if isinstance(cvss, dict):
        vectors.extend(_safe_vector(cvss.get("vectorString"), cvss.get("score") or cvss.get("baseScore")))

    for entry in payload.get("severity") or []:
        if isinstance(entry, dict):
            vectors.extend(_safe_vector(entry.get("score"), None))

    return _dedupe_vectors(vectors)


def _safe_vector(vector: Any, base_score: Any) -> list[CVSSVector]:
    """容错解析单个向量（失败时返回空列表，采集不得因脏数据中断）。"""
    if not isinstance(vector, str) or not vector.strip():
        return []
    score: float | None
    try:
        score = None if base_score in (None, "") else float(base_score)
    except (TypeError, ValueError):
        score = None
    try:
        return [parse_cvss_vector(vector, base_score=score)]
    except ValueError:
        return []
