/**
 * 展示层格式化工具（Day14 任务 2 / 任务 7）。
 *
 * 所有「风险等级 → 颜色 / 文案」的映射集中在这里，组件里不得再写十六进制字面量，
 * 以保证图表、徽标、KPI 卡片三处配色完全一致（token 见 ``tailwind.config.js``）。
 */

import type { DistributionKey, Severity } from "@/lib/types";

/** 风险等级的展示元数据。 */
export interface LevelMeta {
  /** 中文标签。 */
  label: string;
  /** 设计 token 颜色（与 tailwind.config.js 一致，图表库需要字面量）。 */
  color: string;
  /** 徽标 / 标签使用的 Tailwind 类名。 */
  badgeClass: string;
}

/** 风险等级元数据（顺序即图例顺序）。 */
export const LEVEL_META: Record<DistributionKey, LevelMeta> = {
  critical: {
    label: "严重",
    color: "#d62728",
    badgeClass: "bg-critical text-critical-foreground hover:bg-critical/90",
  },
  high: {
    label: "高危",
    color: "#ff7f0e",
    badgeClass: "bg-high text-high-foreground hover:bg-high/90",
  },
  medium: {
    label: "中危",
    color: "#ffbb33",
    badgeClass: "bg-medium text-medium-foreground hover:bg-medium/90",
  },
  low: {
    label: "低危",
    color: "#2ca02c",
    badgeClass: "bg-low text-low-foreground hover:bg-low/90",
  },
  unknown: {
    label: "未定级",
    color: "#94a3b8",
    badgeClass: "bg-muted text-muted-foreground hover:bg-muted/80",
  },
};

/** 图表调色板（来源柱图等非风险类图表使用）。 */
export const CHART_PALETTE: readonly string[] = [
  "#1f77b4",
  "#d62728",
  "#2ca02c",
  "#ff7f0e",
  "#9467bd",
  "#17becf",
  "#8c564b",
  "#7f7f7f",
];

/** 风险分布的固定顺序（与后端 ``SEVERITY_LEVELS`` 对齐）。 */
export const LEVEL_ORDER: readonly DistributionKey[] = ["critical", "high", "medium", "low"];

/**
 * 把任意严重度 / 风险级别归一化为分布键。
 *
 * @param value 严重度（``CRITICAL`` / ``HIGH`` / ...）或风险级别（``critical`` / ...）。
 * @returns 分布键；无法识别时返回 ``unknown``。
 */
export function toLevelKey(value: string | null | undefined): DistributionKey {
  const key = (value ?? "").trim().toLowerCase();
  if (key === "critical" || key === "high" || key === "medium" || key === "low") {
    return key;
  }
  return "unknown";
}

/**
 * 取严重度徽标的展示元数据。
 *
 * @param severity 事实层严重度。
 * @returns 元数据（未定级时返回 ``unknown`` 元数据）。
 */
export function severityMeta(severity: Severity | null | undefined): LevelMeta {
  return LEVEL_META[toLevelKey(severity)];
}

/**
 * 千分位格式化整数。
 *
 * @param value 数值。
 * @returns 形如 ``1,454`` 的字符串。
 */
export function formatCount(value: number): string {
  return new Intl.NumberFormat("zh-CN").format(Math.round(value));
}

/**
 * 格式化 ISO8601 时间为「YYYY-MM-DD HH:mm」。
 *
 * @param iso ISO8601 字符串（UTC，``Z`` 结尾）。
 * @returns 本地时区展示串；非法值返回 ``—``。
 */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) {
    return "—";
  }
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) {
    return "—";
  }
  const pad = (num: number): string => String(num).padStart(2, "0");
  return (
    `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())}` +
    ` ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`
  );
}

/**
 * 格式化日期（趋势图 tooltip 用）。
 *
 * @param value ``YYYY-MM-DD`` 或 ISO8601 串。
 * @returns 形如 ``09-30`` 的短日期；非法值原样返回。
 */
export function formatShortDate(value: string): string {
  const parts = value.slice(0, 10).split("-");
  return parts.length === 3 ? `${parts[1]}-${parts[2]}` : value;
}

/**
 * 格式化 EPSS 概率为百分比。
 *
 * @param score 概率值（0-1）或 ``null``。
 * @returns 形如 ``12.3%``；缺省返回 ``—``。
 */
export function formatPercent(score: number | null | undefined): string {
  if (score === null || score === undefined) {
    return "—";
  }
  return `${(score * 100).toFixed(1)}%`;
}
