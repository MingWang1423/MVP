/**
 * 漏洞列表筛选的纯逻辑（URL ↔ 查询参数映射，Day16 任务 1.3）。
 *
 * 设计要点：
 * 1. **URL 是唯一真相**：筛选状态全部落在 query params，刷新 / 分享链接都能复现；
 * 2. 本模块只做**纯数据转换**（不 import React / axios），便于审阅与复用；
 * 3. 时间范围在客户端换算为 ``since``（ISO8601），与服务端「时间轴」口径一致。
 */

import type { Severity, VulnListParams } from "@/lib/types";

/** 严重度选项（顺序即展示顺序）。 */
export const SEVERITY_OPTIONS: readonly Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/** 数据源选项（与 ``configs/sources.yaml`` 的已接入源对齐；``rss_blog`` 为厂商博客源）。 */
export const SOURCE_OPTIONS: readonly string[] = [
  "nvd",
  "osv",
  "ghsa",
  "kev",
  "epss",
  "vendor_github",
  "rss_blog",
];

/** 时间范围键。 */
export type TimeRangeKey = "7d" | "30d" | "90d" | "all";

/** 时间范围选项（含天数，用于换算 ``since``）。 */
export const TIME_RANGES: readonly { key: TimeRangeKey; label: string; days: number | null }[] = [
  { key: "7d", label: "近 7 天", days: 7 },
  { key: "30d", label: "近 30 天", days: 30 },
  { key: "90d", label: "近 90 天", days: 90 },
  { key: "all", label: "全部", days: null },
];

/** 每页条数选项。 */
export const PAGE_SIZE_OPTIONS: readonly number[] = [20, 50, 100];

/** 排序状态。 */
export interface SortState {
  /** 列 ID。 */
  id: string;
  /** 是否倒序。 */
  desc: boolean;
}

/** 列表页的全部筛选状态。 */
export interface VulnListFilters {
  /** 严重度多选。 */
  severities: Severity[];
  /** 数据源多选。 */
  sources: string[];
  /** 时间范围。 */
  range: TimeRangeKey;
  /** 仅 CISA KEV。 */
  kev: boolean;
  /** 仅有 PoC。 */
  hasPoc: boolean;
  /** 关键词。 */
  q: string;
  /** 页码（从 1 开始）。 */
  page: number;
  /** 每页条数。 */
  pageSize: number;
  /** 排序（客户端排序，见表格组件说明）。 */
  sort: SortState | null;
}

/** 默认筛选（URL 为空时的初始状态）。 */
export const DEFAULT_FILTERS: VulnListFilters = {
  severities: [],
  sources: [],
  range: "all",
  kev: false,
  hasPoc: false,
  q: "",
  page: 1,
  pageSize: 20,
  sort: null,
};

/** 排序状态 → URL 值（``id:desc``）。 */
export function encodeSort(sort: SortState | null): string | null {
  return sort ? `${sort.id}:${sort.desc ? "desc" : "asc"}` : null;
}

/**
 * 解析 URL 中的排序值。
 *
 * @param raw 形如 ``published_at:desc`` 的字符串。
 * @returns 排序状态；非法值返回 ``null``。
 */
export function decodeSort(raw: string | null): SortState | null {
  if (!raw) {
    return null;
  }
  const [id, direction] = raw.split(":");
  if (!id) {
    return null;
  }
  return { id, desc: direction === "desc" };
}

/**
 * 从 URL 查询参数解析筛选状态（纯函数）。
 *
 * @param params URL 查询参数。
 * @returns 解析后的筛选状态（缺省项回落到 :data:`DEFAULT_FILTERS`）。
 */
export function parseFilters(params: URLSearchParams): VulnListFilters {
  const severities = params
    .getAll("severity")
    .map((item) => item.trim().toUpperCase())
    .filter((item): item is Severity => SEVERITY_OPTIONS.includes(item as Severity));

  const sources = params
    .getAll("source")
    .map((item) => item.trim().toLowerCase())
    .filter((item) => item.length > 0);

  const rawRange = params.get("range");
  const range: TimeRangeKey = TIME_RANGES.some((item) => item.key === rawRange)
    ? (rawRange as TimeRangeKey)
    : DEFAULT_FILTERS.range;

  const page = Number.parseInt(params.get("page") ?? "1", 10);
  const pageSize = Number.parseInt(params.get("size") ?? String(DEFAULT_FILTERS.pageSize), 10);

  return {
    severities: [...new Set(severities)],
    sources: [...new Set(sources)],
    range,
    kev: params.get("kev") === "1",
    hasPoc: params.get("poc") === "1",
    q: params.get("q")?.trim() ?? "",
    page: Number.isFinite(page) && page > 0 ? page : 1,
    pageSize: PAGE_SIZE_OPTIONS.includes(pageSize) ? pageSize : DEFAULT_FILTERS.pageSize,
    sort: decodeSort(params.get("sort")),
  };
}

/**
 * 把筛选状态序列化为 URL 查询参数（纯函数，只写非默认项）。
 *
 * @param filters 筛选状态。
 * @returns ``URLSearchParams``（可直接交给 ``setSearchParams``）。
 */
export function buildSearchParams(filters: VulnListFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const severity of filters.severities) {
    params.append("severity", severity);
  }
  for (const source of filters.sources) {
    params.append("source", source);
  }
  if (filters.range !== DEFAULT_FILTERS.range) {
    params.set("range", filters.range);
  }
  if (filters.kev) {
    params.set("kev", "1");
  }
  if (filters.hasPoc) {
    params.set("poc", "1");
  }
  if (filters.q) {
    params.set("q", filters.q);
  }
  if (filters.page > 1) {
    params.set("page", String(filters.page));
  }
  if (filters.pageSize !== DEFAULT_FILTERS.pageSize) {
    params.set("size", String(filters.pageSize));
  }
  const sort = encodeSort(filters.sort);
  if (sort) {
    params.set("sort", sort);
  }
  return params;
}

/**
 * 计算时间范围对应的 ``since``（纯函数）。
 *
 * @param range 时间范围键。
 * @param now 基准时间（默认当前时间；测试可注入）。
 * @returns ISO8601 字符串；``all`` 返回 ``undefined``（不传该筛选）。
 */
export function rangeToSince(range: TimeRangeKey, now: Date = new Date()): string | undefined {
  const option = TIME_RANGES.find((item) => item.key === range);
  if (!option || option.days === null) {
    return undefined;
  }
  const since = new Date(now.getTime() - option.days * 24 * 60 * 60 * 1000);
  return since.toISOString();
}

/**
 * 筛选状态 → 后端查询参数（纯函数）。
 *
 * @param filters 筛选状态。
 * @returns ``GET /api/v1/vulnerabilities`` 的查询参数。
 */
export function toApiParams(filters: VulnListFilters): VulnListParams {
  return {
    severity: filters.severities.length > 0 ? filters.severities : undefined,
    source: filters.sources.length > 0 ? filters.sources : undefined,
    since: rangeToSince(filters.range),
    kev: filters.kev ? true : undefined,
    has_poc: filters.hasPoc ? true : undefined,
    q: filters.q || undefined,
    limit: filters.pageSize,
    offset: (filters.page - 1) * filters.pageSize,
  };
}

/** 判断是否存在任一有效筛选（用于「重置」按钮的可用态与空态文案）。 */
export function hasActiveFilters(filters: VulnListFilters): boolean {
  return (
    filters.severities.length > 0 ||
    filters.sources.length > 0 ||
    filters.range !== DEFAULT_FILTERS.range ||
    filters.kev ||
    filters.hasPoc ||
    filters.q.length > 0
  );
}
