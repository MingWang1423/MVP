/**
 * TanStack Query Hooks（Day14 任务 5）。
 *
 * 约定：
 * - 查询键集中在 :data:`queryKeys`，便于精确失效（例如问答成功后刷新统计）；
 * - ``stats`` 的 ``staleTime`` 取 60s 并开启窗口聚焦刷新，兼顾实时性与请求量；
 * - ``useVuln`` 在 ``cveId`` 为空时 **不发起请求**（``enabled=false``）。
 */

import {
  keepPreviousData,
  useMutation,
  useQuery,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { askQA, getDataQuality, getGraph, getGraphOverview, getStats, getVuln, listVulns } from "@/lib/api";
import type {
  AskRequest,
  DataQualityParams,
  DataQualityResponse,
  GraphOverviewResponse,
  GraphResponse,
  QAResponse,
  StatsResponse,
  VulnDetailResponse,
  VulnListParams,
  VulnListResponse,
} from "@/lib/types";

/** 查询参数类型：仪表盘统计。 */
export interface StatsParams {
  timeline_days?: number;
  high_risk_limit?: number;
}

/** 全局查询键工厂。 */
export const queryKeys = {
  stats: (params: StatsParams = {}) => ["stats", params] as const,
  vulns: (params: VulnListParams = {}) => ["vulns", params] as const,
  vuln: (cveId: string) => ["vuln", cveId] as const,
  graph: (cveId: string) => ["graph", cveId] as const,
  graphOverview: (limit: number) => ["graph", "overview", limit] as const,
  dataQuality: (params: DataQualityParams = {}) => ["data-quality", params] as const,
};

/** 统计数据保鲜时长（毫秒）。 */
const STATS_STALE_MS = 60_000;

/**
 * 仪表盘统计查询。
 *
 * @param params 趋势天数（默认 30）与高危清单条数（默认 10）。
 * @returns TanStack Query 结果对象。
 */
export function useStats(params: StatsParams = {}): UseQueryResult<StatsResponse> {
  return useQuery({
    queryKey: queryKeys.stats(params),
    queryFn: () => getStats(params),
    staleTime: STATS_STALE_MS,
    refetchOnWindowFocus: true,
  });
}

/**
 * 漏洞列表查询（翻页 / 改筛选时保留上一页数据，避免表格闪烁）。
 *
 * @param params 过滤与分页参数。
 * @returns TanStack Query 结果对象。
 */
export function useVulns(params: VulnListParams = {}): UseQueryResult<VulnListResponse> {
  return useQuery({
    queryKey: queryKeys.vulns(params),
    queryFn: () => listVulns(params),
    staleTime: STATS_STALE_MS,
    placeholderData: keepPreviousData,
  });
}

/**
 * 知识图谱子图查询（详情页「图谱子图」Tab；``cveId`` 为空时不请求）。
 *
 * @param cveId 漏洞主键。
 * @param enabled 是否启用查询（如仅在对应 Tab 激活时才拉取）。
 * @returns TanStack Query 结果对象。
 */
export function useGraph(cveId?: string, enabled = true): UseQueryResult<GraphResponse> {
  const key = (cveId ?? "").trim();
  return useQuery({
    queryKey: queryKeys.graph(key),
    queryFn: () => getGraph(key),
    enabled: enabled && key.length > 0,
    staleTime: 5 * 60_000,
  });
}

/**
 * 漏洞详情查询（``cveId`` 为空时不请求）。
 *
 * @param cveId 漏洞主键。
 * @param enabled 是否启用查询（默认由 ``cveId`` 决定）。
 * @returns TanStack Query 结果对象。
 */
export function useVuln(cveId?: string, enabled = true): UseQueryResult<VulnDetailResponse> {
  const key = (cveId ?? "").trim();
  return useQuery({
    queryKey: queryKeys.vuln(key),
    queryFn: () => getVuln(key),
    enabled: enabled && key.length > 0,
    staleTime: STATS_STALE_MS,
  });
}

/**
 * 问答请求（命令式，失败不自动重试，避免重复消耗 LLM 额度）。
 *
 * @returns TanStack Query 的 mutation 对象。
 */
export function useQA(): UseMutationResult<QAResponse, Error, AskRequest> {
  return useMutation({
    mutationFn: (payload: AskRequest) => askQA(payload),
    retry: 0,
  });
}

/**
 * 全图概览查询（图谱页默认视图；``CVE`` 参数为空时使用）。
 *
 * @param limit 参与合并的漏洞条数。
 * @param enabled 是否启用查询（例如切到单 CVE 视图时关闭）。
 * @returns TanStack Query 结果对象。
 */
export function useGraphOverview(
  limit = 20,
  enabled = true,
): UseQueryResult<GraphOverviewResponse> {
  return useQuery({
    queryKey: queryKeys.graphOverview(limit),
    queryFn: () => getGraphOverview(limit),
    enabled,
    staleTime: 5 * 60_000,
  });
}

/**
 * 数据质量查询（后端已带 5 分钟缓存，故前端 ``staleTime`` 与之对齐）。
 *
 * @param params 采样上限 / 趋势天数 / 是否带报告 / 是否强制刷新。
 * @returns TanStack Query 结果对象。
 */
export function useDataQuality(params: DataQualityParams = {}): UseQueryResult<DataQualityResponse> {
  return useQuery({
    queryKey: queryKeys.dataQuality(params),
    queryFn: () => getDataQuality(params),
    staleTime: 5 * 60_000,
  });
}
