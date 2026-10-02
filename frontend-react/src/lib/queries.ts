/**
 * TanStack Query Hooks（Day14 任务 5）。
 *
 * 约定：
 * - 查询键集中在 :data:`queryKeys`，便于精确失效（例如问答成功后刷新统计）；
 * - ``stats`` 的 ``staleTime`` 取 60s 并开启窗口聚焦刷新，兼顾实时性与请求量；
 * - ``useVuln`` 在 ``cveId`` 为空时 **不发起请求**（``enabled=false``）。
 */

import {
  useMutation,
  useQuery,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { askQA, getStats, getVuln, listVulns } from "@/lib/api";
import type {
  AskRequest,
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
 * 漏洞列表查询。
 *
 * @param params 过滤与分页参数。
 * @returns TanStack Query 结果对象。
 */
export function useVulns(params: VulnListParams = {}): UseQueryResult<VulnListResponse> {
  return useQuery({
    queryKey: queryKeys.vulns(params),
    queryFn: () => listVulns(params),
    staleTime: STATS_STALE_MS,
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
