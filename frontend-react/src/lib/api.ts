/**
 * 后端 API 客户端（Day14 任务 5）。
 *
 * 设计要点：
 * 1. **单实例**：所有请求走同一个 Axios 实例，便于统一超时 / 基地址 / 错误处理；
 * 2. **统一错误处理**：拦截器把后端 ``{"detail": "..."}`` 转成 :class:`ApiError`，
 *    并弹一次 Sonner Toast（同一错误以固定 ``toastId`` 去重，避免轮询刷屏）；
 * 3. **只封装业务语义**：``getStats`` / ``listVulns`` / ``getVuln`` / ``askQA``。
 *
 * 基地址来源：
 * - ``VITE_API_URL`` 非空 → 直连该地址；
 * - 为空（开发默认）→ 用相对路径 ``/api/v1/...``，由 Vite 代理转发到 :8000。
 */

import axios, { AxiosError, type AxiosInstance } from "axios";
import { toast } from "sonner";

import type {
  AskRequest,
  GraphResponse,
  QAResponse,
  StatsResponse,
  VulnDetailResponse,
  VulnListParams,
  VulnListResponse,
} from "@/lib/types";

/** 统一请求前缀（与后端 ``api/main.py`` 的 ``API_PREFIX`` 保持一致）。 */
export const API_PREFIX = "/api/v1";

/** 请求超时（毫秒）：问答链路较慢，单列常量便于按端点覆盖。 */
const DEFAULT_TIMEOUT_MS = 20_000;

/** 问答请求超时（LLM + 多跳推理耗时更长）。 */
const QA_TIMEOUT_MS = 120_000;

/** 环境变量中的 API 基地址（空串表示走 Vite 代理）。 */
const BASE_URL: string = (import.meta.env.VITE_API_URL ?? "").trim();

/**
 * 序列化查询参数（纯函数）。
 *
 * Axios 默认把数组序列化成 ``key[]=a&key[]=b``（带方括号），而 FastAPI 的
 * ``list[str] = Query(...)`` 只认**重复键** ``key=a&key=b``；故自定义序列化，
 * 并顺带丢弃 ``undefined`` / ``null`` / 空串（避免后端收到空筛选值）。
 *
 * @param params 参数字典。
 * @returns 查询串（不含前导 ``?``）。
 */
export function serializeParams(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item === undefined || item === null || item === "") {
          continue;
        }
        search.append(key, String(item));
      }
      continue;
    }
    search.append(key, String(value));
  }
  return search.toString();
}

/** Axios 实例（全局唯一）。 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: DEFAULT_TIMEOUT_MS,
  headers: { "Content-Type": "application/json" },
  paramsSerializer: { serialize: serializeParams },
});

/** 后端 / 网络错误的统一封装。 */
export class ApiError extends Error {
  /** HTTP 状态码；网络层失败（无响应）时为 ``null``。 */
  readonly status: number | null;

  /** 面向用户的中文提示。 */
  readonly detail: string;

  /**
   * 构造 API 错误。
   *
   * @param detail 面向用户的提示文案。
   * @param status HTTP 状态码（无响应时为 null）。
   */
  constructor(detail: string, status: number | null) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * 从 Axios 错误中提取可读的中文提示。
 *
 * @param error Axios 抛出的错误。
 * @returns 面向用户的提示文案。
 */
function toDetail(error: AxiosError<{ detail?: unknown }>): string {
  const status = error.response?.status ?? null;
  const payload = error.response?.data as { detail?: unknown } | undefined;
  if (typeof payload?.detail === "string" && payload.detail.trim()) {
    return payload.detail;
  }
  if (status === 404) {
    return "请求的资源不存在（404）";
  }
  if (status === 429) {
    return "请求过于频繁（429），请稍后再试";
  }
  if (status !== null && status >= 500) {
    return `服务端错误（${status}），请查看后端日志`;
  }
  if (error.code === "ECONNABORTED") {
    return "请求超时，请检查后端服务是否可用";
  }
  return "无法连接到后端服务，请确认 API 已在 8000 端口启动";
}

/** 响应拦截器：统一转换错误并提示。 */
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<{ detail?: unknown }>) => {
    const status = error.response?.status ?? null;
    const detail = toDetail(error);
    toast.error(status ? `请求失败（${status}）` : "网络异常", {
      id: `api-error-${status ?? "network"}-${error.config?.url ?? ""}`,
      description: detail,
    });
    return Promise.reject(new ApiError(detail, status));
  },
);

/**
 * 拉取首页仪表盘统计。
 *
 * @param params 可选参数：趋势窗口天数、高危清单条数。
 * @returns 仪表盘统计数据。
 */
export async function getStats(
  params: { timeline_days?: number; high_risk_limit?: number } = {},
): Promise<StatsResponse> {
  const { data } = await apiClient.get<StatsResponse>(`${API_PREFIX}/stats`, { params });
  return data;
}

/**
 * 分页查询漏洞列表。
 *
 * @param params 严重度 / 来源 / 时间窗 / KEV / 分页参数。
 * @returns 分页包装后的漏洞条目。
 */
export async function listVulns(params: VulnListParams = {}): Promise<VulnListResponse> {
  const { data } = await apiClient.get<VulnListResponse>(`${API_PREFIX}/vulnerabilities`, { params });
  return data;
}

/**
 * 获取单条漏洞详情（事实层 + 富化层）。
 *
 * @param cveId 漏洞主键（大小写不敏感）。
 * @returns 详情响应。
 */
export async function getVuln(cveId: string): Promise<VulnDetailResponse> {
  const { data } = await apiClient.get<VulnDetailResponse>(
    `${API_PREFIX}/vulnerabilities/${encodeURIComponent(cveId)}`,
  );
  return data;
}

/**
 * 调用 L4 问答层（Supervisor → Reasoner → Synthesizer）。
 *
 * @param payload 问题 / 会话 ID / 召回条数 / 多跳上限。
 * @returns 带引用与推理链的结构化回答。
 */
export async function askQA(payload: AskRequest): Promise<QAResponse> {
  const { data } = await apiClient.post<QAResponse>(`${API_PREFIX}/qa/ask`, payload, {
    timeout: QA_TIMEOUT_MS,
  });
  return data;
}

/**
 * 获取某漏洞的 1 跳知识图谱子图（React Flow 格式）。
 *
 * @param cveId 漏洞主键。
 * @param limit 邻居行数上限（缺省由后端决定，默认 80）。
 * @returns 子图响应（``backend`` 明示数据来源：neo4j / postgres 降级）。
 */
export async function getGraph(cveId: string, limit?: number): Promise<GraphResponse> {
  const { data } = await apiClient.get<GraphResponse>(
    `${API_PREFIX}/graph/${encodeURIComponent(cveId)}`,
    { params: { limit } },
  );
  return data;
}
