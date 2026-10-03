/**
 * 后端 API 客户端（Day14 任务 5）。
 *
 * 设计要点：
 * 1. **单实例**：所有请求走同一个 Axios 实例，便于统一超时 / 基地址 / 错误处理；
 * 2. **统一错误处理**：拦截器把后端 ``{"detail": "..."}`` 转成 :class:`ApiError`，
 *    并弹一次 Sonner Toast（同一错误以固定 ``toastId`` 去重，避免轮询刷屏）；
 * 3. **只封装业务语义**：``getStats`` / ``listVulns`` / ``getVuln`` / ``askQA``。
 *
 * 基地址来源（本地 / 云端可切换，见 :func:`getApiMode` / :func:`getBaseUrl`）：
 * - ``local``（默认）：``VITE_API_URL_LOCAL``（开发态 ``http://localhost:8000``）；
 *   该变量与 ``VITE_API_URL`` 都为空时回退**同源相对路径** ``/api/v1/...``
 *   （开发态走 Vite 代理、容器态走 nginx 同源反代）；
 * - ``cloud``：``VITE_API_URL_CLOUD``（云服务器对外地址，未配置时不允许切换）；
 * - 模式持久化在 ``localStorage``，由**请求拦截器**逐次读取，切换后无需重建实例。
 */

import axios, { AxiosError, type AxiosInstance } from "axios";
import { toast } from "sonner";

import type {
  AskRequest,
  DataQualityParams,
  DataQualityResponse,
  GraphOverviewResponse,
  GraphResponse,
  PaperDetailResponse,
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

/** 数据质量请求超时（后端需重放 L2 纯函数，首次冷启动约 1–3 秒）。 */
const DATA_QUALITY_TIMEOUT_MS = 60_000;

/** 后端模式：``local`` 本地后端 / ``cloud`` 云端后端。 */
export type ApiMode = "local" | "cloud";

/** localStorage 键名：后端模式（刷新页面后仍生效）。 */
export const API_MODE_STORAGE_KEY = "aisec-intel-api-mode";

/**
 * 规范化 API 基地址（纯函数）。
 *
 * 去掉首尾空白与末尾斜杠；**模板占位符**（含 ``<`` / ``>``，例如
 * ``http://<云服务器IP>:8000``）视为未配置，返回空串，避免把非法地址交给 Axios。
 *
 * @param raw 原始环境变量值。
 * @returns 规范化后的基地址；空串表示未配置（回退同源相对路径）。
 */
export function normalizeBaseUrl(raw: string | undefined): string {
  const value = (raw ?? "").trim();
  if (!value || value.includes("<") || value.includes(">")) {
    return "";
  }
  return value.replace(/\/+$/, "");
}

/**
 * 本地后端基地址：``VITE_API_URL_LOCAL`` → ``VITE_API_URL``（兼容旧变量）→ ``""``（同源）。
 *
 * 容器部署时不注入 ``VITE_API_URL_LOCAL``，故落回 ``VITE_API_URL`` 或空串，
 * 前端继续请求相对路径 ``/api/v1/...``，由 nginx 同源反代到 ``api:8000``（行为与迁移前一致）。
 */
const LOCAL_BASE_URL: string = normalizeBaseUrl(
  import.meta.env.VITE_API_URL_LOCAL ?? import.meta.env.VITE_API_URL ?? "",
);

/** 云端后端基地址（未配置时为空串）。 */
const CLOUD_BASE_URL: string = normalizeBaseUrl(import.meta.env.VITE_API_URL_CLOUD ?? "");

/** 缺省模式：``VITE_API_DEFAULT``（仅 ``cloud`` 视为云端，其余一律 ``local``）。 */
const DEFAULT_MODE: ApiMode =
  (import.meta.env.VITE_API_DEFAULT ?? "").trim().toLowerCase() === "cloud" ? "cloud" : "local";

/**
 * 云端后端是否已配置（未配置时只允许停留在本地模式）。
 *
 * @returns ``VITE_API_URL_CLOUD`` 是否为可用地址。
 */
export function isCloudConfigured(): boolean {
  return CLOUD_BASE_URL.length > 0;
}

/**
 * 读取当前生效的后端模式。
 *
 * 优先级：``localStorage``（用户手动切换）→ ``VITE_API_DEFAULT`` → ``local``；
 * 云端地址未配置时**强制回退** ``local``，避免历史 localStorage 把页面锁死在不可用地址上。
 *
 * @returns 当前模式。
 */
export function getApiMode(): ApiMode {
  if (!isCloudConfigured()) {
    return "local";
  }
  if (typeof window === "undefined") {
    return DEFAULT_MODE;
  }
  const raw = window.localStorage.getItem(API_MODE_STORAGE_KEY);
  if (raw === "cloud" || raw === "local") {
    return raw;
  }
  return DEFAULT_MODE;
}

/**
 * 设置后端模式并持久化到 ``localStorage``。
 *
 * @param mode 目标模式；调用方负责在切换后刷新页面，让查询缓存与新地址一致。
 */
export function setApiMode(mode: ApiMode): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(API_MODE_STORAGE_KEY, mode);
}

/**
 * 解析指定模式下的 API 基地址。
 *
 * @param mode 模式，缺省取当前模式。
 * @returns 基地址；空串表示与页面同源（开发态 Vite 代理 / 容器态 nginx 反代）。
 */
export function getBaseUrl(mode: ApiMode = getApiMode()): string {
  if (mode === "cloud" && CLOUD_BASE_URL) {
    return CLOUD_BASE_URL;
  }
  return LOCAL_BASE_URL;
}

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
  baseURL: getBaseUrl(),
  timeout: DEFAULT_TIMEOUT_MS,
  headers: { "Content-Type": "application/json" },
  paramsSerializer: { serialize: serializeParams },
});

/**
 * 请求拦截器：每次请求按**当前**模式动态覆盖 ``baseURL``。
 *
 * 切换后端只改 ``localStorage``，无需重建 Axios 实例；配合页面刷新，
 * 切换后所有请求（含 TanStack Query 重放）都会走新地址。
 */
apiClient.interceptors.request.use((config) => {
  config.baseURL = getBaseUrl();
  return config;
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

/**
 * 获取全图概览（多 CVE 合并，无中心 CVE）。
 *
 * @param limit 参与合并的漏洞条数（按富化风险分倒序）。
 * @param maxNodes 合并后的节点上限。
 * @returns 概览响应（``cve_ids`` 给出参与合并的漏洞）。
 */
export async function getGraphOverview(limit?: number, maxNodes?: number): Promise<GraphOverviewResponse> {
  const { data } = await apiClient.get<GraphOverviewResponse>(`${API_PREFIX}/graph`, {
    params: { limit, max_nodes: maxNodes },
  });
  return data;
}

/**
 * 获取数据质量快照（KPI + 各源明细 + 趋势 + Markdown 报告）。
 *
 * @param params 采样上限 / 趋势天数 / 是否带报告 / 是否强制刷新。
 * @returns 质量页所需的结构化数据。
 */
export async function getDataQuality(params: DataQualityParams = {}): Promise<DataQualityResponse> {
  const { data } = await apiClient.get<DataQualityResponse>(`${API_PREFIX}/data-quality`, {
    params,
    timeout: DATA_QUALITY_TIMEOUT_MS,
  });
  return data;
}

/**
 * 获取单篇论文详情（Day17 任务 2：论文关联 Tab 点击卡片加载）。
 *
 * @param paperId 论文主键（arXiv ID / OpenAlex Work ID，容忍版本号后缀）。
 * @returns 论文详情（标题 / 作者 / 摘要 / 链接 / 发布时间）。
 */
export async function getPaper(paperId: string): Promise<PaperDetailResponse> {
  const { data } = await apiClient.get<PaperDetailResponse>(
    `${API_PREFIX}/papers/${encodeURIComponent(paperId)}`,
  );
  return data;
}
