/**
 * 后端 API 契约的 TypeScript 镜像（Day14 任务 5）。
 *
 * 与 FastAPI 的 Pydantic 出参一一对应，字段名保持 snake_case，**不做前端重命名**：
 * 一旦后端 §10 契约变更，本文件是唯一需要同步的位置。
 */

/** 事实层严重度（``UnifiedVuln.severity``）。 */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";

/** 富化层风险级别（``EnrichedVuln.risk_level``）。 */
export type RiskLevel = "low" | "medium" | "high" | "critical";

/** 风险分布 / 图表使用的统一级别键（``unknown`` 表示事实层未定级）。 */
export type DistributionKey = "critical" | "high" | "medium" | "low" | "unknown";

/** 漏洞列表条目（``GET /vulnerabilities`` 与 ``GET /stats`` 共用）。 */
export interface VulnSummary {
  vuln_id: string;
  title: string | null;
  severity: Severity | null;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  kev: boolean;
  epss_score: number | null;
  sources: string[];
  published_at: string | null;
  enriched: boolean;
}

/** ``GET /vulnerabilities`` 响应（分页包装）。 */
export interface VulnListResponse {
  items: VulnSummary[];
  total: number;
  limit: number;
  offset: number;
}

/** ``GET /vulnerabilities`` 查询参数。 */
export interface VulnListParams {
  severity?: Severity;
  source?: string;
  days?: number;
  kev_only?: boolean;
  limit?: number;
  offset?: number;
}

/** 趋势折线图上的一个点。 */
export interface TimelinePoint {
  date: string;
  count: number;
}

/** ``GET /stats`` 响应（首页仪表盘唯一数据源）。 */
export interface StatsResponse {
  total_vulns: number;
  critical_count: number;
  source_count: number;
  today_new: number;
  risk_distribution: Record<string, number>;
  source_distribution: Record<string, number>;
  timeline: TimelinePoint[];
  top_high_risk: VulnSummary[];
  generated_at: string;
}

/** CVSS 向量（事实层 ``UnifiedVuln.cvss`` 元素，契约见 ``models/unified_vuln.py``）。 */
export interface CVSSVector {
  version: "2.0" | "3.0" | "3.1" | "4.0";
  vector: string;
  base_score: number;
  severity: Severity;
}

/** CPE 2.3 匹配条目（受影响版本区间）。 */
export interface CpeMatch {
  vendor: string;
  product: string;
  version_start_incl: string | null;
  version_start_excl: string | null;
  version_end_incl: string | null;
  version_end_excl: string | null;
  vulnerable: boolean;
}

/** 外部参考链接。 */
export interface VulnReference {
  url: string;
  source: string;
  tags: string[];
}

/** 事实层实体（``GET /vulnerabilities/{cve_id}`` 的 ``unified`` 字段）。 */
export interface UnifiedVulnDto {
  schema_version: string;
  vuln_id: string;
  aliases: string[];
  trace_ids: string[];
  title: string | null;
  description: string;
  lang: string | null;
  cvss: CVSSVector[];
  severity: Severity | null;
  cwe_ids: string[];
  cpe_matches: CpeMatch[];
  affected_versions: string[];
  ecosystem_packages: string[];
  references: VulnReference[];
  kev: boolean;
  epss_score: number | null;
  epss_percentile: number | null;
  published_at: string | null;
  modified_at: string | null;
  sources: string[];
  normalized_at: string;
}

/** 富化层实体（``GET /vulnerabilities/{cve_id}`` 的 ``enriched`` 字段）。

 * 未富化时为 ``null``；本任务只声明首页与列表页会用到的核心字段，
 * 七维字段在 P8 详情页落地时补齐（后端契约本身已冻结）。
 */
export interface EnrichedVulnDto extends Record<string, unknown> {
  vuln_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  risk_breakdown: Record<string, number>;
  confidence: number;
  model_used: string;
  enriched_at: string;
  review_status: string;
}

/** ``GET /vulnerabilities/{cve_id}`` 响应（事实层 + 富化层并列）。 */
export interface VulnDetailResponse {
  unified: UnifiedVulnDto;
  enriched: EnrichedVulnDto | null;
}

/** 引用来源类型。 */
export type CitationSource = "pg" | "neo4j" | "chroma" | "raw";

/** 一条可回溯引用。 */
export interface Citation {
  source_type: CitationSource;
  locator: string;
  cve_id: string | null;
  trace_id: string | null;
  url: string | null;
  quote: string | null;
}

/** 多跳推理链中的一步。 */
export interface ReasoningStep {
  hop: number;
  question: string;
  evidence: Citation[];
  conclusion: string;
}

/** ``POST /qa/ask`` 请求体。 */
export interface AskRequest {
  query: string;
  session_id?: string | null;
  session_context?: string[];
  top_k?: number;
  max_hops?: number;
}

/** ``POST /qa/ask`` 响应体。 */
export interface QAResponse {
  schema_version: string;
  answer: string;
  citations: Citation[];
  reasoning_chain: ReasoningStep[];
  confidence: number;
  degraded: boolean;
}
