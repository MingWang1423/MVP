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
  poc_count: number;
}

/** ``GET /vulnerabilities`` 响应（分页包装）。 */
export interface VulnListResponse {
  items: VulnSummary[];
  total: number;
  limit: number;
  offset: number;
}

/** ``GET /vulnerabilities`` 查询参数（与后端 Query 参数一一对应）。 */
export interface VulnListParams {
  /** 严重度多选（后端取并集）。 */
  severity?: Severity[];
  /** 数据源多选（后端取并集）。 */
  source?: string[];
  /** 起始时间（ISO8601，含）；与 ``days`` 同时存在时以 ``since`` 为准。 */
  since?: string;
  /** 结束时间（ISO8601，含）。 */
  until?: string;
  /** 最近 N 天（兼容旧参数）。 */
  days?: number;
  /** KEV 三态：true=仅 KEV / false=仅非 KEV / undefined=不过滤。 */
  kev?: boolean;
  /** PoC 三态：true=仅有 PoC / false=仅无 PoC / undefined=不过滤。 */
  has_poc?: boolean;
  /** 关键词（CVE 编号 / 标题 / 描述）。 */
  q?: string;
  /** 单页条数（20/50/100）。 */
  limit?: number;
  /** 分页偏移。 */
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

/** 受影响资产（富化维度①）。 */
export interface AffectedAssetDto {
  asset_type: "library" | "framework" | "os" | "device" | "service" | "cloud" | "other";
  name: string;
  vendor: string | null;
  version_range: string | null;
  ecosystem: string | null;
  confidence: number;
  evidence_refs: string[];
}

/** PoC / EXP 记录（富化维度③）。 */
export interface ExploitDto {
  source: string;
  url: string;
  exploit_type: "poc" | "weaponized" | "analysis" | "unknown";
  maturity: "none" | "poc" | "functional" | "high";
  reliability: number;
  verified: boolean;
  evidence_refs: string[];
}

/** 论文关联（富化维度②；论文元数据由后端 enrichment 落库）。 */
export interface PaperLinkDto {
  paper_id: string;
  vuln_id: string;
  relation: "mentions" | "proposes-attack" | "proposes-defense" | "evaluates" | "surveys";
  confidence: number;
  evidence: string | null;
  evidence_refs: string[];
}

/** 攻击链单步（富化维度⑤）。 */
export interface AttackChainStepDto {
  order: number;
  technique_id: string;
  tactic: string;
  stage: string;
  description: string;
  preconditions: string[];
}

/** 攻击链整体（富化维度⑤）。 */
export interface AttackChainDto {
  steps: AttackChainStepDto[];
  entry_vector: string | null;
  privileges_required: "none" | "low" | "high" | "unknown";
}

/** Agent 执行轨迹（可观测性）。 */
export interface AgentStepDto {
  agent: string;
  round: number;
  confidence: number;
  latency_ms: number;
  model_used: string;
  output_digest: string;
  error: string | null;
}

/** 富化层实体（``GET /vulnerabilities/{cve_id}`` 的 ``enriched`` 字段）。

 * 继承事实层全部字段（后端 ``EnrichedVuln extends UnifiedVuln``），
 * 未富化时整个 ``enriched`` 为 ``null``。
 */
export interface EnrichedVulnDto extends UnifiedVulnDto {
  affected_assets: AffectedAssetDto[];
  related_papers: PaperLinkDto[];
  exploits: ExploitDto[];
  risk_score: number;
  risk_level: RiskLevel;
  risk_breakdown: Record<string, number>;
  attack_chain: AttackChainDto | null;
  confidence: number;
  review_status: "auto_pass" | "revised" | "needs_human";
  review_notes: string[];
  agent_trace: AgentStepDto[];
  model_used: string;
  enriched_at: string;
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

/** 图谱节点类型（后端 ``GET /graph/{cve_id}``；前端按类型着色）。 */
export type GraphNodeType =
  | "vulnerability"
  | "component"
  | "asset"
  | "technique"
  | "paper"
  | "patch"
  | "unknown";

/** 图谱节点（React Flow 可消费）。 */
export interface GraphNodeDto {
  id: string;
  type: string;
  label: string;
  properties: Record<string, unknown>;
}

/** 图谱边（React Flow 可消费）。 */
export interface GraphEdgeDto {
  id: string;
  source: string;
  target: string;
  relation: string;
}

/** ``GET /graph/{cve_id}`` 响应体。 */
export interface GraphResponse {
  cve_id: string;
  backend: "neo4j" | "postgres";
  nodes: GraphNodeDto[];
  edges: GraphEdgeDto[];
  node_count: number;
  edge_count: number;
  truncated: boolean;
}

/** ``GET /graph``（无 CVE 参数）响应体：多 CVE 合并后的全图概览。 */
export interface GraphOverviewResponse {
  backend: "neo4j" | "postgres";
  cve_ids: string[];
  nodes: GraphNodeDto[];
  edges: GraphEdgeDto[];
  node_count: number;
  edge_count: number;
  truncated: boolean;
  generated_at: string;
}

/** 单源数据质量指标（``GET /data-quality`` 的 ``sources`` 元素）。 */
export interface SourceQualityDto {
  source: string;
  kind: "vuln" | "paper";
  raw_count: number;
  normalized_ok: number;
  normalized_failed: number;
  success_rate: number;
  field_completeness: Record<string, number>;
}

/** 两份 Markdown 报告原文（前端用 react-markdown 渲染）。 */
export interface DataQualityReportsDto {
  data_quality: string;
  graph_stats: string | null;
}

/** ``GET /data-quality`` 响应体（质量页唯一数据源）。 */
export interface DataQualityResponse {
  enabled_source_count: number;
  declared_sources: string[];
  missing_sources: string[];
  total_raw: number;
  normalized_ok: number;
  normalized_failed: number;
  normalization_success_rate: number;
  field_completeness: Record<string, number>;
  coverage_rate: number;
  sources: SourceQualityDto[];
  trend: TimelinePoint[];
  trend_normalized: TimelinePoint[];
  trend_days: number;
  sample_limit: number;
  truncated: boolean;
  reports: DataQualityReportsDto | null;
  generated_at: string;
}

/** 质量页查询参数（与后端 Query 一一对应）。 */
export interface DataQualityParams {
  /** 每源重放条数上限（0 = 使用后端上限 10000）。 */
  sample_limit?: number;
  /** 趋势窗口天数。 */
  trend_days?: number;
  /** 是否附带 Markdown 报告原文。 */
  include_reports?: boolean;
  /** true 时绕过后端 5 分钟缓存。 */
  refresh?: boolean;
}
