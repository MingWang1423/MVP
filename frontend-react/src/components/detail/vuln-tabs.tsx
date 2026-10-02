/**
 * 漏洞详情页 7 个 Tab 的内容组件（Day16 任务 2.2）。
 *
 * Tab 与数据来源对照：
 *
 * ==========  ==================================================
 * ① 基础信息   ``unified``：描述 / CVSS（含可视化）/ CWE / CPE / 引用
 * ② 受影响资产 ``enriched.affected_assets``（维度①）
 * ③ PoC / EXP  ``enriched.exploits``（维度③）
 * ④ 论文关联   ``enriched.related_papers``（维度②）
 * ⑤ 攻击链     ``enriched.attack_chain``（维度⑤）
 * ⑥ 修复建议   ``unified``（受影响版本 + patch 引用）—— 见组件内说明
 * ⑦ 图谱子图   ``GET /api/v1/graph/{cve_id}``
 * ==========  ==================================================
 */

import { ExternalLink, FileText, Inbox } from "lucide-react";
import type { ReactNode } from "react";

import { GraphView } from "@/components/detail/graph-view";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { parseVectorMetrics, scoreToLevel } from "@/lib/cvss";
import { LEVEL_META } from "@/lib/format";
import { useGraph } from "@/lib/queries";
import type { EnrichedVulnDto, UnifiedVulnDto } from "@/lib/types";

/** 空态提示。 */
function EmptyHint({ text }: { text: string }): JSX.Element {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-muted-foreground">
      <Inbox className="size-6" aria-hidden />
      <p className="text-sm">{text}</p>
    </div>
  );
}

/** 小节容器。 */
function Section({
  title,
  children,
  extra,
}: {
  title: string;
  children: ReactNode;
  extra?: ReactNode;
}): JSX.Element {
  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
          {title}
        </h3>
        {extra}
      </div>
      {children}
    </section>
  );
}

/** 置信度条（资产 / 论文 / PoC 卡片共用）。 */
function ConfidenceBar({ value, color }: { value: number; color: string }): JSX.Element {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
      <div
        className="h-full rounded-full"
        style={{ width: `${Math.round(Math.min(1, Math.max(0, value)) * 100)}%`, backgroundColor: color }}
      />
    </div>
  );
}

/**
 * ② 受影响资产 Tab。
 *
 * @param props 富化层实体。
 * @returns Tab 内容。
 */
export function AssetsTab({ enriched }: { enriched: EnrichedVulnDto | null }): JSX.Element {
  if (!enriched || enriched.affected_assets.length === 0) {
    return <EmptyHint text="暂无受影响资产（需先完成富化）" />;
  }
  return (
    <div className="overflow-hidden rounded-xl border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>资产名</TableHead>
            <TableHead className="w-[120px]">类型</TableHead>
            <TableHead className="w-[160px]">厂商</TableHead>
            <TableHead className="w-[160px]">受影响版本</TableHead>
            <TableHead className="w-[180px]">置信度</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {enriched.affected_assets.map((asset) => (
            <TableRow key={`${asset.asset_type}-${asset.name}`}>
              <TableCell className="font-medium">{asset.name}</TableCell>
              <TableCell>
                <Badge variant="secondary" className="text-[10px] uppercase">
                  {asset.asset_type}
                </Badge>
              </TableCell>
              <TableCell className="text-sm text-muted-foreground">
                {asset.vendor ?? "—"}
                {asset.ecosystem ? ` · ${asset.ecosystem}` : ""}
              </TableCell>
              <TableCell className="font-mono text-xs">{asset.version_range ?? "—"}</TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <ConfidenceBar
                    value={asset.confidence}
                    color={LEVEL_META[asset.confidence >= 0.8 ? "high" : "medium"].color}
                  />
                  <span className="shrink-0 text-xs tabular-nums">
                    {(asset.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

/**
 * ③ PoC / EXP Tab。
 *
 * Note:
 *     ``exploit_count`` 契约（``ExploitRecord``）不含 star 数——GitHub 星标写入
 *     ``evidence_refs``（``stars=N``），此处直接展示该字段原文。
 *
 * @param props 富化层实体。
 * @returns Tab 内容。
 */
export function ExploitsTab({ enriched }: { enriched: EnrichedVulnDto | null }): JSX.Element {
  if (!enriched || enriched.exploits.length === 0) {
    return <EmptyHint text="暂未发现公开 PoC / EXP" />;
  }
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {enriched.exploits.map((exploit) => (
        <Card key={exploit.url} className="shadow-card">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="uppercase">
                {exploit.source}
              </Badge>
              <Badge variant="secondary" className="text-[10px]">
                {exploit.exploit_type}
              </Badge>
              {exploit.verified ? (
                <Badge className="bg-low text-low-foreground text-[10px]">已验证</Badge>
              ) : null}
            </div>
            <CardTitle className="pt-2 text-sm font-medium">
              <a
                href={exploit.url}
                target="_blank"
                rel="noreferrer"
                className="flex items-start gap-1 break-all text-primary hover:underline"
              >
                {exploit.url}
                <ExternalLink className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              </a>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs text-muted-foreground">
            <div className="flex items-center gap-2">
              <span className="w-16 shrink-0">成熟度</span>
              <span className="font-medium text-foreground">{exploit.maturity}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 shrink-0">可靠性</span>
              <ConfidenceBar value={exploit.reliability} color={LEVEL_META.high.color} />
              <span className="shrink-0 tabular-nums">
                {(exploit.reliability * 100).toFixed(0)}%
              </span>
            </div>
            {exploit.evidence_refs.length > 0 ? (
              <p className="break-all">证据：{exploit.evidence_refs.join(" · ")}</p>
            ) : null}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

/**
 * ④ 论文关联 Tab。
 *
 * Note:
 *     富化契约 ``PaperVulnLink`` 只含 ``paper_id`` / 关系 / 置信度 / 证据；
 *     论文标题与作者在 ``paper`` 表中（本轮 API 未暴露），故此处展示 arXiv 链接，
 *     点击可查看标题与作者（P9 可加 ``GET /api/v1/papers`` 补齐）。
 *
 * @param props 富化层实体。
 * @returns Tab 内容。
 */
export function PapersTab({ enriched }: { enriched: EnrichedVulnDto | null }): JSX.Element {
  if (!enriched || enriched.related_papers.length === 0) {
    return <EmptyHint text="暂无关联论文" />;
  }
  const relationLabels: Record<string, string> = {
    mentions: "提及",
    "proposes-attack": "提出攻击",
    "proposes-defense": "提出防御",
    evaluates: "评测",
    surveys: "综述",
  };
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {enriched.related_papers.map((paper) => {
        const arxivUrl = `https://arxiv.org/abs/${paper.paper_id}`;
        return (
          <Card key={paper.paper_id} className="shadow-card">
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="font-mono text-[10px]">
                  arXiv:{paper.paper_id}
                </Badge>
                <Badge variant="secondary" className="text-[10px]">
                  {relationLabels[paper.relation] ?? paper.relation}
                </Badge>
              </div>
              <CardTitle className="pt-2 text-sm font-medium">
                <a
                  href={arxivUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-primary hover:underline"
                >
                  在 arXiv 查看标题与作者
                  <ExternalLink className="size-3.5" aria-hidden />
                </a>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <span className="w-16 shrink-0">相关度</span>
                <ConfidenceBar value={paper.confidence} color={LEVEL_META.low.color} />
                <span className="shrink-0 tabular-nums">
                  {(paper.confidence * 100).toFixed(0)}%
                </span>
              </div>
              {paper.evidence ? (
                <blockquote className="border-l-2 pl-2 italic">
                  “{paper.evidence.slice(0, 200)}”
                </blockquote>
              ) : null}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

/**
 * ⑤ 攻击链 Tab（ATT&CK 时间线）。
 *
 * @param props 富化层实体。
 * @returns Tab 内容。
 */
export function AttackChainTab({ enriched }: { enriched: EnrichedVulnDto | null }): JSX.Element {
  const chain = enriched?.attack_chain ?? null;
  if (!chain || chain.steps.length === 0) {
    return <EmptyHint text="未识别出攻击链（该漏洞可能不适用 ATT&CK 映射）" />;
  }
  const sorted = [...chain.steps].sort((left, right) => left.order - right.order);
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
        <span>
          入口向量：<span className="font-medium text-foreground">{chain.entry_vector ?? "—"}</span>
        </span>
        <span>
          所需权限：
          <span className="font-medium text-foreground">{chain.privileges_required}</span>
        </span>
      </div>
      <ol className="relative space-y-4 border-l border-border pl-6">
        {sorted.map((step) => (
          <li key={`${step.order}-${step.technique_id}`} className="relative">
            <span className="absolute -left-[34px] flex size-6 items-center justify-center rounded-full bg-primary text-[11px] font-semibold text-primary-foreground">
              {step.order}
            </span>
            <div className="rounded-xl border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <a
                  href={`https://attack.mitre.org/techniques/${step.technique_id.replace(".", "/")}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-xs font-medium text-primary hover:underline"
                >
                  {step.technique_id}
                </a>
                <Badge variant="secondary" className="text-[10px]">
                  {step.tactic}
                </Badge>
                <Badge variant="outline" className="text-[10px]">
                  {step.stage}
                </Badge>
              </div>
              <p className="mt-2 text-sm">{step.description}</p>
              {step.preconditions.length > 0 ? (
                <p className="mt-1 text-xs text-muted-foreground">
                  前置条件：{step.preconditions.join(" · ")}
                </p>
              ) : null}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

/**
 * ⑥ 修复建议 Tab。
 *
 * Note（如实说明数据来源）:
 *     富化维度⑦ ``Remediation``（LLM 摘要 + 缓解措施）目前只存在于
 *     ``EnrichmentOutput`` 内存对象，**未落库**（``enriched_vuln`` 无对应列），
 *     因此本 Tab 展示事实层可确认的修复线索：受影响版本区间、patch / 公告引用、
 *     富化复核说明；页面下方给出该缺口提示，供后续按 §10.3 变更流程补齐。
 *
 * @param props 事实层与富化层实体。
 * @returns Tab 内容。
 */
export function RemediationTab({
  unified,
  enriched,
}: {
  unified: UnifiedVulnDto;
  enriched: EnrichedVulnDto | null;
}): JSX.Element {
  const patchTags = new Set(["patch", "advisory", "vendor-advisory", "fix", "mitigation"]);
  const patchLinks = unified.references.filter((reference) =>
    reference.tags.some((tag) => patchTags.has(tag.toLowerCase())),
  );

  return (
    <div className="space-y-6">
      <Section title={`受影响版本区间（${unified.affected_versions.length}）`}>
        {unified.affected_versions.length === 0 ? (
          <EmptyHint text="未解析出受影响版本区间，无法给出升级目标版本" />
        ) : (
          <ul className="space-y-1 font-mono text-xs">
            {unified.affected_versions.map((item) => (
              <li key={item} className="rounded bg-muted/40 px-2 py-1">
                {item}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section
        title={`补丁 / 缓解链接（${patchLinks.length}）`}
        extra={<span className="text-xs text-muted-foreground">按引用标签过滤</span>}
      >
        {patchLinks.length === 0 ? (
          <EmptyHint text="未发现带 patch / advisory 标签的引用" />
        ) : (
          <ul className="space-y-1.5">
            {patchLinks.map((reference) => (
              <li key={reference.url} className="flex items-start gap-2 text-sm">
                <ExternalLink className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <a
                  href={reference.url}
                  target="_blank"
                  rel="noreferrer"
                  className="break-all text-primary hover:underline"
                >
                  {reference.url}
                </a>
                {reference.tags.map((tag) => (
                  <Badge key={tag} variant="secondary" className="shrink-0 text-[10px]">
                    {tag}
                  </Badge>
                ))}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="富化复核说明">
        {enriched && enriched.review_notes.length > 0 ? (
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {enriched.review_notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            {enriched ? "Reviewer 未提出修订意见（自动通过）" : "尚未富化"}
          </p>
        )}
      </Section>

      <p className="rounded-lg border border-dashed p-3 text-xs text-muted-foreground">
        说明：LLM 生成的「缓解措施 / 修复摘要」（富化维度⑦）当前未持久化到
        ``enriched_vuln``，故本页仅展示事实层可确认的修复线索。补齐需按 §10.3 变更流程
        增列并重跑富化。
      </p>
    </div>
  );
}

/**
 * ⑦ 图谱子图 Tab（React Flow 1 跳子图）。
 *
 * @param props 漏洞主键。
 * @returns Tab 内容。
 */
export function GraphTab({ cveId }: { cveId: string }): JSX.Element {
  const { data, isLoading, isError, error } = useGraph(cveId);

  if (isLoading) {
    return (
      <div className="space-y-2" aria-busy>
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-[520px] w-full rounded-xl" />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <EmptyHint
        text={error instanceof Error ? error.message : "图谱加载失败（Neo4j 与降级路径均不可用）"}
      />
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge variant="outline">{data.node_count} 节点</Badge>
        <Badge variant="outline">{data.edge_count} 边</Badge>
        <Badge variant={data.backend === "neo4j" ? "default" : "secondary"}>
          数据来源：{data.backend === "neo4j" ? "Neo4j" : "PostgreSQL 降级推导"}
        </Badge>
        {data.truncated ? <Badge variant="destructive">已截断（超出 limit）</Badge> : null}
        <span>拖拽节点可调整布局 · 滚轮缩放</span>
      </div>
      <GraphView graph={data} />
      <div className="flex flex-wrap gap-2 text-xs">
        {Object.entries({
          vulnerability: "漏洞",
          component: "组件",
          asset: "资产",
          technique: "攻击技术",
          paper: "论文",
          patch: "补丁",
        }).map(([type, label]) => (
          <span key={type} className="flex items-center gap-1 text-muted-foreground">
            <span
              className="size-2.5 rounded-full"
              style={{
                backgroundColor: {
                  vulnerability: "#d62728",
                  component: "#1f77b4",
                  asset: "#2ca02c",
                  technique: "#ff7f0e",
                  paper: "#17becf",
                  patch: "#9467bd",
                }[type],
              }}
              aria-hidden
            />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * ① 基础信息 Tab（描述 / CVSS 可视化 / CWE / CPE / 引用）。
 *
 * @param props 事实层实体。
 * @returns Tab 内容。
 */
export function BasicInfoTab({ unified }: { unified: UnifiedVulnDto }): JSX.Element {
  const patchTags = new Set(["patch", "advisory", "vendor-advisory", "fix"]);

  return (
    <div className="space-y-6">
      <Section title="描述">
        <p className="whitespace-pre-wrap rounded-xl border bg-muted/30 p-4 text-sm leading-relaxed">
          {unified.description || "（源未提供描述）"}
        </p>
      </Section>

      <Section title={`CVSS 向量（${unified.cvss.length}）`}>
        {unified.cvss.length === 0 ? (
          <EmptyHint text="源数据未提供 CVSS 向量" />
        ) : (
          <div className="space-y-3">
            {unified.cvss.map((vector) => {
              const level = scoreToLevel(vector.base_score);
              const meta = LEVEL_META[level === "none" ? "low" : level];
              return (
                <div key={`${vector.version}-${vector.vector}`} className="rounded-xl border p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">CVSS {vector.version}</Badge>
                    <span
                      className="text-lg font-semibold tabular-nums"
                      style={{ color: meta.color }}
                    >
                      {vector.base_score.toFixed(1)}
                    </span>
                    <SeverityBadge severity={vector.severity} />
                  </div>
                  <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${(vector.base_score / 10) * 100}%`,
                        backgroundColor: meta.color,
                      }}
                    />
                  </div>
                  <code className="mt-3 block break-all rounded bg-muted/60 px-2 py-1 font-mono text-[11px] text-muted-foreground">
                    {vector.vector}
                  </code>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {parseVectorMetrics(vector.vector).map((metric) => (
                      <span
                        key={metric.code}
                        className="rounded border bg-background px-2 py-1 text-[11px]"
                      >
                        <span className="font-medium">{metric.code}</span>
                        <span className="ml-1 text-muted-foreground">{metric.label}</span>
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Section>

      <Section title={`CWE（${unified.cwe_ids.length}）`}>
        {unified.cwe_ids.length === 0 ? (
          <EmptyHint text="未关联 CWE" />
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {unified.cwe_ids.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/\D/g, "")}.html`}
                target="_blank"
                rel="noreferrer"
                className="rounded border px-2 py-1 font-mono text-xs text-primary hover:underline"
              >
                {cwe}
              </a>
            ))}
          </div>
        )}
      </Section>

      <Section title={`CPE 匹配（${unified.cpe_matches.length}）`}>
        {unified.cpe_matches.length === 0 ? (
          <EmptyHint text="未提供 CPE 匹配" />
        ) : (
          <ul className="space-y-1 text-xs">
            {unified.cpe_matches.slice(0, 20).map((cpe, index) => (
              <li
                key={`${cpe.vendor}-${cpe.product}-${index}`}
                className="flex flex-wrap items-center gap-2 rounded bg-muted/40 px-2 py-1"
              >
                <span className="font-mono font-medium">{`${cpe.vendor}:${cpe.product}`}</span>
                <span className="font-mono text-muted-foreground">
                  {[
                    cpe.version_start_incl ? `>=${cpe.version_start_incl}` : "",
                    cpe.version_start_excl ? `>${cpe.version_start_excl}` : "",
                    cpe.version_end_incl ? `<=${cpe.version_end_incl}` : "",
                    cpe.version_end_excl ? `<${cpe.version_end_excl}` : "",
                  ]
                    .filter(Boolean)
                    .join(" , ") || "全部版本"}
                </span>
                {cpe.vulnerable ? <span className="text-critical">受影响</span> : null}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={`引用链接（${unified.references.length}）`}>
        {unified.references.length === 0 ? (
          <EmptyHint text="无外部引用" />
        ) : (
          <ul className="space-y-1.5">
            {unified.references.slice(0, 15).map((reference) => (
              <li key={reference.url} className="flex items-start gap-2 text-sm">
                <FileText className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <a
                  href={reference.url}
                  target="_blank"
                  rel="noreferrer"
                  className="break-all text-primary hover:underline"
                >
                  {reference.url}
                </a>
                {reference.tags.map((tag) => (
                  <Badge
                    key={tag}
                    variant={patchTags.has(tag.toLowerCase()) ? "default" : "secondary"}
                    className="shrink-0 text-[10px]"
                  >
                    {tag}
                  </Badge>
                ))}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}
