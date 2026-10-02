/**
 * 问答页展示型组件（Day16 任务 3.2）：引用卡片 / 推理链 / 思考动画 / 快捷问题。
 */

import { Database, ExternalLink, FileText, GitBranch, Search, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { Citation, CitationSource, ReasoningStep } from "@/lib/types";

/** 引用来源 → 图标与配色。 */
const SOURCE_META: Record<CitationSource, { label: string; icon: typeof Database; color: string }> = {
  pg: { label: "PostgreSQL", icon: Database, color: "#1f77b4" },
  neo4j: { label: "Neo4j 图谱", icon: GitBranch, color: "#2ca02c" },
  chroma: { label: "向量检索", icon: Search, color: "#ff7f0e" },
  raw: { label: "原文快照", icon: FileText, color: "#9467bd" },
};

/**
 * 单条引用卡片（来源图标 + 标题 + 可点击 URL + 置信度）。
 *
 * @param props 引用对象。
 * @returns 引用卡片。
 */
export function CitationCard({ citation }: { citation: Citation }): JSX.Element {
  const meta = SOURCE_META[citation.source_type] ?? SOURCE_META.pg;
  const Icon = meta.icon;
  const title = citation.cve_id ?? citation.locator;

  return (
    <Card className="shadow-none">
      <CardContent className="space-y-1.5 p-3">
        <div className="flex items-center gap-2">
          <span
            className="flex size-6 items-center justify-center rounded-md"
            style={{ backgroundColor: `${meta.color}1a`, color: meta.color }}
          >
            <Icon className="size-3.5" aria-hidden />
          </span>
          <span className="text-xs font-medium" style={{ color: meta.color }}>
            {meta.label}
          </span>
          <Badge variant="outline" className="ml-auto font-mono text-[10px]">
            {citation.source_type}
          </Badge>
        </div>
        <p className="break-all font-mono text-[11px] text-muted-foreground">{title}</p>
        {citation.quote ? (
          <blockquote className="border-l-2 pl-2 text-[11px] italic text-muted-foreground">
            “{citation.quote.slice(0, 160)}”
          </blockquote>
        ) : null}
        {citation.url ? (
          <a
            href={citation.url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 break-all text-[11px] text-primary hover:underline"
          >
            {citation.url.slice(0, 80)}
            <ExternalLink className="size-3 shrink-0" aria-hidden />
          </a>
        ) : null}
        {citation.trace_id ? (
          <p className="font-mono text-[10px] text-muted-foreground">trace: {citation.trace_id}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

/**
 * 多跳推理链时间线（步骤号 + 结论 + 证据链接）。
 *
 * @param props 推理链步骤。
 * @returns 时间线元素。
 */
export function ReasoningTimeline({ steps }: { steps: ReasoningStep[] }): JSX.Element {
  return (
    <ol className="relative space-y-3 border-l border-border pl-5">
      {steps.map((step) => (
        <li key={`${step.hop}-${step.question}`} className="relative">
          <span className="absolute -left-[27px] flex size-5 items-center justify-center rounded-full bg-primary text-[10px] font-semibold text-primary-foreground">
            {step.hop}
          </span>
          <p className="text-xs font-medium">{step.question}</p>
          <p className="text-xs text-muted-foreground">{step.conclusion}</p>
          {step.evidence.length > 0 ? (
            <div className="mt-1 flex flex-wrap gap-1">
              {step.evidence.map((citation) => (
                <a
                  key={`${citation.source_type}-${citation.locator}`}
                  href={citation.url ?? "#"}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground hover:text-foreground"
                >
                  {citation.source_type}:{citation.cve_id ?? citation.locator.slice(0, 24)}
                </a>
              ))}
            </div>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

/**
 * 「AI 思考中」动画（三点跳动 + 文案）。
 *
 * @returns 动画元素。
 */
export function ThinkingDots(): JSX.Element {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground" aria-live="polite">
      <Sparkles className="size-4 animate-pulse text-primary" aria-hidden />
      <span>AI 思考中</span>
      <span className="flex gap-1">
        {[0, 1, 2].map((index) => (
          <span
            key={index}
            className="size-1.5 animate-bounce rounded-full bg-primary"
            style={{ animationDelay: `${index * 120}ms` }}
          />
        ))}
      </span>
    </div>
  );
}

/** 快捷问题（任务 3.3 指定的 4 条）。 */
export const QUICK_PROMPTS: readonly string[] = [
  "最近 30 天高危漏洞",
  "CVE-2024-3400 影响哪些资产",
  "有哪些 KEV 漏洞有 PoC",
  "Ollama 的 RCE 漏洞怎么修",
];

/**
 * 快捷问题按钮组。
 *
 * @param props 点击回调与禁用态。
 * @returns 按钮组。
 */
export function QuickPrompts({
  onPick,
  disabled,
}: {
  onPick: (question: string) => void;
  disabled?: boolean;
}): JSX.Element {
  return (
    <div className="flex flex-wrap gap-2">
      {QUICK_PROMPTS.map((prompt) => (
        <Button
          key={prompt}
          variant="outline"
          size="sm"
          disabled={disabled}
          onClick={() => onPick(prompt)}
          className="h-8 text-xs"
        >
          {prompt}
        </Button>
      ))}
    </div>
  );
}
