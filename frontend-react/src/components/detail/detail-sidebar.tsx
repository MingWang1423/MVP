/**
 * 详情页右侧边栏（Day16 任务 2.3）：风险评分环形进度 / 置信度 / 时间线 / 数据来源。
 *
 * 数据全部来自 ``GET /vulnerabilities/{cve_id}`` 的事实层与富化层，无额外请求。
 */

import { AlertTriangle, CheckCircle2, Clock, FileText, GitBranch, Link2 } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { LEVEL_META, formatDateTime, toLevelKey } from "@/lib/format";
import type { EnrichedVulnDto, UnifiedVulnDto } from "@/lib/types";

/** 组件属性。 */
export interface DetailSidebarProps {
  /** 事实层实体。 */
  unified: UnifiedVulnDto;
  /** 富化层实体（未富化时为 ``null``）。 */
  enriched: EnrichedVulnDto | null;
}

/** 环形进度条属性。 */
interface RingProps {
  /** 0-100 的数值。 */
  value: number;
  /** 颜色。 */
  color: string;
  /** 中心文案。 */
  caption: string;
}

/**
 * 环形进度（SVG，无第三方依赖）。
 *
 * @param props 见 :interface:`RingProps`。
 * @returns 环形图元素。
 */
function RiskRing({ value, color, caption }: RingProps): JSX.Element {
  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const ratio = Math.max(0, Math.min(100, value)) / 100;

  return (
    <div className="relative mx-auto size-[120px]">
      <svg viewBox="0 0 120 120" className="size-full -rotate-90">
        <circle cx="60" cy="60" r={radius} fill="none" strokeWidth="10" className="stroke-muted" />
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          stroke={color}
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - ratio)}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-semibold tabular-nums" style={{ color }}>
          {value.toFixed(0)}
        </span>
        <span className="text-[11px] text-muted-foreground">{caption}</span>
      </div>
    </div>
  );
}

/** 时间线条目。 */
interface TimelineEntry {
  /** 图标。 */
  icon: ReactNode;
  /** 标题。 */
  title: string;
  /** 时间（缺失时展示状态文案）。 */
  time: string;
  /** 是否为「无时间戳」的推断项。 */
  inferred: boolean;
}

/**
 * 组装时间线（纯函数）。
 *
 * 时间戳口径（Day26）：``published_at`` 只表示**源侧**披露时间；源未提供时**不用**入库时间
 * （``normalized_at``）冒充，而是追加一条说明性推断项，``normalized_at`` 单列「入库（归一化）」。
 *
 * @param unified 事实层实体。
 * @param enriched 富化层实体。
 * @returns 时间线条目（有时间戳的按时间倒序，其后是推断项）。
 */
export function buildTimeline(
  unified: UnifiedVulnDto,
  enriched: EnrichedVulnDto | null,
): TimelineEntry[] {
  const dated: { iso: string; entry: TimelineEntry }[] = [];
  const inferred: TimelineEntry[] = [];

  if (unified.published_at) {
    dated.push({
      iso: unified.published_at,
      entry: {
        icon: <FileText className="size-3.5" aria-hidden />,
        title: "漏洞披露",
        time: formatDateTime(unified.published_at),
        inferred: false,
      },
    });
  }
  if (unified.modified_at) {
    dated.push({
      iso: unified.modified_at,
      entry: {
        icon: <Clock className="size-3.5" aria-hidden />,
        title: "最近修改",
        time: formatDateTime(unified.modified_at),
        inferred: false,
      },
    });
  }
  if (enriched) {
    dated.push({
      iso: enriched.enriched_at,
      entry: {
        icon: <GitBranch className="size-3.5" aria-hidden />,
        title: "富化完成",
        time: formatDateTime(enriched.enriched_at),
        inferred: false,
      },
    });
  }
  dated.push({
    iso: unified.normalized_at,
    entry: {
      icon: <Clock className="size-3.5" aria-hidden />,
      title: "入库（归一化）",
      time: formatDateTime(unified.normalized_at),
      inferred: false,
    },
  });
  if (!unified.published_at) {
    inferred.push({
      icon: <FileText className="size-3.5" aria-hidden />,
      title: "漏洞披露",
      time: "源未提供发布时间（不以入库时间替代）",
      inferred: true,
    });
  }
  if (unified.kev) {
    inferred.push({
      icon: <AlertTriangle className="size-3.5 text-critical" aria-hidden />,
      title: "进入 CISA KEV",
      time: "已收录（KEV 未提供具体日期）",
      inferred: true,
    });
  }
  if (enriched && enriched.exploits.length > 0) {
    inferred.push({
      icon: <CheckCircle2 className="size-3.5 text-high" aria-hidden />,
      title: `检出 PoC / EXP（${enriched.exploits.length} 条）`,
      time: "检出时间未提供，随富化产出",
      inferred: true,
    });
  }
  const patchCount = unified.references.filter((item) =>
    item.tags.some((tag) =>
      ["patch", "advisory", "vendor-advisory", "fix"].includes(tag.toLowerCase()),
    ),
  ).length;
  if (patchCount > 0) {
    inferred.push({
      icon: <Link2 className="size-3.5 text-low" aria-hidden />,
      title: `补丁 / 公告链接（${patchCount} 条）`,
      time: "发布时间未提供",
      inferred: true,
    });
  }

  dated.sort((left, right) => right.iso.localeCompare(left.iso));
  return [...dated.map((item) => item.entry), ...inferred];
}

/**
 * 详情页侧边栏。
 *
 * @param props 见 :interface:`DetailSidebarProps`。
 * @returns 侧边栏元素。
 */
export function DetailSidebar({ unified, enriched }: DetailSidebarProps): JSX.Element {
  const riskScore = enriched?.risk_score ?? null;
  const riskMeta = enriched ? LEVEL_META[toLevelKey(enriched.risk_level)] : null;
  const timeline = buildTimeline(unified, enriched);

  return (
    <aside className="space-y-4" aria-label="漏洞概览">
      <Card className="shadow-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">风险评分</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {riskScore === null || !riskMeta ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              尚未富化，暂无风险评分
            </p>
          ) : (
            <>
              <RiskRing value={riskScore} color={riskMeta.color} caption={`${riskMeta.label}风险`} />
              <div className="space-y-1">
                {Object.entries(enriched?.risk_breakdown ?? {}).map(([factor, contribution]) => (
                  <div key={factor} className="flex items-center justify-between text-xs">
                    <span className="uppercase text-muted-foreground">{factor}</span>
                    <span className="tabular-nums">+{Number(contribution).toFixed(1)}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card className="shadow-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">置信度</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {enriched ? (
            <>
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">富化结论可信度</span>
                <span className="font-medium tabular-nums">
                  {(enriched.confidence * 100).toFixed(0)}%
                </span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary"
                  style={{ width: `${Math.round(enriched.confidence * 100)}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                复核状态：{enriched.review_status} · 模型：{enriched.model_used}
              </p>
            </>
          ) : (
            <p className="text-sm text-muted-foreground">尚未富化</p>
          )}
        </CardContent>
      </Card>

      <Card className="shadow-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">时间线</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="relative space-y-3 border-l border-border pl-4">
            {timeline.map((entry) => (
              <li key={entry.title} className="relative">
                <span className="absolute -left-[22px] flex size-4 items-center justify-center rounded-full bg-card text-muted-foreground">
                  {entry.icon}
                </span>
                <p className="text-sm font-medium">{entry.title}</p>
                <p className="text-xs text-muted-foreground">{entry.time}</p>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>

      <Card className="shadow-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">数据来源</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex flex-wrap gap-1">
            {unified.sources.length === 0 ? (
              <span className="text-muted-foreground">—</span>
            ) : (
              unified.sources.map((source) => (
                <span
                  key={source}
                  className="rounded bg-muted px-1.5 py-0.5 text-[11px] uppercase text-muted-foreground"
                >
                  {source}
                </span>
              ))
            )}
          </div>
          <Separator />
          <dl className="space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <dt>KEV（已知被利用）</dt>
              <dd className={unified.kev ? "font-medium text-critical" : ""}>
                {unified.kev ? "是" : "否"}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt>EPSS 概率</dt>
              <dd className="tabular-nums">
                {unified.epss_score === null ? "—" : `${(unified.epss_score * 100).toFixed(2)}%`}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt>原始证据（trace_id）</dt>
              <dd className="tabular-nums">{unified.trace_ids.length}</dd>
            </div>
            <div className="flex justify-between">
              <dt>归一化时间</dt>
              <dd>{formatDateTime(unified.normalized_at)}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
    </aside>
  );
}
