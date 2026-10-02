/**
 * 首页仪表盘（Day14 任务 7）。
 *
 * 布局参考 Snyk 控制台：
 * 1. 顶部 4 个 KPI 卡片（总数 / 高危 / 数据源 / 今日新增）——图标 + 数字滚动动画 + hover 阴影；
 * 2. 中部两栏：左「风险分布饼图」、右「来源分布柱图」；
 * 3. 下方通栏：近 30 天披露趋势折线图；
 * 4. 底部：最近 10 条高危漏洞表格（KEV 标记 + 风险分 + 来源）。
 *
 * 数据来源：``GET /api/v1/stats``（单次请求返回上述全部数据，避免首屏瀑布）。
 */

import { Bug, CalendarPlus, Database, RefreshCw, ShieldAlert } from "lucide-react";

import { ChartCard } from "@/components/chart-card";
import { RiskPieChart } from "@/components/charts/risk-pie-chart";
import { SourceBarChart } from "@/components/charts/source-bar-chart";
import { TrendLineChart } from "@/components/charts/trend-line-chart";
import { KpiCard } from "@/components/kpi-card";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatDateTime, formatPercent } from "@/lib/format";
import { useStats } from "@/lib/queries";
import type { VulnSummary } from "@/lib/types";

/** 需求：底部表格固定展示最近 10 条高危漏洞。 */
const HIGH_RISK_LIMIT = 10;

/** 需求：趋势窗口固定 30 天。 */
const TIMELINE_DAYS = 30;

/**
 * 骨架屏：与真实布局同构，避免数据到达后页面跳动。
 *
 * @returns 骨架屏元素。
 */
function DashboardSkeleton(): JSX.Element {
  return (
    <div className="space-y-6" aria-busy>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((index) => (
          <Card key={index} className="shadow-card">
            <CardContent className="flex items-center justify-between gap-4 p-5">
              <div className="space-y-2">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-8 w-24" />
                <Skeleton className="h-3 w-28" />
              </div>
              <Skeleton className="size-12 rounded-xl" />
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {[0, 1].map((index) => (
          <Card key={index} className="shadow-card">
            <CardHeader className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-3 w-40" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-[320px] w-full rounded-lg" />
            </CardContent>
          </Card>
        ))}
      </div>
      <Card className="shadow-card">
        <CardHeader className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-3 w-56" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[320px] w-full rounded-lg" />
        </CardContent>
      </Card>
      <Card className="shadow-card">
        <CardHeader className="space-y-2">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-3 w-64" />
        </CardHeader>
        <CardContent className="space-y-2">
          {[0, 1, 2, 3, 4, 5].map((index) => (
            <Skeleton key={index} className="h-10 w-full" />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

/** 高危漏洞表格属性。 */
interface HighRiskTableProps {
  /** 最近高危条目。 */
  rows: VulnSummary[];
}

/**
 * 最近高危漏洞表格。
 *
 * @param props 见 :interface:`HighRiskTableProps`。
 * @returns 表格卡片。
 */
function HighRiskTable({ rows }: HighRiskTableProps): JSX.Element {
  return (
    <Card className="shadow-card">
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">最近高危漏洞</h2>
          <p className="text-sm text-muted-foreground">
            事实层严重度为 CRITICAL / HIGH 的最新 10 条（按发布时间倒序）
          </p>
        </div>
        <ShieldAlert className="size-5 text-critical" aria-hidden />
      </CardHeader>
      <CardContent className="pt-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[150px]">漏洞编号</TableHead>
                <TableHead className="min-w-[280px]">标题</TableHead>
                <TableHead className="w-[90px]">严重度</TableHead>
                <TableHead className="w-[90px] text-right">风险分</TableHead>
                <TableHead className="w-[90px] text-right">EPSS</TableHead>
                <TableHead className="w-[170px]">来源</TableHead>
                <TableHead className="w-[150px]">发布时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                    暂无高危漏洞数据
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((row) => (
                  <TableRow key={row.vuln_id} className="hover:bg-muted/50">
                    <TableCell className="font-mono text-xs font-medium">
                      <a
                        href={`/vulnerabilities/${row.vuln_id}`}
                        className="text-primary hover:underline"
                      >
                        {row.vuln_id}
                      </a>
                    </TableCell>
                    <TableCell className="max-w-[420px] truncate" title={row.title ?? undefined}>
                      {row.title ?? "—"}
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={row.severity} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {row.risk_score === null ? "—" : row.risk_score.toFixed(1)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatPercent(row.epss_score)}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {row.kev ? (
                          <span className="rounded bg-critical/10 px-1.5 py-0.5 text-[11px] font-medium text-critical">
                            KEV
                          </span>
                        ) : null}
                        {row.sources.slice(0, 3).map((source) => (
                          <span
                            key={source}
                            className="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground"
                          >
                            {source}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatDateTime(row.published_at)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * 首页仪表盘页面组件。
 *
 * @returns 仪表盘元素（4 KPI + 3 图表 + 1 表格）。
 */
export function Dashboard(): JSX.Element {
  const { data, isLoading, isError, error, refetch, isFetching } = useStats({
    timeline_days: TIMELINE_DAYS,
    high_risk_limit: HIGH_RISK_LIMIT,
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <DashboardHeader />
        <DashboardSkeleton />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="space-y-6">
        <DashboardHeader />
        <Card className="border-destructive/40 shadow-card">
          <CardHeader className="space-y-1">
            <h2 className="text-base font-semibold text-destructive">统计数据加载失败</h2>
            <p className="text-sm text-muted-foreground">
              {error instanceof Error ? error.message : "未知错误"}
            </p>
          </CardHeader>
          <CardContent>
            <Button onClick={() => void refetch()} disabled={isFetching}>
              <RefreshCw className={isFetching ? "mr-2 size-4 animate-spin" : "mr-2 size-4"} />
              重新加载
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <DashboardHeader
        generatedAt={data.generated_at}
        onRefresh={() => void refetch()}
        refreshing={isFetching}
      />

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="核心指标">
        {/* 四张卡片错峰淡入（Framer Motion + 数字滚动动画）。
            截图脚本会等待动画播完再抓帧，不要为此去掉 delay。 */}
        <KpiCard
          title="漏洞总数"
          value={data.total_vulns}
          hint="多源去重合并后的统一漏洞实体"
          icon={Bug}
          accentColor="#1f77b4"
          delay={0}
        />
        <KpiCard
          title="高危漏洞"
          value={data.critical_count}
          hint="CVSS 严重度 = CRITICAL"
          icon={ShieldAlert}
          accentColor="#d62728"
          delay={0.06}
        />
        <KpiCard
          title="数据源"
          value={data.source_count}
          hint="已启用的采集源（NVD/KEV/EPSS/OSV/GHSA…）"
          icon={Database}
          accentColor="#2ca02c"
          delay={0.12}
        />
        <KpiCard
          title="今日新增"
          value={data.today_new}
          hint="近 24 小时入库 / 披露"
          icon={CalendarPlus}
          accentColor="#ff7f0e"
          delay={0.18}
        />
      </section>

      <section className="grid gap-4 lg:grid-cols-2" aria-label="分布统计">
        <ChartCard title="风险分布" description="按 CVSS 严重度统计（未定级单列）">
          <RiskPieChart distribution={data.risk_distribution} />
        </ChartCard>
        <ChartCard title="来源分布" description="各采集源贡献的漏洞条数">
          <SourceBarChart distribution={data.source_distribution} />
        </ChartCard>
      </section>

      <section aria-label="披露趋势">
        <ChartCard
          title="近 30 天披露趋势"
          description="按发布时间（缺省回退入库时间）逐日统计，缺失日期已补 0"
        >
          <TrendLineChart timeline={data.timeline} />
        </ChartCard>
      </section>

      <section aria-label="高危漏洞清单">
        <HighRiskTable rows={data.top_high_risk} />
      </section>
    </div>
  );
}

/** 页头属性。 */
interface DashboardHeaderProps {
  /** 统计生成时间（UTC ISO8601）。 */
  generatedAt?: string;
  /** 刷新回调。 */
  onRefresh?: () => void;
  /** 是否正在刷新。 */
  refreshing?: boolean;
}

/**
 * 页头（标题 + 口径说明 + 刷新按钮）。
 *
 * @param props 见 :interface:`DashboardHeaderProps`。
 * @returns 页头元素。
 */
function DashboardHeader({
  generatedAt,
  onRefresh,
  refreshing,
}: DashboardHeaderProps): JSX.Element {
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">情报看板</h1>
        <p className="text-sm text-muted-foreground">
          多源漏洞情报总览 · 数据更新时间：{formatDateTime(generatedAt)}
        </p>
      </div>
      {onRefresh ? (
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
          <RefreshCw
            className={refreshing ? "mr-2 size-4 animate-spin" : "mr-2 size-4"}
            aria-hidden
          />
          刷新
        </Button>
      ) : null}
    </header>
  );
}

export default Dashboard;

