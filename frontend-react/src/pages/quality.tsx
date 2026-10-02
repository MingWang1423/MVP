/**
 * 数据质量页（Day16 任务 2）。
 *
 * 结构：
 * 1. KPI 卡（数据源数 / 采集总条数 / 归一化成功率 / 字段平均完整率）；
 * 2. 图表（各源采集量柱图、归一化成功率环形图、字段完整率雷达图、采集与入库双线趋势）；
 * 3. 各源明细表（含零数据源的采集缺口提示）；
 * 4. 报告渲染：``reports/data_quality.md``（后端同生成器实时重算）+ ``reports/graph_stats.md``，
 *    用 react-markdown 渲染（§2.3 的第二种方案：结构化数据 + 报告原文一并返回）。
 *
 * 数据源：``GET /api/v1/data-quality``（单次请求，后端带 5 分钟缓存，``refresh=true`` 强制重算）。
 */

import { Database, FileText, Gauge, Layers, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { ChartCard } from "@/components/chart-card";
import { CompletenessRadarChart } from "@/components/charts/completeness-radar-chart";
import { DualTrendChart } from "@/components/charts/dual-trend-chart";
import { SourceBarChart } from "@/components/charts/source-bar-chart";
import { SuccessRingChart } from "@/components/charts/success-ring-chart";
import { KpiCard } from "@/components/kpi-card";
import { Markdown } from "@/components/markdown";
import { PageHeader } from "@/components/page-header";
import { EmptyState } from "@/components/state/empty-state";
import { ErrorState } from "@/components/state/error-state";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatCount, formatDateTime, formatPercent } from "@/lib/format";
import { useDataQuality } from "@/lib/queries";
import type { DataQualityResponse } from "@/lib/types";

/** 字段 → 中文名（表格与说明共用）。 */
const FIELD_LABELS: Record<string, string> = {
  description: "描述",
  cvss: "CVSS",
  cwe: "CWE",
  references: "参考链接",
};

/**
 * 页面骨架（与真实布局同构，避免数据到达后跳动）。
 *
 * @returns 骨架元素。
 */
function QualitySkeleton(): JSX.Element {
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
        {[0, 1, 2, 3].map((index) => (
          <Card key={index} className="shadow-card">
            <CardHeader className="space-y-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-3 w-44" />
            </CardHeader>
            <CardContent>
              <Skeleton className="h-[280px] w-full rounded-lg" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

/**
 * 数据质量页组件。
 *
 * @returns 质量页元素。
 */
export function QualityPage(): JSX.Element {
  const [refreshToken, setRefreshToken] = useState(0);
  const { data, isLoading, isFetching, isError, error, refetch } = useDataQuality(
    useMemo(() => (refreshToken > 0 ? { refresh: true } : {}), [refreshToken]),
  );

  const averageCompleteness = useMemo(() => {
    const values = Object.values(data?.field_completeness ?? {});
    return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
  }, [data]);

  const sourceVolumes = useMemo(
    () => Object.fromEntries((data?.sources ?? []).map((item) => [item.source, item.raw_count])),
    [data],
  );

  const vulnerabilities = useMemo(
    () => (data?.sources ?? []).filter((item) => item.kind === "vuln"),
    [data],
  );

  const papers = useMemo(
    () => (data?.sources ?? []).filter((item) => item.kind === "paper"),
    [data],
  );

  const handleRefresh = (): void => {
    setRefreshToken((token) => token + 1);
    void refetch();
  };

  if (isLoading && !data) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="数据质量"
          description="采集条数 / 归一化成功率 / 字段完整率 / 源覆盖率 · 口径与 reports/data_quality.md 一致"
        />
        <QualitySkeleton />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="space-y-6">
        <PageHeader title="数据质量" description="采集与归一化质量指标" />
        <ErrorState
          title="数据质量加载失败"
          error={error}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="数据质量"
        description={
          <span>
            采集条数 / 归一化成功率 / 字段完整率 / 源覆盖率 · 生成于{" "}
            {formatDateTime(data.generated_at)} · 每源重放上限 {formatCount(data.sample_limit)} 条
            {data.truncated ? "（已触达上限，数值为下界）" : ""}
          </span>
        }
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isFetching}>
            <RefreshCw
              className={isFetching ? "mr-2 size-4 animate-spin" : "mr-2 size-4"}
              aria-hidden
            />
            强制刷新（跳过缓存）
          </Button>
        }
      />

      {data.missing_sources.length > 0 ? (
        <Card className="border-high/40 bg-high/5 shadow-none">
          <CardContent className="flex items-start gap-3 p-4 text-sm">
            <TriangleAlert className="mt-0.5 size-4 shrink-0 text-high" aria-hidden />
            <p>
              <span className="font-medium">采集缺口：</span>
              {data.missing_sources.join("、")} 声明启用但当前无数据（检查调度 / 凭据 / 源可用性）。
            </p>
          </CardContent>
        </Card>
      ) : null}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4" aria-label="质量指标">
        <KpiCard
          title="数据源数"
          value={data.enabled_source_count}
          hint={`已启用 ${data.enabled_source_count} / 声明启用 ${data.declared_sources.length}`}
          icon={Database}
          accentColor="#1f77b4"
        />
        <KpiCard
          title="采集总条数"
          value={data.total_raw}
          hint="raw_item 表全量（各源之和）"
          icon={Layers}
          accentColor="#ff7f0e"
          delay={0.06}
        />
        <KpiCard
          title="归一化成功率"
          value={data.normalization_success_rate * 100}
          hint={`成功 ${formatCount(data.normalized_ok)} / 失败 ${formatCount(data.normalized_failed)}`}
          icon={ShieldCheck}
          accentColor="#2ca02c"
          format={(value) => `${value.toFixed(1)}%`}
          delay={0.12}
        />
        <KpiCard
          title="字段完整率"
          value={averageCompleteness * 100}
          hint="description / cvss / cwe / references 平均"
          icon={Gauge}
          accentColor="#9467bd"
          format={(value) => `${value.toFixed(1)}%`}
          delay={0.18}
        />
      </section>

      <section className="grid gap-4 lg:grid-cols-2" aria-label="质量图表">
        <ChartCard title="各源采集量" description="raw_item 按源统计（含论文源）">
          <SourceBarChart distribution={sourceVolumes} />
        </ChartCard>
        <ChartCard
          title="归一化成功率"
          description="L2 纯函数 build_unified_vuln 重放结果（分母 = 尝试条数）"
        >
          <SuccessRingChart
            rate={data.normalization_success_rate}
            ok={data.normalized_ok}
            failed={data.normalized_failed}
          />
        </ChartCard>
        <ChartCard title="字段完整率" description="分母 = 归一化成功条数；论文源天然缺 cvss / cwe">
          <CompletenessRadarChart completeness={data.field_completeness} />
        </ChartCard>
        <ChartCard
          title={`近 ${data.trend_days} 天采集趋势`}
          description="采集 = raw_item.fetched_at；入库 / 披露 = unified_vuln 时间轴（缺失日补 0）"
        >
          <DualTrendChart collected={data.trend} normalized={data.trend_normalized} />
        </ChartCard>
      </section>

      <Tabs defaultValue="sources" className="space-y-4">
        <TabsList>
          <TabsTrigger value="sources">各源明细</TabsTrigger>
          <TabsTrigger value="reports">质量报告</TabsTrigger>
        </TabsList>

        <TabsContent value="sources" className="space-y-4">
          <SourceTable title="漏洞源" rows={vulnerabilities} emptyHint="当前没有启用的漏洞源数据" />
          <SourceTable title="论文源" rows={papers} emptyHint="当前没有启用的论文源数据" />
        </TabsContent>

        <TabsContent value="reports" className="space-y-4">
          {data.reports ? (
            <>
              <ChartCard
                title="采集数据质量报告（reports/data_quality.md）"
                description="由后端与 P4 脚本共用同一生成器实时重算，口径逐字一致（仅生成时间不同）"
                action={
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      const content = data.reports?.data_quality ?? "";
                      const url = URL.createObjectURL(
                        new Blob([content], { type: "text/markdown;charset=utf-8" }),
                      );
                      const anchor = document.createElement("a");
                      anchor.href = url;
                      anchor.download = "data_quality.md";
                      anchor.click();
                      URL.revokeObjectURL(url);
                    }}
                  >
                    <FileText className="mr-1.5 size-3.5" aria-hidden />
                    下载 .md
                  </Button>
                }
              >
                <div className="max-h-[520px] overflow-y-auto rounded-lg border p-4">
                  <Markdown content={data.reports.data_quality} />
                </div>
              </ChartCard>

              <ChartCard
                title="图谱规模报告（reports/graph_stats.md）"
                description="由 scripts/load_graph.py --all 生成（Neo4j 抽取统计）"
              >
                {data.reports.graph_stats ? (
                  <div className="max-h-[420px] overflow-y-auto rounded-lg border p-4">
                    <Markdown content={data.reports.graph_stats} />
                  </div>
                ) : (
                  <EmptyState
                    title="尚未生成图谱规模报告"
                    description="执行 python -m scripts.load_graph --all 后重新刷新即可看到该报告。"
                  />
                )}
              </ChartCard>
            </>
          ) : (
            <EmptyState
              title="报告未随本次响应返回"
              description="本次请求使用了 include_reports=false；点击右上角「强制刷新」可重新获取报告原文。"
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** 各源明细表属性。 */
interface SourceTableProps {
  /** 表格标题。 */
  title: string;
  /** 数据行。 */
  rows: DataQualityResponse["sources"];
  /** 空态提示。 */
  emptyHint: string;
}

/**
 * 各源明细表（采集量 / 归一化成功率 / 四字段完整率）。
 *
 * @param props 见 :interface:`SourceTableProps`。
 * @returns 表格卡片元素。
 */
function SourceTable({ title, rows, emptyHint }: SourceTableProps): JSX.Element {
  return (
    <Card className="shadow-card">
      <CardHeader className="pb-2">
        <h2 className="text-base font-semibold">
          {title}
          <span className="ml-2 text-xs font-normal text-muted-foreground">{rows.length} 个源</span>
        </h2>
      </CardHeader>
      <CardContent className="pt-2">
        {rows.length === 0 ? (
          <EmptyState title={emptyHint} />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>源</TableHead>
                  <TableHead className="text-right">采集条数</TableHead>
                  <TableHead className="text-right">归一化成功</TableHead>
                  <TableHead className="text-right">失败</TableHead>
                  <TableHead className="text-right">成功率</TableHead>
                  {Object.keys(FIELD_LABELS).map((field) => (
                    <TableHead key={field} className="text-right">
                      {FIELD_LABELS[field]}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.source}>
                    <TableCell className="font-medium">{row.source}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCount(row.raw_count)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCount(row.normalized_ok)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {row.normalized_failed > 0 ? (
                        <span className="text-destructive">{row.normalized_failed}</span>
                      ) : (
                        0
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {row.raw_count === 0 ? "—" : formatPercent(row.success_rate)}
                    </TableCell>
                    {Object.keys(FIELD_LABELS).map((field) => (
                      <TableCell key={field} className="text-right tabular-nums">
                        {formatPercent(row.field_completeness[field] ?? 0)}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default QualityPage;
