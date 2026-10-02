/**
 * 漏洞详情页（Day16 任务 2）。
 *
 * 结构：
 * - 顶部 Header：CVE ID + 严重度 + 来源标签 / 导出 JSON · 复制 CVE ID · 在 NVD 查看；
 * - 左侧主区：7 个 Tab（基础信息 / 受影响资产 / PoC-EXP / 论文 / 攻击链 / 修复建议 / 图谱子图）；
 * - 右侧边栏：风险评分环形进度 / 置信度 / 时间线 / 数据来源；
 * - 加载态：整页 Skeleton；「图谱子图」Tab 因按需拉取单独有局部 Skeleton。
 */

import { Copy, Download, ExternalLink, RefreshCw } from "lucide-react";
import { useCallback, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";

import { DetailSidebar } from "@/components/detail/detail-sidebar";
import {
  AssetsTab,
  AttackChainTab,
  BasicInfoTab,
  ExploitsTab,
  GraphTab,
  PapersTab,
  RemediationTab,
} from "@/components/detail/vuln-tabs";
import { SeverityBadge } from "@/components/severity-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useVuln } from "@/lib/queries";
import type { VulnDetailResponse } from "@/lib/types";

/** Tab 定义（顺序即展示顺序）。 */
const TAB_ITEMS: { value: string; label: string }[] = [
  { value: "basic", label: "基础信息" },
  { value: "assets", label: "受影响资产" },
  { value: "exploits", label: "PoC / EXP" },
  { value: "papers", label: "论文关联" },
  { value: "attack", label: "攻击链" },
  { value: "remediation", label: "修复建议" },
  { value: "graph", label: "图谱子图" },
];

/**
 * 整页骨架屏（首次加载）。
 *
 * @returns 骨架屏元素。
 */
function DetailSkeleton(): JSX.Element {
  return (
    <div className="space-y-4" aria-busy>
      <Skeleton className="h-20 w-full rounded-xl" />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-3">
          <Skeleton className="h-10 w-full max-w-xl" />
          <Skeleton className="h-[420px] w-full rounded-xl" />
        </div>
        <div className="space-y-3">
          <Skeleton className="h-[180px] w-full rounded-xl" />
          <Skeleton className="h-[140px] w-full rounded-xl" />
          <Skeleton className="h-[180px] w-full rounded-xl" />
        </div>
      </div>
    </div>
  );
}

/**
 * 触发浏览器下载（导出 JSON 用）。
 *
 * @param payload 详情响应。
 * @param cveId 漏洞主键。
 */
function downloadJson(payload: VulnDetailResponse, cveId: string): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${cveId}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

/**
 * 漏洞详情页组件。
 *
 * @returns 详情页元素。
 */
export function VulnDetailPage(): JSX.Element {
  const { cveId } = useParams<{ cveId: string }>();
  const { data, isLoading, isError, error, refetch, isFetching } = useVuln(cveId);
  const [activeTab, setActiveTab] = useState("basic");

  const handleCopy = useCallback(async () => {
    if (!cveId) {
      return;
    }
    try {
      await navigator.clipboard.writeText(cveId.toUpperCase());
      toast.success("已复制 CVE 编号", { description: cveId.toUpperCase() });
    } catch {
      toast.error("复制失败：浏览器拒绝了剪贴板访问");
    }
  }, [cveId]);

  if (isLoading) {
    return <DetailSkeleton />;
  }

  if (isError || !data) {
    return (
      <Card className="border-destructive/40 shadow-card">
        <CardHeader className="space-y-1">
          <h1 className="text-lg font-semibold text-destructive">
            {cveId ?? "未指定漏洞"} 加载失败
          </h1>
          <p className="text-sm text-muted-foreground">
            {error instanceof Error ? error.message : "未知错误"}
          </p>
        </CardHeader>
        <CardContent className="flex gap-2">
          <Button onClick={() => void refetch()}>
            <RefreshCw className="mr-2 size-4" aria-hidden />
            重试
          </Button>
          <Button variant="outline" asChild>
            <Link to="/vulnerabilities">返回列表</Link>
          </Button>
        </CardContent>
      </Card>
    );
  }

  const { unified, enriched } = data;
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${unified.vuln_id}`;

  return (
    <div className="space-y-4">
      <header className="rounded-xl border border-border/70 bg-card p-5 shadow-card">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="font-mono text-2xl font-semibold tracking-tight">{unified.vuln_id}</h1>
              <SeverityBadge severity={unified.severity} />
              {unified.kev ? (
                <Badge className="bg-critical text-critical-foreground">KEV 已知被利用</Badge>
              ) : null}
              {enriched ? (
                <Badge variant="secondary">已富化 · 风险 {enriched.risk_score.toFixed(0)}</Badge>
              ) : (
                <Badge variant="outline">未富化</Badge>
              )}
            </div>
            <p className="max-w-3xl text-sm text-muted-foreground">
              {unified.title ?? "（无标题）"}
            </p>
            <div className="flex flex-wrap items-center gap-1">
              {unified.sources.map((source) => (
                <span
                  key={source}
                  className="rounded bg-muted px-1.5 py-0.5 text-[11px] uppercase text-muted-foreground"
                >
                  {source}
                </span>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => downloadJson(data, unified.vuln_id)}>
              <Download className="mr-2 size-4" aria-hidden />
              导出 JSON
            </Button>
            <Button variant="outline" size="sm" onClick={() => void handleCopy()}>
              <Copy className="mr-2 size-4" aria-hidden />
              复制 CVE ID
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href={nvdUrl} target="_blank" rel="noreferrer">
                在 NVD 查看
                <ExternalLink className="ml-2 size-4" aria-hidden />
              </a>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void refetch()}
              disabled={isFetching}
              aria-label="刷新详情"
            >
              <RefreshCw className={isFetching ? "size-4 animate-spin" : "size-4"} aria-hidden />
            </Button>
          </div>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <div className="overflow-x-auto">
              <TabsList className="w-max">
                {TAB_ITEMS.map((item) => (
                  <TabsTrigger key={item.value} value={item.value}>
                    {item.label}
                  </TabsTrigger>
                ))}
              </TabsList>
            </div>

            <TabsContent value="basic">
              <BasicInfoTab unified={unified} />
            </TabsContent>
            <TabsContent value="assets">
              <AssetsTab enriched={enriched} />
            </TabsContent>
            <TabsContent value="exploits">
              <ExploitsTab enriched={enriched} />
            </TabsContent>
            <TabsContent value="papers">
              <PapersTab enriched={enriched} />
            </TabsContent>
            <TabsContent value="attack">
              <AttackChainTab enriched={enriched} />
            </TabsContent>
            <TabsContent value="remediation">
              <RemediationTab unified={unified} enriched={enriched} />
            </TabsContent>
            <TabsContent value="graph">
              <GraphTab cveId={unified.vuln_id} />
            </TabsContent>
          </Tabs>
        </div>

        <DetailSidebar unified={unified} enriched={enriched} />
      </div>
    </div>
  );
}

export default VulnDetailPage;
