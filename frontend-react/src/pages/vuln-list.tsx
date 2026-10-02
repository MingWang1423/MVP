/**
 * 漏洞列表页（Day16 任务 1，参考 Dependabot 布局）。
 *
 * 组成：筛选栏（1.1） + 虚拟滚动表格（1.2） + 分页 + URL 同步（1.3）。
 * URL 是筛选状态唯一真相：刷新 / 分享链接都能复现同一视图。
 */

import type { SortingState } from "@tanstack/react-table";
import { ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { FilterBar } from "@/components/vuln/filter-bar";
import { VulnTable } from "@/components/vuln/vuln-table";
import { formatCount } from "@/lib/format";
import { useVulns } from "@/lib/queries";
import {
  DEFAULT_FILTERS,
  PAGE_SIZE_OPTIONS,
  buildSearchParams,
  parseFilters,
  toApiParams,
  type VulnListFilters,
} from "@/lib/vuln-filters";

/**
 * 漏洞列表页组件。
 *
 * @returns 列表页元素。
 */
export function VulnListPage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useMemo(() => parseFilters(searchParams), [searchParams]);
  const apiParams = useMemo(() => toApiParams(filters), [filters]);

  const { data, isLoading, isFetching, isError, error, refetch } = useVulns(apiParams);

  const sorting: SortingState = useMemo(
    () => (filters.sort ? [{ id: filters.sort.id, desc: filters.sort.desc }] : []),
    [filters.sort],
  );

  const applyPatch = useCallback(
    (patch: Partial<VulnListFilters>) => {
      setSearchParams(buildSearchParams({ ...filters, ...patch }), { replace: true });
    },
    [filters, setSearchParams],
  );

  const handleReset = useCallback(() => {
    setSearchParams(new URLSearchParams(), { replace: true });
  }, [setSearchParams]);

  const handleSortingChange = useCallback(
    (next: SortingState) => {
      const first = next[0];
      applyPatch({ sort: first ? { id: first.id, desc: first.desc } : null });
    },
    [applyPatch],
  );

  const rows = data?.items ?? [];
  const total = data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / filters.pageSize));
  const start = total === 0 ? 0 : (filters.page - 1) * filters.pageSize + 1;
  const end = Math.min(total, filters.page * filters.pageSize);
  const isCustomPageSize = filters.pageSize !== DEFAULT_FILTERS.pageSize;

  return (
    <div className="space-y-4">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">漏洞情报列表</h1>
          <p className="text-sm text-muted-foreground">
            多源归一化后的统一漏洞视图 · 支持严重度 / 来源 / 时间 / KEV / PoC 组合筛选
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void refetch()} disabled={isFetching}>
          <RefreshCw
            className={isFetching ? "mr-2 size-4 animate-spin" : "mr-2 size-4"}
            aria-hidden
          />
          刷新
        </Button>
      </header>

      <FilterBar
        filters={filters}
        onChange={applyPatch}
        onReset={handleReset}
        total={total}
        loading={isFetching}
      />

      {isError ? (
        <Card className="border-destructive/40 shadow-card">
          <CardHeader className="space-y-1">
            <h2 className="text-base font-semibold text-destructive">列表加载失败</h2>
            <p className="text-sm text-muted-foreground">
              {error instanceof Error ? error.message : "未知错误"}
            </p>
          </CardHeader>
          <CardContent>
            <Button onClick={() => void refetch()}>
              <RefreshCw className="mr-2 size-4" aria-hidden />
              重试
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card className="overflow-hidden shadow-card">
          <VulnTable
            rows={rows}
            loading={isLoading}
            refreshing={isFetching && !isLoading}
            sorting={sorting}
            onSortingChange={handleSortingChange}
          />
          <div className="flex flex-col gap-2 border-t px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3 text-xs text-muted-foreground">
              <span>
                第 {start}-{end} 条 / 共 {formatCount(total)} 条
              </span>
              <span className="hidden sm:inline">
                第 {filters.page} / {pageCount} 页
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">每页</span>
              <Select
                value={String(filters.pageSize)}
                onValueChange={(value) => applyPatch({ pageSize: Number(value), page: 1 })}
              >
                <SelectTrigger className="h-8 w-[80px]" aria-label="每页条数">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PAGE_SIZE_OPTIONS.map((size) => (
                    <SelectItem key={size} value={String(size)}>
                      {size}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="sm"
                className="h-8"
                disabled={filters.page <= 1}
                onClick={() => applyPatch({ page: filters.page - 1 })}
              >
                <ChevronLeft className="mr-1 size-4" aria-hidden />
                上一页
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8"
                disabled={filters.page >= pageCount}
                onClick={() => applyPatch({ page: filters.page + 1 })}
              >
                下一页
                <ChevronRight className="ml-1 size-4" aria-hidden />
              </Button>
            </div>
          </div>
        </Card>
      )}

      <p className="text-xs text-muted-foreground">
        提示：筛选条件已写入 URL（可复制分享）；页码与每页条数同样保留
        {isCustomPageSize ? "（当前为自定义每页条数）" : ""}。
      </p>
    </div>
  );
}

export default VulnListPage;
