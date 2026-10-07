/**
 * 漏洞列表表格（Day16 任务 1.2）：TanStack Table（列定义 / 排序）+ TanStack Virtual（虚拟滚动）。
 *
 * 设计说明：
 * 1. **虚拟滚动**：行高固定 56px，只渲染可视区 ± overscan 行；分页 100 条 / 页时
 *    仍保持恒定 DOM 规模（后续放宽分页上限也无需改组件）；
 * 2. **排序**：服务端只保证「时间轴倒序」，因此列头排序是**当前页内排序**
 *    （TanStack 本地排序模型），排序状态由父组件同步到 URL；
 * 3. **点击行**跳转 ``/vulnerabilities/:cveId``；CVE 编号本身也是链接（可新窗口打开）。
 */

import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, ArrowUpDown, Inbox } from "lucide-react";
import { useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";

import { SeverityBadge } from "@/components/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { formatDateTime } from "@/lib/format";
import type { VulnSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

/** 行高（像素，虚拟滚动依赖固定行高）。 */
const ROW_HEIGHT = 56;

/** 可视区外预渲染行数。 */
const OVERSCAN = 8;

/** 表格滚动容器高度（像素）。 */
const VIEWPORT_HEIGHT = 560;

/** 列宽（CSS Grid 模板，表头与行共用同一份定义，保证对齐）。 */
const GRID_TEMPLATE =
  "150px minmax(260px, 3fr) 96px 92px minmax(140px, 1fr) 150px 80px 72px";

/** 严重度排序权重（未知最小）。 */
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

/** 组件属性。 */
export interface VulnTableProps {
  /** 当前页数据。 */
  rows: VulnSummary[];
  /** 是否首次加载（渲染骨架屏）。 */
  loading?: boolean;
  /** 是否正在后台刷新（保留旧数据，进度提示）。 */
  refreshing?: boolean;
  /** 排序状态（受控，由父组件同步 URL）。 */
  sorting: SortingState;
  /** 排序变更回调。 */
  onSortingChange: (sorting: SortingState) => void;
}

/**
 * 列定义（纯数据，便于审阅与复用）。
 *
 * @returns TanStack Table 列定义数组。
 */
function buildColumns(): ColumnDef<VulnSummary>[] {
  return [
    {
      id: "vuln_id",
      header: "CVE ID",
      accessorFn: (row) => row.vuln_id,
      cell: ({ row }) => (
        <a
          href={`/vulnerabilities/${row.original.vuln_id}`}
          className="font-mono text-xs font-medium text-primary hover:underline"
          onClick={(event) => event.stopPropagation()}
        >
          {row.original.vuln_id}
        </a>
      ),
    },
    {
      id: "title",
      header: "标题",
      accessorFn: (row) => row.title ?? "",
      cell: ({ row }) => (
        <span className="line-clamp-2 text-sm" title={row.original.title ?? undefined}>
          {row.original.title ?? "—"}
        </span>
      ),
    },
    {
      id: "severity",
      header: "严重度",
      accessorFn: (row) => SEVERITY_RANK[row.severity ?? ""] ?? 0,
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "risk_score",
      header: "风险分",
      accessorFn: (row) => row.risk_score ?? -1,
      cell: ({ row }) => (
        <span className="tabular-nums">
          {row.original.risk_score === null ? "—" : row.original.risk_score.toFixed(1)}
        </span>
      ),
    },
    {
      id: "sources",
      header: "来源",
      accessorFn: (row) => row.sources.join(","),
      cell: ({ row }) => (
        <span className="flex flex-wrap gap-1">
          {row.original.sources.slice(0, 3).map((source) => (
            <span
              key={source}
              className="rounded bg-muted px-1.5 py-0.5 text-[11px] uppercase text-muted-foreground"
            >
              {source}
            </span>
          ))}
          {row.original.sources.length > 3 ? (
            <span className="text-[11px] text-muted-foreground">
              +{row.original.sources.length - 3}
            </span>
          ) : null}
        </span>
      ),
    },
    {
      id: "published_at",
      header: "发布时间",
      accessorFn: (row) => row.published_at ?? "",
      cell: ({ row }) => (
        <span
          className="whitespace-nowrap text-xs text-muted-foreground"
          title={
            row.original.published_at
              ? "源侧披露时间"
              : "源未提供发布时间（不以入库时间替代；见详情页「入库（归一化）」）"
          }
        >
          {formatDateTime(row.original.published_at)}
        </span>
      ),
    },
    {
      id: "poc_count",
      header: "PoC 数",
      accessorFn: (row) => row.poc_count,
      cell: ({ row }) => (
        <span className={cn("tabular-nums", row.original.poc_count > 0 && "font-medium text-high")}>
          {row.original.poc_count}
        </span>
      ),
    },
    {
      id: "kev",
      header: "KEV",
      accessorFn: (row) => (row.kev ? 1 : 0),
      cell: ({ row }) =>
        row.original.kev ? (
          <span className="rounded bg-critical/10 px-1.5 py-0.5 text-[11px] font-medium text-critical">
            KEV
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
  ];
}

/**
 * 骨架屏（首次加载）。
 *
 * @returns 与真实行同高的占位列表。
 */
function TableSkeleton(): JSX.Element {
  return (
    <div className="space-y-2 p-4" aria-busy>
      {Array.from({ length: 8 }).map((_, index) => (
        <Skeleton key={index} className="h-[48px] w-full" />
      ))}
    </div>
  );
}

/**
 * 虚拟滚动漏洞表格。
 *
 * @param props 见 :interface:`VulnTableProps`。
 * @returns 表格元素。
 */
export function VulnTable({
  rows,
  loading,
  refreshing,
  sorting,
  onSortingChange,
}: VulnTableProps): JSX.Element {
  const navigate = useNavigate();
  const scrollRef = useRef<HTMLDivElement>(null);
  const columns = useMemo(buildColumns, []);

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sorting) : updater;
      onSortingChange(next);
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const tableRows = table.getRowModel().rows;
  const virtualizer = useVirtualizer({
    count: tableRows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: OVERSCAN,
  });

  if (loading) {
    return <TableSkeleton />;
  }

  if (tableRows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-20 text-muted-foreground">
        <Inbox className="size-8" aria-hidden />
        <p className="text-sm">没有符合条件的漏洞，试试放宽筛选条件</p>
      </div>
    );
  }

  const virtualRows = virtualizer.getVirtualItems();

  return (
    <div className={cn("relative", refreshing && "opacity-60 transition-opacity")}>
      {/* 表头（与行共用 GRID_TEMPLATE，保证列对齐） */}
      <div
        className="grid items-center gap-3 border-b bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground"
        style={{ gridTemplateColumns: GRID_TEMPLATE }}
        role="row"
      >
        {table.getHeaderGroups()[0].headers.map((header) => {
          const sorted = header.column.getIsSorted();
          return (
            <button
              key={header.id}
              type="button"
              className="flex items-center gap-1 text-left uppercase tracking-wide hover:text-foreground"
              onClick={header.column.getToggleSortingHandler()}
              aria-label={`按 ${String(header.column.columnDef.header)} 排序`}
            >
              {flexRender(header.column.columnDef.header, header.getContext())}
              {sorted === "asc" ? (
                <ArrowUp className="size-3" aria-hidden />
              ) : sorted === "desc" ? (
                <ArrowDown className="size-3" aria-hidden />
              ) : (
                <ArrowUpDown className="size-3 opacity-40" aria-hidden />
              )}
            </button>
          );
        })}
      </div>

      {/* 虚拟滚动区 */}
      <div ref={scrollRef} className="overflow-auto" style={{ height: VIEWPORT_HEIGHT }}>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualRows.map((virtualRow) => {
            const row = tableRows[virtualRow.index];
            return (
              <div
                key={row.id}
                role="row"
                tabIndex={0}
                onClick={() => navigate(`/vulnerabilities/${row.original.vuln_id}`)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    navigate(`/vulnerabilities/${row.original.vuln_id}`);
                  }
                }}
                className="absolute left-0 top-0 grid w-full cursor-pointer items-center gap-3 border-b px-4 transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none"
                style={{
                  gridTemplateColumns: GRID_TEMPLATE,
                  height: ROW_HEIGHT,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                {row.getVisibleCells().map((cell) => (
                  <div key={cell.id} className="min-w-0">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>

      <div className="flex items-center justify-between border-t px-4 py-2 text-xs text-muted-foreground">
        <span>当前页 {tableRows.length} 条（虚拟滚动渲染 {virtualRows.length} 行）</span>
        <span>点击任意行查看详情 · 点击列头排序（当前页内）</span>
      </div>
    </div>
  );
}

export { GRID_TEMPLATE, ROW_HEIGHT };
