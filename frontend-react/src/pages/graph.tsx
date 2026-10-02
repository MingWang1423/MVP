/**
 * 知识图谱页（Day16 任务 1；P8 最后一页）。
 *
 * 数据源（§1.4）：
 * - URL 带 ``?cve=CVE-XXXX`` → ``GET /api/v1/graph/{cve_id}``（1 跳子图，Neo4j 优先、PG 降级）；
 * - 不带参数 → ``GET /api/v1/graph?limit=N``（多 CVE 合并全图概览，PG 冻结契约推导）。
 *
 * 交互（§1.3）：拖拽 / 缩放 / MiniMap / 适应画布、节点展开折叠、双击漏洞节点跳详情、
 * 导出 PNG（自绘 canvas，无新增依赖）。
 *
 * 布局（§1.1）：概览用 :func:`layoutOverview`（簇 + 枢纽，确定性）；
 * 单 CVE 子图复用详情页的 :func:`layoutRadial`（放射状，同一 CVE 位置稳定，便于截图对比）。
 */

import { RefreshCw } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { layoutRadial } from "@/components/detail/graph-view";
import { GraphCanvas } from "@/components/graph/graph-canvas";
import { GraphLegend } from "@/components/graph/graph-legend";
import { buildFlowEdges, buildFlowNodes } from "@/components/graph/graph-node";
import { GraphSidebar } from "@/components/graph/graph-sidebar";
import { GraphToolbar } from "@/components/graph/graph-toolbar";
import { PageHeader } from "@/components/page-header";
import { ErrorState } from "@/components/state/error-state";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { formatCount, formatDateTime } from "@/lib/format";
import { downloadCanvasPng, graphFileName, renderGraphToCanvas } from "@/lib/graph-export";
import {
  UNKNOWN_RISK_SCORE,
  applyCollapse,
  buildAdjacency,
  layoutOverview,
  matchesQuery,
  matchesRiskRange,
  nodeRiskScore,
  summarizeTypes,
} from "@/lib/graph-layout";
import { GRAPH_NODE_META, normalizeNodeType } from "@/lib/graph-meta";
import { useGraph, useGraphOverview } from "@/lib/queries";
import type { GraphNodeDto, GraphNodeType } from "@/lib/types";

/** 概览默认合并的漏洞条数（与后端默认一致）。 */
const OVERVIEW_LIMIT = 20;

/** 无 CVE 参数时使用的占位值（Radix Select 不接受空串）。 */
const OVERVIEW_KEY = "__overview__";

/** 类型过滤：空集合表示全选。 */
type TypeFilter = Set<GraphNodeType>;

/**
 * 生成数据来源文案（Neo4j 图数据库 / 冻结契约推导）。
 *
 * @param isOverview 是否为全图概览。
 * @param backend 后端 ``backend`` 字段。
 * @returns 中文来源说明。
 */
function originLabel(isOverview: boolean, backend?: "neo4j" | "postgres"): string {
  if (!backend) {
    return "加载中";
  }
  if (backend === "neo4j") {
    return "Neo4j 图数据库";
  }
  return isOverview ? "冻结契约推导（PG）" : "冻结契约推导（PG 降级）";
}

/**
 * 图谱页组件。
 *
 * @returns 图谱页元素（左侧筛选栏 + 占满主内容区的 React Flow 画布）。
 */
export function GraphPage(): JSX.Element {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const cveParam = (searchParams.get("cve") ?? "").trim();
  const isOverview = cveParam.length === 0;

  const overviewQuery = useGraphOverview(OVERVIEW_LIMIT, isOverview);
  const subgraphQuery = useGraph(cveParam, !isOverview);
  const { data, isLoading, isFetching, isError, error, refetch } = isOverview
    ? overviewQuery
    : subgraphQuery;

  const [query, setQuery] = useState("");
  const [activeTypes, setActiveTypes] = useState<TypeFilter>(new Set());
  const [riskRange, setRiskRange] = useState<[number, number]>([0, 100]);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const allNodes: GraphNodeDto[] = useMemo(() => data?.nodes ?? [], [data]);
  const allEdges = useMemo(() => data?.edges ?? [], [data]);
  const viewKey = isOverview ? `overview-${OVERVIEW_LIMIT}` : cveParam.toUpperCase();
  const backend = data?.backend;

  const adjacency = useMemo(() => buildAdjacency(allEdges), [allEdges]);
  const neighbourCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const [id, neighbours] of adjacency.entries()) {
      counts.set(id, neighbours.size);
    }
    return counts;
  }, [adjacency]);

  // ① 类型 + 风险分过滤（检索只做高亮，不做隐藏，避免「搜不到就白屏」）
  const filtered = useMemo(() => {
    const nodes = allNodes.filter(
      (node) =>
        (activeTypes.size === 0 || activeTypes.has(normalizeNodeType(node.type))) &&
        matchesRiskRange(node, riskRange),
    );
    const ids = new Set(nodes.map((node) => node.id));
    return { nodes, edges: allEdges.filter((edge) => ids.has(edge.source) && ids.has(edge.target)) };
  }, [allNodes, allEdges, activeTypes, riskRange]);

  // ② 展开 / 折叠（共享枢纽不被误隐藏，见 lib/graph-layout.ts）
  const collapseResult = useMemo(
    () => applyCollapse(filtered.nodes, filtered.edges, collapsed),
    [filtered, collapsed],
  );

  const positions = useMemo(
    () =>
      isOverview
        ? layoutOverview(collapseResult.nodes, collapseResult.edges)
        : layoutRadial(collapseResult.nodes),
    [isOverview, collapseResult],
  );

  const riskScores = useMemo(() => {
    const scores = new Map<string, number>();
    for (const node of allNodes) {
      scores.set(node.id, nodeRiskScore(node));
    }
    return scores;
  }, [allNodes]);

  const matchedIds = useMemo(() => {
    const ids = new Set<string>();
    if (!query.trim()) {
      return ids;
    }
    for (const node of collapseResult.nodes) {
      if (matchesQuery(node, query)) {
        ids.add(node.id);
      }
    }
    return ids;
  }, [collapseResult.nodes, query]);

  const handleToggleCollapse = useCallback((nodeId: string) => {
    setCollapsed((previous) => {
      const next = new Set(previous);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  }, []);

  const hiddenCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const id of collapsed) {
      const neighbours = adjacency.get(id) ?? new Set<string>();
      const visible = collapseResult.nodes.filter((node) => neighbours.has(node.id)).length;
      counts.set(id, Math.max(0, neighbours.size - visible));
    }
    return counts;
  }, [adjacency, collapsed, collapseResult.nodes]);

  const flowNodes = useMemo(
    () =>
      buildFlowNodes(collapseResult.nodes, positions, {
        riskScores,
        neighbourCounts,
        collapsed,
        hiddenCounts,
        matchedIds,
        highlight: query.trim().length > 0,
        onToggleCollapse: handleToggleCollapse,
      }),
    [
      collapseResult.nodes,
      positions,
      riskScores,
      neighbourCounts,
      collapsed,
      hiddenCounts,
      matchedIds,
      query,
      handleToggleCollapse,
    ],
  );

  const flowEdges = useMemo(() => buildFlowEdges(collapseResult.edges), [collapseResult.edges]);
  const typeCounts = useMemo(() => summarizeTypes(collapseResult.nodes), [collapseResult.nodes]);
  const relationTypes = useMemo(
    () => [...new Set(collapseResult.edges.map((edge) => edge.relation))].sort(),
    [collapseResult.edges],
  );
  const selected = useMemo(
    () => allNodes.find((node) => node.id === selectedId) ?? null,
    [allNodes, selectedId],
  );
  const collapsibleVulnerabilities = useMemo(
    () =>
      collapseResult.nodes.filter(
        (node) => normalizeNodeType(node.type) === "vulnerability" && (neighbourCounts.get(node.id) ?? 0) > 0,
      ),
    [collapseResult.nodes, neighbourCounts],
  );

  /**
   * 切换视图（概览 ↔ 某 CVE 子图），并重置折叠 / 选中状态。
   *
   * @param value ``__overview__`` 或某个 CVE 编号。
   */
  const switchView = useCallback(
    (value: string) => {
      setCollapsed(new Set());
      setSelectedId(null);
      const next = new URLSearchParams(searchParams);
      if (value === OVERVIEW_KEY) {
        next.delete("cve");
      } else {
        next.set("cve", value);
      }
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams],
  );

  /** 导出当前视图为 PNG（自绘 canvas，无新增依赖）。 */
  const handleExport = useCallback(() => {
    const canvas = renderGraphToCanvas(
      collapseResult.nodes.map((node) => {
        const position = positions[node.id] ?? { x: 0, y: 0 };
        return {
          id: node.id,
          label: node.label,
          type: normalizeNodeType(node.type),
          x: position.x,
          y: position.y,
          riskScore: riskScores.get(node.id) ?? UNKNOWN_RISK_SCORE,
        };
      }),
      collapseResult.edges.map((edge) => ({
        source: edge.source,
        target: edge.target,
        relation: edge.relation,
      })),
      {
        colors: Object.fromEntries(
          Object.entries(GRAPH_NODE_META).map(([type, meta]) => [type, meta.color]),
        ),
        labels: Object.fromEntries(
          Object.entries(GRAPH_NODE_META).map(([type, meta]) => [type, meta.label]),
        ),
        title: isOverview
          ? `知识图谱概览（${originLabel(isOverview, backend)}）`
          : `CVE 1 跳子图：${cveParam.toUpperCase()}（${originLabel(isOverview, backend)}）`,
      },
    );
    downloadCanvasPng(canvas, graphFileName(isOverview ? "overview" : cveParam));
  }, [collapseResult, positions, riskScores, isOverview, cveParam, backend]);

  const cveOptions = useMemo(() => {
    const ids = isOverview
      ? data && "cve_ids" in data
        ? data.cve_ids
        : []
      : [cveParam];
    return [...new Set(ids.map((id) => id.toUpperCase()))].filter(Boolean);
  }, [data, isOverview, cveParam]);

  return (
    <div className="flex h-[calc(100vh-7.5rem)] min-h-[620px] flex-col gap-4">
      <PageHeader
        title="知识图谱"
        description={
          <span>
            漏洞 / 组件 / 资产 / 攻击技术 / 补丁 / 论文关联子图 · 边 = AFFECTS · INSTALLED_ON ·
            EXPLOITS · FIXED_BY · RELATED_TO
            {data ? (
              <>
                {" "}
                · 当前 {formatCount(data.node_count)} 节点 / {formatCount(data.edge_count)} 边 ·{" "}
                {originLabel(isOverview, backend)} ·{" "}
                {formatDateTime("generated_at" in data ? data.generated_at : undefined)}
              </>
            ) : null}
          </span>
        }
        actions={
          <>
            <Select
              value={isOverview ? OVERVIEW_KEY : cveParam.toUpperCase()}
              onValueChange={switchView}
            >
              <SelectTrigger className="w-[260px]" aria-label="切换图谱视图">
                <SelectValue placeholder="选择视图" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={OVERVIEW_KEY}>
                  全图概览（Top {OVERVIEW_LIMIT} 风险漏洞）
                </SelectItem>
                {cveOptions.map((cve) => (
                  <SelectItem key={cve} value={cve}>
                    1 跳子图：{cve}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => void refetch()} disabled={isFetching}>
              <RefreshCw
                className={isFetching ? "mr-2 size-4 animate-spin" : "mr-2 size-4"}
                aria-hidden
              />
              刷新
            </Button>
          </>
        }
      />

      {isError && !data ? (
        <ErrorState
          className="flex-1"
          title="图谱加载失败"
          error={error}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-4 xl:flex-row">
          <GraphSidebar
            className="max-h-none overflow-y-auto xl:max-h-full"
            query={query}
            onQueryChange={setQuery}
            activeTypes={activeTypes}
            onToggleType={(type) =>
              setActiveTypes((previous) => {
                const next = new Set(previous);
                if (next.has(type)) {
                  next.delete(type);
                } else {
                  next.add(type);
                }
                return next;
              })
            }
            typeCounts={summarizeTypes(allNodes)}
            riskRange={riskRange}
            onRiskRangeChange={setRiskRange}
            matchedCount={query.trim() ? matchedIds.size : collapseResult.nodes.length}
            totalCount={collapseResult.nodes.length}
            selected={selected}
            onOpenDetail={(cveId) => navigate(`/vulnerabilities/${encodeURIComponent(cveId)}`)}
          />

          <div className="relative min-h-[420px] flex-1 overflow-hidden rounded-xl border bg-card shadow-card">
            {!data && !isError ? (
              <div className="flex h-full items-center justify-center" aria-busy>
                <div className="flex flex-col items-center gap-2 text-sm text-muted-foreground">
                  <span className="size-6 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                  正在加载图谱数据…
                </div>
              </div>
            ) : (
              <GraphCanvas
                nodes={flowNodes}
                edges={flowEdges}
                viewKey={viewKey}
                loading={isLoading && !data}
                onSelectNode={setSelectedId}
                emptyHint={
                  data && data.node_count === 0
                    ? "图谱中暂无数据（先富化漏洞，再执行 python -m scripts.load_graph --all）"
                    : "当前筛选条件下没有可展示的节点"
                }
                toolbar={
                  <GraphToolbar
                    viewLabel={isOverview ? "全图概览" : cveParam.toUpperCase()}
                    nodeCount={flowNodes.length}
                    edgeCount={flowEdges.length}
                    hiddenCount={collapseResult.hiddenCount}
                    canCollapse={collapsibleVulnerabilities.length > 0}
                    onExpandAll={() => setCollapsed(new Set())}
                    onCollapseAll={() =>
                      setCollapsed(new Set(collapsibleVulnerabilities.map((node) => node.id)))
                    }
                    onExport={handleExport}
                  />
                }
                legend={<GraphLegend typeCounts={typeCounts} relations={relationTypes} />}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default GraphPage;
