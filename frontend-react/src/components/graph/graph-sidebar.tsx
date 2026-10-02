/**
 * 图谱侧栏（Day16 任务 1.2）：检索 / 类型多选 / 风险分区间 / 选中节点详情。
 *
 * 交互约定：
 * - 侧栏**只负责收集条件**，过滤与折叠由页面（``pages/graph.tsx``）执行，保证「同一份
 *   筛选状态 → 同一张图」，便于截图复现；
 * - 检索命中数实时显示（``命中 / 总数``），方便演示时确认筛选生效；
 * - 选中节点详情展示 ``properties`` 全量键值（后端已把 ``risk_score`` / ``severity``
 *   等字段放进 ``properties``），并提供「打开详情页」入口（仅漏洞节点）。
 */

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { RangeSlider } from "@/components/ui/range-slider";
import { nodeRiskScore } from "@/lib/graph-layout";
import { GRAPH_NODE_META, GRAPH_NODE_TYPE_ORDER, normalizeNodeType } from "@/lib/graph-meta";
import type { GraphNodeDto, GraphNodeType } from "@/lib/types";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface GraphSidebarProps {
  /** 检索关键词。 */
  query: string;
  /** 检索变化回调。 */
  onQueryChange: (value: string) => void;
  /** 选中的类型（空集合 = 全选）。 */
  activeTypes: Set<GraphNodeType>;
  /** 类型开关回调。 */
  onToggleType: (type: GraphNodeType) => void;
  /** 各类型节点数量（勾选框右侧展示）。 */
  typeCounts: Partial<Record<GraphNodeType, number>>;
  /** 风险分区间。 */
  riskRange: [number, number];
  /** 风险分区间变化回调。 */
  onRiskRangeChange: (value: [number, number]) => void;
  /** 命中检索的节点数。 */
  matchedCount: number;
  /** 当前视图节点总数。 */
  totalCount: number;
  /** 当前选中节点。 */
  selected: GraphNodeDto | null;
  /** 打开详情页（仅漏洞节点可用）。 */
  onOpenDetail?: (cveId: string) => void;
  /** 附加类名。 */
  className?: string;
}

/**
 * 渲染图谱侧栏。
 *
 * @param props 见 :interface:`GraphSidebarProps`。
 * @returns 侧栏元素。
 */
export function GraphSidebar({
  query,
  onQueryChange,
  activeTypes,
  onToggleType,
  typeCounts,
  riskRange,
  onRiskRangeChange,
  matchedCount,
  totalCount,
  selected,
  onOpenDetail,
  className,
}: GraphSidebarProps): JSX.Element {
  const selectedType = selected ? normalizeNodeType(selected.type) : null;
  const selectedCve = selected ? String(selected.properties?.cve_id ?? "") : "";

  return (
    <aside className={cn("space-y-4 xl:w-72 xl:shrink-0", className)} aria-label="图谱筛选">
      <section className="space-y-2 rounded-xl border bg-card p-4 shadow-card">
        <h2 className="text-sm font-semibold">检索</h2>
        <Input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="CVE 编号 / 组件名，如 CVE-2024-3400"
          aria-label="图谱检索框"
        />
        <p className="text-xs text-muted-foreground">
          命中 <span className="font-medium tabular-nums text-foreground">{matchedCount}</span> /{" "}
          {totalCount}
          {query.trim() ? " 个节点（未命中节点会变淡）" : "（输入关键词后高亮匹配节点）"}
        </p>
      </section>

      <section className="space-y-2 rounded-xl border bg-card p-4 shadow-card">
        <h2 className="text-sm font-semibold">节点类型</h2>
        <ul className="space-y-1.5">
          {GRAPH_NODE_TYPE_ORDER.filter((type) => (typeCounts[type] ?? 0) > 0).map((type) => {
            const meta = GRAPH_NODE_META[type];
            return (
              <li key={type}>
                <label className="flex cursor-pointer items-center gap-2 text-sm">
                  <Checkbox
                    checked={activeTypes.size === 0 || activeTypes.has(type)}
                    onCheckedChange={() => onToggleType(type)}
                    aria-label={`过滤 ${meta.label}`}
                  />
                  <span
                    className="size-2.5 rounded-full"
                    style={{ backgroundColor: meta.color }}
                    aria-hidden
                  />
                  <span className="flex-1">{meta.label}</span>
                  <span className="text-xs tabular-nums text-muted-foreground">
                    {typeCounts[type] ?? 0}
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
        {activeTypes.size > 0 ? (
          <p className="text-xs text-muted-foreground">
            已选 {activeTypes.size} 类；取消全部勾选即恢复全选。
          </p>
        ) : null}
      </section>

      <section className="space-y-2 rounded-xl border bg-card p-4 shadow-card">
        <h2 className="text-sm font-semibold">风险分区间</h2>
        <RangeSlider
          min={0}
          max={100}
          step={5}
          value={riskRange}
          onChange={onRiskRangeChange}
          ariaLabel="风险分区间"
        />
        <p className="text-xs text-muted-foreground">
          仅过滤漏洞节点（闭区间）；未富化条目风险分按 0 处理。
        </p>
      </section>

      <section className="space-y-2 rounded-xl border bg-card p-4 shadow-card">
        <h2 className="text-sm font-semibold">节点详情</h2>
        {selected ? (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span
                className="size-2.5 rounded-full"
                style={{ backgroundColor: GRAPH_NODE_META[selectedType ?? "unknown"].color }}
                aria-hidden
              />
              <span className="text-sm font-medium">{selected.label}</span>
            </div>
            <p className="text-xs text-muted-foreground">
              类型：{GRAPH_NODE_META[selectedType ?? "unknown"].label}
              {selectedType === "vulnerability"
                ? ` · 风险分 ${nodeRiskScore(selected).toFixed(0)}`
                : ""}
            </p>
            <dl className="max-h-56 space-y-1 overflow-y-auto rounded-lg bg-muted/40 p-2 text-xs">
              {Object.entries(selected.properties ?? {})
                .filter(([, value]) => value !== null && value !== undefined && value !== "")
                .slice(0, 24)
                .map(([key, value]) => (
                  <div key={key} className="flex gap-2">
                    <dt className="w-24 shrink-0 truncate text-muted-foreground">{key}</dt>
                    <dd className="min-w-0 flex-1 break-words">
                      {Array.isArray(value) ? value.join("、") : String(value)}
                    </dd>
                  </div>
                ))}
            </dl>
            {selectedType === "vulnerability" && selectedCve && onOpenDetail ? (
              <Button size="sm" variant="outline" onClick={() => onOpenDetail(selectedCve)}>
                打开漏洞详情
              </Button>
            ) : null}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            点击画布中的节点查看属性；
            <span className="font-medium">双击漏洞节点</span>可直接跳转详情页。
          </p>
        )}
      </section>
    </aside>
  );
}
