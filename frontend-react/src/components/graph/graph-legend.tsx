/**
 * 图谱图例（Day16 任务 1.1）：类型配色 + 数量 + 关系类型。
 *
 * 与侧栏的类型过滤器同源（都读 :data:`GRAPH_NODE_META`），保证颜色含义在全站唯一。
 * 关系类型只展示代号（中文释义放 ``title`` 悬浮提示），避免图例在画布上过宽遮挡节点。
 */

import { GRAPH_NODE_META, GRAPH_RELATION_LABELS } from "@/lib/graph-meta";
import type { GraphNodeType } from "@/lib/types";

/** 组件属性。 */
export interface GraphLegendProps {
  /** 类型 → 数量（仅展示出现过且数量 > 0 的类型）。 */
  typeCounts: Partial<Record<GraphNodeType, number>>;
  /** 出现过的关系类型（展示代号 + 悬浮中文释义）。 */
  relations: string[];
}

/**
 * 渲染图例。
 *
 * @param props 见 :interface:`GraphLegendProps`。
 * @returns 图例元素。
 */
export function GraphLegend({ typeCounts, relations }: GraphLegendProps): JSX.Element {
  const types = (Object.keys(GRAPH_NODE_META) as GraphNodeType[]).filter(
    (type) => (typeCounts[type] ?? 0) > 0,
  );
  return (
    <div className="flex max-w-[min(70vw,880px)] flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
      {types.map((type) => (
        <span key={type} className="flex items-center gap-1">
          <span
            className="size-2.5 rounded-full"
            style={{ backgroundColor: GRAPH_NODE_META[type].color }}
            aria-hidden
          />
          {GRAPH_NODE_META[type].label}
          <span className="tabular-nums">({typeCounts[type] ?? 0})</span>
        </span>
      ))}
      {relations.length > 0 ? (
        <span className="flex flex-wrap items-center gap-x-2">
          <span className="opacity-60">|</span>
          {relations.map((relation) => (
            <span key={relation} title={GRAPH_RELATION_LABELS[relation] ?? relation}>
              {relation}
            </span>
          ))}
        </span>
      ) : null}
    </div>
  );
}
