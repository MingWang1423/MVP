/**
 * 图谱节点类型的展示元数据（Day16 任务 1；单一事实来源）。
 *
 * 为什么单独成文件：三处都要用同一份「类型 → 颜色 / 中文名」映射——
 * 1. 详情页「图谱子图」Tab（``components/detail/graph-view.tsx``，已改为从本文件 re-export）；
 * 2. 图谱页画布 / 图例 / 侧栏（``components/graph/*``）；
 * 3. 图谱页「导出 PNG」的画布渲染（``lib/graph-export.ts`` 由调用方传入配色）。
 *
 * 颜色与 ``tailwind.config.js`` / ``lib/format.ts`` 的设计 token 保持一致：
 * 漏洞 = ``#d62728``（critical）、组件 = ``#1f77b4``（primary）、资产 = ``#2ca02c``（low）、
 * 攻击技术 = ``#ff7f0e``（high）、补丁 = ``#9467bd``、论文 = ``#17becf``。
 */

import type { GraphNodeType } from "@/lib/types";

/** 节点类型元数据（颜色为图表库所需的字面量，禁止在组件里再写十六进制）。 */
export const GRAPH_NODE_META: Record<GraphNodeType, { label: string; color: string }> = {
  vulnerability: { label: "漏洞", color: "#d62728" },
  component: { label: "组件", color: "#1f77b4" },
  asset: { label: "资产", color: "#2ca02c" },
  technique: { label: "攻击技术", color: "#ff7f0e" },
  paper: { label: "论文", color: "#17becf" },
  patch: { label: "补丁", color: "#9467bd" },
  unknown: { label: "其它", color: "#94a3b8" },
};

/** 类型过滤器的展示顺序（图例与复选框共用）。 */
export const GRAPH_NODE_TYPE_ORDER: readonly GraphNodeType[] = [
  "vulnerability",
  "component",
  "asset",
  "technique",
  "patch",
  "paper",
  "unknown",
];

/** 关系类型的中文说明（边标签 tooltip 用；关系名本身按后端原样展示）。 */
export const GRAPH_RELATION_LABELS: Record<string, string> = {
  AFFECTS: "影响（漏洞 → 组件）",
  INSTALLED_ON: "部署于（组件 → 资产）",
  EXPLOITS: "利用（漏洞 → 攻击技术）",
  FIXED_BY: "修复（漏洞 → 补丁 / 公告）",
  RELATED_TO: "相关（论文 ↔ 漏洞）",
};

/**
 * 把后端节点类型字符串归一化为 :type:`GraphNodeType`（纯函数）。
 *
 * @param type 后端返回的 ``type``。
 * @returns 归一化后的类型（未知类型回退 ``unknown``）。
 */
export function normalizeNodeType(type: string): GraphNodeType {
  return type in GRAPH_NODE_META ? (type as GraphNodeType) : "unknown";
}

/**
 * 取节点配色的十六进制字面量（图表 / 画布导出用）。
 *
 * @param type 后端节点类型字符串。
 * @returns 形如 ``#d62728`` 的颜色。
 */
export function nodeColor(type: string): string {
  return GRAPH_NODE_META[normalizeNodeType(type)].color;
}
