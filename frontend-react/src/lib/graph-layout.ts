/**
 * 图谱页的**纯函数**工具（Day16 任务 1：布局 / 折叠 / 检索 / 统计）。
 *
 * 全部为确定性计算，不触碰 DOM 与 React，便于单测与「同一份数据每次渲染位置一致」
 * （截图可复现）。三类能力：
 *
 * 1. :func:`layoutOverview`——多 CVE 合并图的「簇 + 枢纽」布局；
 * 2. :func:`applyCollapse`——展开 / 折叠邻居（共享枢纽不被误隐藏）；
 * 3. :func:`buildAdjacency` / :func:`matchesQuery` / :func:`nodeRiskScore` /
 *    :func:`summarizeTypes`——邻接表、检索、风险分读取与类型统计。
 */

import { normalizeNodeType } from "@/lib/graph-meta";
import type { GraphEdgeDto, GraphNodeDto, GraphNodeType } from "@/lib/types";

/** 坐标。 */
export interface XY {
  x: number;
  y: number;
}

/** 簇布局参数（有邻居的漏洞簇网格间距）。 */
const CLUSTER_GAP_X = 700;
const CLUSTER_GAP_Y = 620;

/** 无邻居漏洞（孤立中心）的紧凑网格间距。 */
const ISOLATED_GAP_X = 200;
const ISOLATED_GAP_Y = 180;

/** 邻居环：每环容量与环间距（环数随邻居数自适应，避免单环过宽）。 */
const RING_CAPACITY = 8;
const RING_BASE_RADIUS = 175;
const RING_STEP = 150;

/** 无风险分时的缺省值（未富化条目）。 */
export const UNKNOWN_RISK_SCORE = 0;

/** 邻接表：节点 ID → 邻居 ID 集合。 */
export type Adjacency = Map<string, Set<string>>;

/**
 * 计算邻居在环上的相对坐标（纯函数，确定性）。
 *
 * @param index 邻居序号（从 0 开始）。
 * @param total 该漏洞的邻居总数。
 * @returns 相对簇中心的坐标。
 */
function ringOffset(index: number, total: number): XY {
  const ring = Math.floor(index / RING_CAPACITY);
  const start = ring * RING_CAPACITY;
  const inRing = Math.max(1, Math.min(RING_CAPACITY, total - start));
  const order = index - start;
  const radius = RING_BASE_RADIUS + ring * RING_STEP;
  const angle = (2 * Math.PI * order) / inRing - Math.PI / 2 + ring * 0.45;
  return { x: Math.round(radius * Math.cos(angle)), y: Math.round(radius * Math.sin(angle)) };
}

/**
 * 读取漏洞节点的风险分（纯函数）。
 *
 * @param node 图谱节点。
 * @returns ``properties.risk_score``；缺失或非数字时返回 :data:`UNKNOWN_RISK_SCORE`。
 */
export function nodeRiskScore(node: GraphNodeDto): number {
  const raw = node.properties?.risk_score;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw;
  }
  if (typeof raw === "string" && raw.trim() !== "") {
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : UNKNOWN_RISK_SCORE;
  }
  return UNKNOWN_RISK_SCORE;
}

/**
 * 计算无向邻接表（纯函数）。
 *
 * @param edges 边列表。
 * @returns 邻接表（双向）。
 */
export function buildAdjacency(edges: GraphEdgeDto[]): Adjacency {
  const adjacency: Adjacency = new Map();
  const link = (from: string, to: string): void => {
    const bucket = adjacency.get(from) ?? new Set<string>();
    bucket.add(to);
    adjacency.set(from, bucket);
  };
  for (const edge of edges) {
    link(edge.source, edge.target);
    link(edge.target, edge.source);
  }
  return adjacency;
}

/**
 * 统计各类型的节点数量（纯函数，图例与侧栏展示用）。
 *
 * @param nodes 节点列表。
 * @returns 类型 → 数量（仅含出现过的类型）。
 */
export function summarizeTypes(nodes: GraphNodeDto[]): Partial<Record<GraphNodeType, number>> {
  const counts: Partial<Record<GraphNodeType, number>> = {};
  for (const node of nodes) {
    const type = normalizeNodeType(node.type);
    counts[type] = (counts[type] ?? 0) + 1;
  }
  return counts;
}

/**
 * 判断节点是否命中检索词（纯函数）。
 *
 * 口径：节点 ``id`` / ``label`` 与 ``properties`` 中的 ``cve_id`` / ``title`` /
 * ``component`` / ``name`` / ``vendor`` / ``technique_id`` 任意一处包含关键词
 * （大小写不敏感）。因此 CVE 编号与「vendor:product」组件名都能搜到。
 *
 * @param node 节点。
 * @param query 关键词（空串视为命中全部）。
 * @returns 命中返回 ``true``。
 */
export function matchesQuery(node: GraphNodeDto, query: string): boolean {
  const keyword = query.trim().toLowerCase();
  if (!keyword) {
    return true;
  }
  const haystack = [
    node.id,
    node.label,
    String(node.properties?.cve_id ?? ""),
    String(node.properties?.title ?? ""),
    String(node.properties?.component ?? ""),
    String(node.properties?.name ?? ""),
    String(node.properties?.vendor ?? ""),
    String(node.properties?.technique_id ?? ""),
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(keyword);
}

/**
 * 多 CVE 合并图的「簇 + 枢纽 + 孤立行」布局（纯函数）。
 *
 * 规则：
 * 1. **有邻居的漏洞**（通常是已富化条目）按风险分倒序排在网格上，列数 ≈ ``sqrt(n)``，
 *    邻居围绕簇中心成环（每环 8 个，环数随邻居数增长），共享邻居只放在首次出现的簇，
 *    因此多个 CVE 共用的组件 / 攻击技术会自然形成跨簇「枢纽」；
 * 2. **无邻居的漏洞**（未富化，只有中心节点）在簇下方用**紧凑网格**排布，
 *    避免它们把画布撑大、把有信息的簇挤小；
 * 3. 完全未挂到任何漏洞的节点排在最后一行。
 *
 * @param nodes 节点列表。
 * @param edges 边列表。
 * @returns 节点 ID → 坐标（缺失 ID 时由调用方兜底 ``{x: 0, y: 0}``）。
 */
export function layoutOverview(
  nodes: GraphNodeDto[],
  edges: GraphEdgeDto[],
): Record<string, XY> {
  const adjacency = buildAdjacency(edges);
  const vulnerabilities = nodes
    .filter((node) => normalizeNodeType(node.type) === "vulnerability")
    .sort((left, right) => {
      const diff = nodeRiskScore(right) - nodeRiskScore(left);
      return diff !== 0 ? diff : left.id.localeCompare(right.id);
    });
  const connected = vulnerabilities.filter((node) => (adjacency.get(node.id)?.size ?? 0) > 0);
  const isolated = vulnerabilities.filter((node) => (adjacency.get(node.id)?.size ?? 0) === 0);

  const positions: Record<string, XY> = {};
  const placed = new Set<string>();

  // ① 有邻居的漏洞：簇 + 邻居环
  const clusterColumns = Math.max(1, Math.ceil(Math.sqrt(connected.length)));
  connected.forEach((vuln, index) => {
    const center: XY = {
      x: (index % clusterColumns) * CLUSTER_GAP_X,
      y: Math.floor(index / clusterColumns) * CLUSTER_GAP_Y,
    };
    positions[vuln.id] = center;
    placed.add(vuln.id);

    const neighbours = [...(adjacency.get(vuln.id) ?? new Set<string>())]
      .filter((id) => !placed.has(id))
      .sort((left, right) => left.localeCompare(right));
    neighbours.forEach((id, order) => {
      const offset = ringOffset(order, neighbours.length);
      positions[id] = { x: center.x + offset.x, y: center.y + offset.y };
      placed.add(id);
    });
  });

  // ② 无邻居的漏洞：紧凑网格（簇下方）
  const isolatedColumns = Math.max(1, Math.ceil(Math.sqrt(isolated.length)));
  const isolatedTop =
    connected.length > 0
      ? Math.ceil(connected.length / clusterColumns) * CLUSTER_GAP_Y + CLUSTER_GAP_Y / 2
      : 0;
  isolated.forEach((vuln, index) => {
    positions[vuln.id] = {
      x: (index % isolatedColumns) * ISOLATED_GAP_X,
      y: isolatedTop + Math.floor(index / isolatedColumns) * ISOLATED_GAP_Y,
    };
    placed.add(vuln.id);
  });

  // ③ 其余孤立节点：最后一行
  const orphans = nodes
    .filter((node) => !placed.has(node.id))
    .sort((left, right) => left.id.localeCompare(right.id));
  orphans.forEach((node, index) => {
    positions[node.id] = { x: index * ISOLATED_GAP_X, y: isolatedTop + ISOLATED_GAP_Y };
  });
  return positions;
}

/** 折叠计算的结果。 */
export interface CollapseResult {
  /** 可见节点。 */
  nodes: GraphNodeDto[];
  /** 可见边（两端都可见）。 */
  edges: GraphEdgeDto[];
  /** 因折叠被隐藏的节点数。 */
  hiddenCount: number;
}

/**
 * 应用「展开 / 折叠」（纯函数）。
 *
 * 语义（对演示友好且不会把图拆散）：
 *
 * - 折叠某节点 = 隐藏它的**非漏洞**邻居；
 * - 若该邻居同时挂在另一个**未折叠**的漏洞上（共享枢纽），或它自身也被折叠，则仍然可见；
 * - 漏洞节点永不因折叠而隐藏（否则图失去中心）；
 * - 两端不都可见的边一律隐藏（React Flow 渲染前置约束）。
 *
 * @param nodes 全部节点。
 * @param edges 全部边。
 * @param collapsed 被折叠的节点 ID 集合。
 * @returns 可见节点 / 可见边 / 隐藏数量。
 */
export function applyCollapse(
  nodes: GraphNodeDto[],
  edges: GraphEdgeDto[],
  collapsed: Set<string>,
): CollapseResult {
  if (collapsed.size === 0) {
    return { nodes, edges, hiddenCount: 0 };
  }
  const adjacency = buildAdjacency(edges);
  const typeById = new Map(nodes.map((node) => [node.id, normalizeNodeType(node.type)]));

  const visible = new Set(nodes.map((node) => node.id));
  for (const id of collapsed) {
    for (const neighbour of adjacency.get(id) ?? new Set<string>()) {
      if (typeById.get(neighbour) === "vulnerability" || collapsed.has(neighbour)) {
        continue;
      }
      // 该邻居是否还挂在「未折叠的漏洞」上？是则作为共享枢纽保留
      const anchors = [...(adjacency.get(neighbour) ?? new Set<string>())].filter(
        (other) => other !== id && !collapsed.has(other),
      );
      if (!anchors.some((other) => typeById.get(other) === "vulnerability")) {
        visible.delete(neighbour);
      }
    }
  }

  const visibleNodes = nodes.filter((node) => visible.has(node.id));
  const visibleEdges = edges.filter((edge) => visible.has(edge.source) && visible.has(edge.target));
  return {
    nodes: visibleNodes,
    edges: visibleEdges,
    hiddenCount: nodes.length - visibleNodes.length,
  };
}

/**
 * 判断漏洞节点是否落在风险分区间内（纯函数）。
 *
 * 非漏洞节点一律保留（风险分只对漏洞有意义），区间为闭区间。
 *
 * @param node 节点。
 * @param range 区间 ``[min, max]``。
 * @returns 命中返回 ``true``。
 */
export function matchesRiskRange(node: GraphNodeDto, range: [number, number]): boolean {
  if (normalizeNodeType(node.type) !== "vulnerability") {
    return true;
  }
  const score = nodeRiskScore(node);
  return score >= range[0] && score <= range[1];
}
