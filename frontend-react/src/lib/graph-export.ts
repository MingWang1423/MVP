/**
 * 图谱「导出 PNG」（Day16 任务 1.3）。
 *
 * 为什么不引第三方截图库（``html-to-image`` / ``dom-to-image``）：
 * 1. 现有依赖里没有，新增依赖需评审（§11.2 关键依赖清单要同步维护）；
 * 2. DOM 截图会带上 React Flow 的网格 / 控件 / 徽标，且字体跨域时容易空白；
 * 3. 自绘 canvas 只依赖节点 / 边数据，**结果确定**、体积小、离线可用。
 *
 * 本模块只接受纯数据（不含 React / DOM），画布内容 = 白底 + 边（带关系标签与箭头）
 * + 节点（按类型着色、按风险分定大小、标签居中）。
 */

/** 导出用的节点（由调用方从 React Flow 节点拍平）。 */
export interface ExportNode {
  /** 节点 ID。 */
  id: string;
  /** 展示名。 */
  label: string;
  /** 节点类型（后端原样值）。 */
  type: string;
  /** 画布坐标 X。 */
  x: number;
  /** 画布坐标 Y。 */
  y: number;
  /** 风险分（仅漏洞节点有意义，0-100）。 */
  riskScore?: number;
}

/** 导出用的边。 */
export interface ExportEdge {
  /** 起点节点 ID。 */
  source: string;
  /** 终点节点 ID。 */
  target: string;
  /** 关系类型（``AFFECTS`` / ``EXPLOITS`` / ...）。 */
  relation: string;
}

/** 渲染参数。 */
export interface ExportCanvasOptions {
  /** 节点类型 → 颜色（十六进制字面量）。 */
  colors: Record<string, string>;
  /** 节点类型 → 中文名（写进图例）。 */
  labels: Record<string, string>;
  /** 画布标题（左上角）。 */
  title?: string;
  /** 像素密度（默认 2，导出清晰）。 */
  scale?: number;
  /** 是否绘制图例（默认 true）。 */
  legend?: boolean;
}

/** 节点尺寸与间距常量（与画布渲染保持一致，便于估算画布大小）。 */
const NODE_MIN_SIZE = 44;
const NODE_MAX_SIZE = 104;
const LABEL_PADDING = 92;
const MARGIN = 48;

/**
 * 计算节点半径（按风险分缩放，纯函数）。
 *
 * @param node 导出节点。
 * @returns 半径（像素）。
 */
export function nodeRadius(node: ExportNode): number {
  if (node.type !== "vulnerability") {
    return NODE_MIN_SIZE / 2;
  }
  const score = Math.max(0, Math.min(100, node.riskScore ?? 0));
  return (NODE_MIN_SIZE + ((NODE_MAX_SIZE - NODE_MIN_SIZE) * score) / 100) / 2;
}

/**
 * 计算画布尺寸（纯函数）。
 *
 * @param nodes 导出节点。
 * @param scale 像素密度。
 * @returns 画布宽高（含边距与标题区）。
 */
export function canvasSize(nodes: ExportNode[], scale = 1): { width: number; height: number } {
  if (nodes.length === 0) {
    return { width: 640 * scale, height: 360 * scale };
  }
  const minX = Math.min(...nodes.map((node) => node.x)) - LABEL_PADDING - MARGIN;
  const maxX = Math.max(...nodes.map((node) => node.x)) + LABEL_PADDING + MARGIN;
  const minY = Math.min(...nodes.map((node) => node.y)) - MARGIN - 24;
  const maxY = Math.max(...nodes.map((node) => node.y)) + MARGIN + 24;
  return {
    width: Math.min(6000, Math.round((maxX - minX) * scale)),
    height: Math.min(4000, Math.round((maxY - minY) * scale)),
  };
}

/**
 * 把十六进制颜色转为带透明度的 rgba（纯函数）。
 *
 * @param hex 形如 ``#d62728``。
 * @param alpha 透明度（0-1）。
 * @returns ``rgba(...)`` 字符串；``hex`` 非法时原样返回。
 */
export function hexToRgba(hex: string, alpha: number): string {
  const normalized = hex.replace("#", "");
  if (normalized.length !== 6) {
    return hex;
  }
  const value = Number.parseInt(normalized, 16);
  const red = (value >> 16) & 255;
  const green = (value >> 8) & 255;
  const blue = value & 255;
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

/**
 * 绘制圆角矩形路径。
 *
 * @param ctx 画布上下文。
 * @param x 左上角 X。
 * @param y 左上角 Y。
 * @param width 宽。
 * @param height 高。
 * @param radius 圆角半径。
 */
function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number,
): void {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + width - r, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + r);
  ctx.lineTo(x + width, y + height - r);
  ctx.quadraticCurveTo(x + width, y + height, x + width - r, y + height);
  ctx.lineTo(x + r, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

/**
 * 把图谱渲染到离屏画布（纯数据 → HTMLCanvasElement，不依赖 DOM 尺寸）。
 *
 * 绘制顺序：白底 → 边（含箭头与关系标签）→ 节点（圆 + 类型色 + 标签）→ 标题与图例。
 * 节点大小按风险分缩放（漏洞节点），其余类型固定大小。
 *
 * @param nodes 导出节点（坐标由布局函数给出）。
 * @param edges 导出边。
 * @param options 渲染参数（配色 / 标题 / 密度 / 图例）。
 * @returns 已绘制完成的画布（可直接 ``toBlob`` 下载）。
 */
export function renderGraphToCanvas(
  nodes: ExportNode[],
  edges: ExportEdge[],
  options: ExportCanvasOptions,
): HTMLCanvasElement {
  const scale = options.scale ?? 2;
  const { width, height } = canvasSize(nodes, scale);
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    return canvas;
  }

  ctx.scale(scale, scale);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, width / scale, height / scale);

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const offsetX = MARGIN + LABEL_PADDING - Math.min(...nodes.map((node) => node.x), 0);
  const offsetY = MARGIN + 24 - Math.min(...nodes.map((node) => node.y), 0);

  // ① 边（先画，避免压住节点）
  ctx.lineWidth = 1.2;
  ctx.font = "11px Inter, system-ui, sans-serif";
  for (const edge of edges) {
    const from = byId.get(edge.source);
    const to = byId.get(edge.target);
    if (!from || !to) {
      continue;
    }
    const startX = from.x + offsetX;
    const startY = from.y + offsetY;
    const endX = to.x + offsetX;
    const endY = to.y + offsetY;
    ctx.strokeStyle = "#94a3b8";
    ctx.beginPath();
    ctx.moveTo(startX, startY);
    ctx.lineTo(endX, endY);
    ctx.stroke();

    const angle = Math.atan2(endY - startY, endX - startX);
    const tipX = endX - Math.cos(angle) * (nodeRadius(to) + 6);
    const tipY = endY - Math.sin(angle) * (nodeRadius(to) + 6);
    ctx.fillStyle = "#94a3b8";
    ctx.beginPath();
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(tipX - 9 * Math.cos(angle - 0.35), tipY - 9 * Math.sin(angle - 0.35));
    ctx.lineTo(tipX - 9 * Math.cos(angle + 0.35), tipY - 9 * Math.sin(angle + 0.35));
    ctx.closePath();
    ctx.fill();

    const midX = (startX + endX) / 2;
    const midY = (startY + endY) / 2;
    const textWidth = ctx.measureText(edge.relation).width;
    ctx.fillStyle = "rgba(255, 255, 255, 0.88)";
    roundRect(ctx, midX - textWidth / 2 - 4, midY - 9, textWidth + 8, 15, 4);
    ctx.fill();
    ctx.fillStyle = "#475569";
    ctx.fillText(edge.relation, midX - textWidth / 2, midY + 2);
  }

  // ② 节点（圆 + 类型色边框 + 标签）
  ctx.textAlign = "center";
  for (const node of nodes) {
    const color = options.colors[node.type] ?? options.colors.unknown ?? "#94a3b8";
    const radius = nodeRadius(node);
    const centerX = node.x + offsetX;
    const centerY = node.y + offsetY;

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.fillStyle = hexToRgba(color, 0.16);
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = color;
    ctx.stroke();

    ctx.fillStyle = "#0f172a";
    ctx.font = `${node.type === "vulnerability" ? "bold " : ""}12px Inter, system-ui, sans-serif`;
    const label = node.label.length > 26 ? `${node.label.slice(0, 25)}…` : node.label;
    ctx.fillText(label, centerX, centerY + radius + 14);
  }
  ctx.textAlign = "left";

  // ③ 标题与图例（写在图外区域：标题在左上，图例贴底部）
  ctx.fillStyle = "#0f172a";
  ctx.font = "bold 16px Inter, system-ui, sans-serif";
  ctx.fillText(options.title ?? "知识图谱", MARGIN / 2, 30);

  if (options.legend !== false) {
    ctx.font = "12px Inter, system-ui, sans-serif";
    let cursor = MARGIN;
    const legendY = height / scale - 18;
    for (const [type, color] of Object.entries(options.colors)) {
      const label = options.labels[type] ?? type;
      ctx.beginPath();
      ctx.arc(cursor + 5, legendY - 4, 5, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.fillStyle = "#475569";
      ctx.fillText(label, cursor + 14, legendY);
      cursor += ctx.measureText(label).width + 34;
    }
  }
  return canvas;
}

/**
 * 触发浏览器下载 PNG（``toBlob`` 后立即释放对象 URL）。
 *
 * @param canvas 已绘制的画布。
 * @param filename 文件名（含扩展名）。
 */
export function downloadCanvasPng(canvas: HTMLCanvasElement, filename: string): void {
  canvas.toBlob((blob) => {
    if (!blob) {
      return;
    }
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }, "image/png");
}

/**
 * 生成导出文件名（纯函数）。
 *
 * @param mode 数据视图标识（``overview`` 或某个 CVE 编号）。
 * @param now 时间基准（默认当前时间）。
 * @returns 形如 ``aisec-graph-CVE-2024-3400-20261002-1530.png``。
 */
export function graphFileName(mode: string, now: Date = new Date()): string {
  const pad = (value: number): string => String(value).padStart(2, "0");
  const stamp =
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
    `-${pad(now.getHours())}${pad(now.getMinutes())}`;
  const safe = mode.replace(/[^0-9A-Za-z_-]/g, "_") || "overview";
  return `aisec-graph-${safe}-${stamp}.png`;
}
