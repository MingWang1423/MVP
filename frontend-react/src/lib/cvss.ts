/**
 * CVSS 向量解析（纯函数，Day16 任务 2.2 基础信息 Tab 的可视化用）。
 *
 * 只做**字符串拆解**（不重算分数——分数一律用后端 ``base_score``，避免前端臆造数值）。
 */

/** 单个向量度量。 */
export interface VectorMetric {
  /** 度量简称（``AV`` / ``AC`` / ``PR`` / ``UI`` / ``S`` / ``C`` / ``I`` / ``A``）。 */
  code: string;
  /** 度量取值（``N`` / ``L`` / ``H`` 等）。 */
  value: string;
  /** 中文含义（``网络`` / ``低复杂度`` …）。 */
  label: string;
}

/** 度量代码 → 取值 → 中文含义。 */
const METRIC_LABELS: Record<string, Record<string, string>> = {
  AV: { N: "网络", A: "相邻网络", L: "本地", P: "物理" },
  AC: { L: "低复杂度", H: "高复杂度" },
  PR: { N: "无需权限", L: "低权限", H: "高权限" },
  UI: { N: "无需交互", R: "需要交互" },
  S: { U: "影响不变", C: "影响范围改变" },
  C: { H: "机密性高", L: "机密性低", N: "机密性无" },
  I: { H: "完整性高", L: "完整性低", N: "完整性无" },
  A: { H: "可用性高", L: "可用性低", N: "可用性无" },
  E: { U: "未验证", P: "概念验证", F: "功能性", H: "已武器化" },
  RL: { O: "官方修复", T: "临时修复", W: "缓解措施", U: "无" },
};

/**
 * 解析 CVSS 向量串中的各度量。
 *
 * @param vector 形如 ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`` 的向量串。
 * @returns 度量列表（无法识别的片段被忽略；空串返回空数组）。
 */
export function parseVectorMetrics(vector: string | null | undefined): VectorMetric[] {
  if (!vector) {
    return [];
  }
  return vector
    .split("/")
    .map((segment) => segment.split(":"))
    .filter((parts): parts is [string, string] => parts.length === 2)
    .filter(([code]) => code !== "CVSS")
    .map(([code, value]) => ({
      code,
      value,
      label: METRIC_LABELS[code]?.[value] ?? value,
    }));
}

/**
 * 由基础分推导 CVSS v3 定性等级（仅用于展示色阶，不覆盖后端严重度）。
 *
 * @param score 基础分（0-10）。
 * @returns ``critical`` / ``high`` / ``medium`` / ``low`` / ``none``。
 */
export function scoreToLevel(score: number): "critical" | "high" | "medium" | "low" | "none" {
  if (score >= 9) {
    return "critical";
  }
  if (score >= 7) {
    return "high";
  }
  if (score >= 4) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return "none";
}
