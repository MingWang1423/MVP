/**
 * 字段完整率雷达图（ECharts，Day16 任务 2.2）。
 *
 * 口径：后端 ``field_completeness``（``description`` / ``cvss`` / ``cwe`` / ``references``），
 * 分母为「归一化成功条数」。四轴均以 100% 为满量程，便于一眼看出哪类字段是短板
 * （例如论文源天然没有 cvss / cwe）。
 */

import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";

import { useTheme } from "@/components/theme-provider";

/** 字段 → 中文名（雷达轴标签）。 */
const FIELD_LABELS: Record<string, string> = {
  description: "描述",
  cvss: "CVSS",
  cwe: "CWE",
  references: "参考链接",
};

/** 组件属性。 */
export interface CompletenessRadarChartProps {
  /** 字段 → 完整率（0-1）。 */
  completeness: Record<string, number>;
  /** 图高度（像素）。 */
  height?: number;
}

/**
 * 渲染字段完整率雷达图。
 *
 * @param props 见 :interface:`CompletenessRadarChartProps`。
 * @returns ECharts 元素。
 */
export function CompletenessRadarChart({
  completeness,
  height = 280,
}: CompletenessRadarChartProps): JSX.Element {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const option = useMemo<EChartsOption>(() => {
    const fields = Object.keys(FIELD_LABELS).filter((field) => field in completeness);
    const values = fields.map((field) => Number(((completeness[field] ?? 0) * 100).toFixed(1)));
    return {
      textStyle: { color: isDark ? "#e2e8f0" : "#334155", fontFamily: "Inter, system-ui" },
      tooltip: {
        trigger: "item",
        formatter: (params: unknown) => {
          const item = params as { value: number[] };
          return fields
            .map((field, index) => `${FIELD_LABELS[field]}：<b>${item.value[index]}%</b>`)
            .join("<br/>");
        },
      },
      radar: {
        indicator: fields.map((field) => ({ name: FIELD_LABELS[field], max: 100 })),
        radius: "66%",
        center: ["50%", "54%"],
        axisName: { color: isDark ? "#cbd5e1" : "#475569", fontSize: 11 },
        splitLine: { lineStyle: { color: isDark ? "rgba(148,163,184,0.25)" : "rgba(148,163,184,0.35)" } },
        splitArea: { areaStyle: { color: ["transparent"] } },
        axisLine: { lineStyle: { color: isDark ? "rgba(148,163,184,0.3)" : "rgba(148,163,184,0.4)" } },
      },
      series: [
        {
          type: "radar",
          symbolSize: 5,
          lineStyle: { width: 2, color: "#1f77b4" },
          itemStyle: { color: "#1f77b4" },
          areaStyle: { color: "rgba(31,119,180,0.25)" },
          data: [{ value: values, name: "字段完整率" }],
        },
      ],
    };
  }, [completeness, isDark]);

  return <ReactECharts option={option} style={{ height }} notMerge lazyUpdate />;
}
