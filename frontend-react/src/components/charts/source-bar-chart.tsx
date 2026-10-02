/**
 * 来源分布柱图（ECharts，Day14 任务 7）。
 *
 * 口径：后端 ``source_distribution``（各采集源贡献的漏洞条数，已按条数倒序）。
 * 采用横向条形图，源名较长时不会互相遮挡。
 */

import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";

import { useTheme } from "@/components/theme-provider";
import { CHART_PALETTE, formatCount } from "@/lib/format";

/** 组件属性。 */
export interface SourceBarChartProps {
  /** 来源分布（键为源标识）。 */
  distribution: Record<string, number>;
  /** 图高度（像素）。 */
  height?: number;
}

/**
 * 渲染来源分布横向柱图。
 *
 * @param props 见 :interface:`SourceBarChartProps`。
 * @returns ECharts 元素。
 */
export function SourceBarChart({ distribution, height = 320 }: SourceBarChartProps): JSX.Element {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const option = useMemo<EChartsOption>(() => {
    const entries = Object.entries(distribution).sort((left, right) => right[1] - left[1]);
    const names = entries.map(([key]) => key.toUpperCase());
    const values = entries.map(([, value], index) => ({
      value,
      itemStyle: { color: CHART_PALETTE[index % CHART_PALETTE.length], borderRadius: [0, 4, 4, 0] },
    }));

    return {
      // 关闭入场动画（理由同风险分布饼图：首屏更快、截图可复现）
      animation: false,
      textStyle: { color: isDark ? "#e2e8f0" : "#334155", fontFamily: "Inter, system-ui" },
      grid: { left: 8, right: 32, top: 16, bottom: 8, containLabel: true },
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        formatter: (params: unknown) => {
          const list = params as { name: string; value: number }[];
          const first = list[0];
          return first ? `${first.name}<br/><b>${formatCount(first.value)}</b> 条` : "";
        },
      },
      xAxis: {
        type: "value",
        splitLine: { lineStyle: { color: isDark ? "rgba(148,163,184,0.18)" : "rgba(148,163,184,0.25)" } },
        axisLabel: { color: isDark ? "#94a3b8" : "#64748b" },
      },
      yAxis: {
        type: "category",
        inverse: true,
        data: names,
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: isDark ? "#cbd5e1" : "#475569", fontWeight: 500 },
      },
      series: [
        {
          type: "bar",
          barWidth: 16,
          data: values,
          label: {
            show: true,
            position: "right",
            formatter: (params: unknown) => formatCount((params as { value: number }).value),
            color: isDark ? "#cbd5e1" : "#475569",
          },
        },
      ],
    };
  }, [distribution, isDark]);

  return <ReactECharts option={option} style={{ height }} notMerge lazyUpdate />;
}
