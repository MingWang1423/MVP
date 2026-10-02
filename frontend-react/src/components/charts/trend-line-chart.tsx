/**
 * 近 N 天披露 / 入库趋势折线图（ECharts，Day14 任务 7）。
 *
 * 口径：后端 ``timeline``（近 30 天，日期连续、缺失日补 0）。
 * 面积渐变 + 平滑曲线，X 轴只显示短日期（``MM-DD``）。
 */

import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";

import { useTheme } from "@/components/theme-provider";
import { formatCount, formatShortDate } from "@/lib/format";
import type { TimelinePoint } from "@/lib/types";

/** 组件属性。 */
export interface TrendLineChartProps {
  /** 趋势数据点（日期升序）。 */
  timeline: TimelinePoint[];
  /** 图高度（像素）。 */
  height?: number;
}

/**
 * 渲染趋势折线图。
 *
 * @param props 见 :interface:`TrendLineChartProps`。
 * @returns ECharts 元素。
 */
export function TrendLineChart({ timeline, height = 320 }: TrendLineChartProps): JSX.Element {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const option = useMemo<EChartsOption>(() => {
    const dates = timeline.map((point) => point.date);
    const counts = timeline.map((point) => point.count);

    return {
      // 关闭入场动画（理由同风险分布饼图：首屏更快、截图可复现）
      animation: false,
      textStyle: { color: isDark ? "#e2e8f0" : "#334155", fontFamily: "Inter, system-ui" },
      grid: { left: 8, right: 20, top: 24, bottom: 8, containLabel: true },
      tooltip: {
        trigger: "axis",
        formatter: (params: unknown) => {
          const list = params as { axisValue: string; value: number }[];
          const first = list[0];
          return first ? `${first.axisValue}<br/><b>${formatCount(first.value)}</b> 条` : "";
        },
      },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: dates,
        axisLabel: {
          color: isDark ? "#94a3b8" : "#64748b",
          formatter: (value: string) => formatShortDate(value),
          interval: Math.max(0, Math.floor(dates.length / 12) - 1),
        },
        axisLine: { lineStyle: { color: isDark ? "#334155" : "#e2e8f0" } },
      },
      yAxis: {
        type: "value",
        splitLine: {
          lineStyle: { color: isDark ? "rgba(148,163,184,0.18)" : "rgba(148,163,184,0.25)" },
        },
        axisLabel: { color: isDark ? "#94a3b8" : "#64748b" },
      },
      series: [
        {
          type: "line",
          name: "披露 / 入库条数",
          smooth: true,
          showSymbol: false,
          data: counts,
          lineStyle: { width: 2.5, color: "#1f77b4" },
          itemStyle: { color: "#1f77b4" },
          areaStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "rgba(31,119,180,0.35)" },
                { offset: 1, color: "rgba(31,119,180,0.02)" },
              ],
            },
          },
        },
      ],
    };
  }, [timeline, isDark]);

  return <ReactECharts option={option} style={{ height }} notMerge lazyUpdate />;
}
