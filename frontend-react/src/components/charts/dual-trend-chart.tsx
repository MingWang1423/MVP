/**
 * 采集 / 入库双线趋势图（ECharts，Day16 任务 2.2「30 天采集趋势折线」）。
 *
 * 两条线口径不同，刻意同图对照：
 * - **采集条数**：``raw_item.fetched_at`` 逐日分桶（今天重跑全量会集中到当天，属正常现象）；
 * - **入库 / 披露条数**：``unified_vuln`` 时间轴（``published_at`` 优先，回退 ``normalized_at``）。
 *
 * 两条线都缺失日期补 0（后端已补），故 X 轴连续、无需前端补点。
 */

import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";

import { useTheme } from "@/components/theme-provider";
import { formatCount, formatShortDate } from "@/lib/format";
import type { TimelinePoint } from "@/lib/types";

/** 组件属性。 */
export interface DualTrendChartProps {
  /** 采集趋势（``raw_item.fetched_at``）。 */
  collected: TimelinePoint[];
  /** 入库 / 披露趋势（``unified_vuln`` 时间轴）。 */
  normalized: TimelinePoint[];
  /** 图高度（像素）。 */
  height?: number;
}

/**
 * 渲染双线趋势图。
 *
 * @param props 见 :interface:`DualTrendChartProps`。
 * @returns ECharts 元素。
 */
export function DualTrendChart({
  collected,
  normalized,
  height = 320,
}: DualTrendChartProps): JSX.Element {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const option = useMemo<EChartsOption>(() => {
    const dates = (collected.length >= normalized.length ? collected : normalized).map(
      (point) => point.date,
    );
    return {
      textStyle: { color: isDark ? "#e2e8f0" : "#334155", fontFamily: "Inter, system-ui" },
      legend: {
        top: 0,
        right: 8,
        icon: "roundRect",
        itemWidth: 10,
        itemHeight: 10,
        textStyle: { color: isDark ? "#cbd5e1" : "#475569", fontSize: 11 },
      },
      grid: { left: 8, right: 20, top: 34, bottom: 8, containLabel: true },
      tooltip: {
        trigger: "axis",
        formatter: (params: unknown) => {
          const list = params as { seriesName: string; axisValue: string; value: number }[];
          const first = list[0];
          if (!first) {
            return "";
          }
          return [
            `<b>${first.axisValue}</b>`,
            ...list.map((item) => `${item.seriesName}：<b>${formatCount(item.value)}</b> 条`),
          ].join("<br/>");
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
          name: "采集条数",
          smooth: true,
          showSymbol: false,
          data: collected.map((point) => point.count),
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
        {
          type: "line",
          name: "入库 / 披露条数",
          smooth: true,
          showSymbol: false,
          data: normalized.map((point) => point.count),
          lineStyle: { width: 2.5, color: "#2ca02c", type: "dashed" },
          itemStyle: { color: "#2ca02c" },
        },
      ],
    };
  }, [collected, normalized, isDark]);

  return <ReactECharts option={option} style={{ height }} notMerge lazyUpdate />;
}
