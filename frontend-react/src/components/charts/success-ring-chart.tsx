/**
 * 归一化成功率环形图（ECharts，Day16 任务 2.2）。
 *
 * 口径：后端 ``normalization_success_rate``（成功条数 / 尝试条数），
 * 中心显示百分比与「成功 / 失败」明细，环形留白保持与柱图相同的视觉密度。
 */

import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";

import { useTheme } from "@/components/theme-provider";
import { formatCount } from "@/lib/format";

/** 组件属性。 */
export interface SuccessRingChartProps {
  /** 成功率（0-1）。 */
  rate: number;
  /** 归一化成功条数。 */
  ok: number;
  /** 归一化失败条数。 */
  failed: number;
  /** 图高度（像素）。 */
  height?: number;
}

/** 成功段颜色（与设计 token 的 low 一致）。 */
const SUCCESS_COLOR = "#2ca02c";

/** 失败段颜色（与设计 token 的 critical 一致）。 */
const FAILED_COLOR = "#d62728";

/**
 * 渲染归一化成功率环形图。
 *
 * @param props 见 :interface:`SuccessRingChartProps`。
 * @returns ECharts 元素。
 */
export function SuccessRingChart({ rate, ok, failed, height = 280 }: SuccessRingChartProps): JSX.Element {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const option = useMemo<EChartsOption>(() => {
    const hasData = ok + failed > 0;
    return {
      textStyle: { color: isDark ? "#e2e8f0" : "#334155", fontFamily: "Inter, system-ui" },
      tooltip: {
        trigger: "item",
        formatter: (params: unknown) => {
          const item = params as { name: string; value: number; percent: number };
          return `${item.name}<br/><b>${formatCount(item.value)}</b> 条（${item.percent.toFixed(1)}%）`;
        },
      },
      // 中心文字（ECharts 无内建中心标签，用 graphic 定位）
      graphic: [
        {
          type: "text",
          left: "center",
          top: "45%",
          style: {
            text: hasData ? `${(rate * 100).toFixed(1)}%` : "—",
            fontSize: 26,
            fontWeight: "bold",
            fill: isDark ? "#e2e8f0" : "#0f172a",
          },
        },
        {
          type: "text",
          left: "center",
          top: "58%",
          style: {
            text: "归一化成功率",
            fontSize: 11,
            fill: isDark ? "#94a3b8" : "#64748b",
          },
        },
      ],
      series: [
        {
          type: "pie",
          radius: ["62%", "86%"],
          avoidLabelOverlap: false,
          label: { show: false },
          labelLine: { show: false },
          itemStyle: { borderWidth: 2, borderColor: isDark ? "#0f172a" : "#ffffff" },
          data: hasData
            ? [
                { value: ok, name: "归一化成功", itemStyle: { color: SUCCESS_COLOR } },
                { value: failed, name: "归一化失败", itemStyle: { color: FAILED_COLOR } },
              ]
            : [{ value: 1, name: "无数据", itemStyle: { color: isDark ? "#334155" : "#e2e8f0" } }],
        },
      ],
    };
  }, [rate, ok, failed, isDark]);

  return <ReactECharts option={option} style={{ height }} notMerge lazyUpdate />;
}
