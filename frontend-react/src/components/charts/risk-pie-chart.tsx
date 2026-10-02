/**
 * 风险分布饼图（ECharts，Day14 任务 7）。
 *
 * 口径：事实层 ``severity`` 分布（后端 ``risk_distribution``）；
 * 计数为 0 的等级不出现在图中，但图例顺序恒为 严重 → 高危 → 中危 → 低危 → 未定级。
 */

import type { EChartsOption } from "echarts";
import ReactECharts from "echarts-for-react";
import { useMemo } from "react";

import { useTheme } from "@/components/theme-provider";
import { LEVEL_META, LEVEL_ORDER, formatCount, toLevelKey } from "@/lib/format";

/** 组件属性。 */
export interface RiskPieChartProps {
  /** 风险分布（键为小写等级，含可选 ``unknown``）。 */
  distribution: Record<string, number>;
  /** 图高度（像素）。 */
  height?: number;
}

/**
 * 渲染风险分布环形图。
 *
 * @param props 见 :interface:`RiskPieChartProps`。
 * @returns ECharts 元素。
 */
export function RiskPieChart({ distribution, height = 320 }: RiskPieChartProps): JSX.Element {
  const { resolvedTheme } = useTheme();
  const isDark = resolvedTheme === "dark";

  const option = useMemo<EChartsOption>(() => {
    const keys = [...LEVEL_ORDER];
    const unknown = Object.keys(distribution).some((key) => toLevelKey(key) === "unknown");
    const ordered = unknown ? [...keys, "unknown" as const] : keys;
    const data = ordered
      .map((key) => ({
        name: LEVEL_META[key].label,
        value: distribution[key] ?? 0,
        itemStyle: { color: LEVEL_META[key].color },
      }))
      .filter((item) => item.value > 0);

    return {
      // 保留 ECharts 入场动画（真实用户可感知的体验优化）；
      // 截图 / 视觉回归请使用 scripts/capture-screenshot.mjs（会等待动画播完再抓帧），
      // 不要为此关闭动画。
      textStyle: { color: isDark ? "#e2e8f0" : "#334155", fontFamily: "Inter, system-ui" },
      tooltip: {
        trigger: "item",
        formatter: (params: unknown) => {
          const item = params as { name: string; value: number; percent: number };
          return `${item.name}<br/><b>${formatCount(item.value)}</b> 条（${item.percent}%）`;
        },
      },
      legend: {
        bottom: 0,
        icon: "circle",
        itemWidth: 10,
        itemHeight: 10,
        textStyle: { color: isDark ? "#cbd5e1" : "#475569" },
      },
      series: [
        {
          type: "pie",
          radius: ["48%", "72%"],
          center: ["50%", "44%"],
          avoidLabelOverlap: true,
          padAngle: 2,
          itemStyle: { borderRadius: 6, borderWidth: 2, borderColor: isDark ? "#0f172a" : "#ffffff" },
          label: {
            formatter: "{b}\n{c}",
            color: isDark ? "#e2e8f0" : "#334155",
            lineHeight: 16,
          },
          labelLine: { length: 10, length2: 10 },
          data,
        },
      ],
    };
  }, [distribution, isDark]);

  return <ReactECharts option={option} style={{ height }} notMerge lazyUpdate />;
}
