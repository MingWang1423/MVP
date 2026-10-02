/**
 * KPI 指标卡（Day14 任务 7）。
 *
 * 视觉参考 Snyk 控制台：左侧图标 + 标题、右侧大号数字 + 环比说明；
 * hover 抬升阴影（``shadow-card-hover``）与 Framer Motion 淡入。
 */

import { motion } from "framer-motion";
import type { LucideIcon } from "lucide-react";

import { AnimatedNumber } from "@/components/animated-number";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface KpiCardProps {
  /** 指标名称。 */
  title: string;
  /** 指标数值。 */
  value: number;
  /** 补充说明（口径 / 环比）。 */
  hint?: string;
  /** 图标组件（lucide-react）。 */
  icon: LucideIcon;
  /** 图标与强调条的颜色（默认主色）。 */
  accentColor?: string;
  /** 数值格式化（默认千分位整数）。 */
  format?: (value: number) => string;
  /** 入场动画延迟（秒），用于四卡错峰出现。 */
  delay?: number;
}

/**
 * 单个 KPI 卡片。
 *
 * @param props 见 :interface:`KpiCardProps`。
 * @returns 卡片元素。
 */
export function KpiCard({
  title,
  value,
  hint,
  icon: Icon,
  accentColor = "#1f77b4",
  format,
  delay = 0,
}: KpiCardProps): JSX.Element {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, delay }}
    >
      <Card className="group overflow-hidden border-border/70 shadow-card transition-shadow duration-300 hover:shadow-card-hover">
        <CardContent className="flex items-center justify-between gap-4 p-5">
          <div className="min-w-0 space-y-1">
            <p className="truncate text-sm font-medium text-muted-foreground">{title}</p>
            <p className="text-3xl font-semibold tracking-tight tabular-nums">
              <AnimatedNumber value={value} format={format} />
            </p>
            {hint ? <p className="truncate text-xs text-muted-foreground">{hint}</p> : null}
          </div>
          <span
            className={cn(
              "flex size-12 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 group-hover:scale-105",
            )}
            style={{ backgroundColor: `${accentColor}1a`, color: accentColor }}
          >
            <Icon className="size-6" aria-hidden />
          </span>
        </CardContent>
      </Card>
    </motion.div>
  );
}
