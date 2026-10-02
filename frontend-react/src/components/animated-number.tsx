/**
 * 数字滚动动画组件（Day14 任务 7：KPI 卡片）。
 *
 * 使用 Framer Motion 的 ``animate`` 驱动 ``MotionValue``，避免逐帧 setState；
 * 数值变化时自动从当前值滚动到目标值。
 */

import { animate, motion, useMotionValue, useTransform } from "framer-motion";
import { useEffect } from "react";

/** 组件属性。 */
export interface AnimatedNumberProps {
  /** 目标数值。 */
  value: number;
  /** 动画时长（秒）。 */
  duration?: number;
  /** 自定义格式化（默认千分位）。 */
  format?: (value: number) => string;
  /** 附加类名。 */
  className?: string;
}

/**
 * 从 0（或上一次的值）滚动到目标值的数字。
 *
 * @param props 见 :interface:`AnimatedNumberProps`。
 * @returns 带动画的 ``<span>``。
 */
export function AnimatedNumber({
  value,
  duration = 1.1,
  format = (input: number) => new Intl.NumberFormat("zh-CN").format(Math.round(input)),
  className,
}: AnimatedNumberProps): JSX.Element {
  const motionValue = useMotionValue(0);
  const text = useTransform(motionValue, (latest: number) => format(latest));

  useEffect(() => {
    const controls = animate(motionValue, value, { duration, ease: "easeOut" });
    return () => controls.stop();
  }, [duration, motionValue, value]);

  return (
    <motion.span className={className} aria-label={format(value)}>
      {text}
    </motion.span>
  );
}
