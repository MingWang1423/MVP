/**
 * 双端区间滑块（Day16 任务 1.2「风险分范围滑块」）。
 *
 * 为什么不用 ``@radix-ui/react-slider``：它不在现有依赖清单内（§11.2），
 * 而原生 ``<input type="range">`` 已能表达区间与键盘可达性；
 * 这里用两个叠放的轨道实现「双端」外观，保持零新增依赖。
 */

import * as React from "react";

import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface RangeSliderProps {
  /** 区间下限。 */
  min: number;
  /** 区间上限。 */
  max: number;
  /** 当前值 ``[low, high]``。 */
  value: [number, number];
  /** 值变化回调。 */
  onChange: (value: [number, number]) => void;
  /** 步长。 */
  step?: number;
  /** 控件无障碍标签。 */
  ariaLabel: string;
  /** 附加类名。 */
  className?: string;
}

/**
 * 渲染双端区间滑块。
 *
 * @param props 见 :interface:`RangeSliderProps`。
 * @returns 两个联动 ``range`` 输入与一条高亮轨道。
 */
export function RangeSlider({
  min,
  max,
  value,
  onChange,
  step = 1,
  ariaLabel,
  className,
}: RangeSliderProps): JSX.Element {
  const [low, high] = value;
  const span = Math.max(1, max - min);
  const leftPercent = ((low - min) / span) * 100;
  const rightPercent = ((high - min) / span) * 100;

  const handleLow = (event: React.ChangeEvent<HTMLInputElement>): void => {
    const next = Math.min(Number(event.target.value), high);
    onChange([next, high]);
  };

  const handleHigh = (event: React.ChangeEvent<HTMLInputElement>): void => {
    const next = Math.max(Number(event.target.value), low);
    onChange([low, next]);
  };

  return (
    <div className={cn("space-y-2", className)}>
      <div className="relative h-6">
        <span className="absolute top-1/2 h-1.5 w-full -translate-y-1/2 rounded-full bg-muted" />
        <span
          className="absolute top-1/2 h-1.5 -translate-y-1/2 rounded-full bg-primary/70"
          style={{ left: `${leftPercent}%`, width: `${Math.max(0, rightPercent - leftPercent)}%` }}
        />
        <input
          type="range"
          min={min}
          max={max}
          step={step}
          value={low}
          onChange={handleLow}
          aria-label={`${ariaLabel} 下限`}
          className="pointer-events-none absolute inset-0 h-6 w-full appearance-none bg-transparent [&::-webkit-slider-thumb]:pointer-events-auto [&::-webkit-slider-thumb]:size-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:border [&::-webkit-slider-thumb]:border-primary/60 [&::-webkit-slider-thumb]:bg-background [&::-webkit-slider-thumb]:shadow"
        />
        <input
          type="range"
          min={min}
          max={max}
          step={step}
          value={high}
          onChange={handleHigh}
          aria-label={`${ariaLabel} 上限`}
          className="pointer-events-none absolute inset-0 h-6 w-full appearance-none bg-transparent [&::-webkit-slider-thumb]:pointer-events-auto [&::-webkit-slider-thumb]:size-4 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:border [&::-webkit-slider-thumb]:border-primary/60 [&::-webkit-slider-thumb]:bg-background [&::-webkit-slider-thumb]:shadow"
        />
      </div>
      <div className="flex items-center justify-between text-xs tabular-nums text-muted-foreground">
        <span>{low.toFixed(0)}</span>
        <span>
          {high.toFixed(0)} / {max}
        </span>
      </div>
    </div>
  );
}
