/**
 * 漏洞列表筛选栏（Day16 任务 1.1，参考 Dependabot 布局）。
 *
 * 全部筛选状态由父组件持有并同步到 URL（见 ``lib/vuln-filters.ts``）；
 * 本组件只负责渲染与回调，不自己存筛选状态（搜索框除外——它需要输入中间态）。
 */

import { Filter, RotateCcw, Search, SlidersHorizontal } from "lucide-react";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { LEVEL_META, formatCount, toLevelKey } from "@/lib/format";
import {
  SEVERITY_OPTIONS,
  SOURCE_OPTIONS,
  TIME_RANGES,
  hasActiveFilters,
  type TimeRangeKey,
  type VulnListFilters,
} from "@/lib/vuln-filters";
import { cn } from "@/lib/utils";

/** 组件属性。 */
export interface FilterBarProps {
  /** 当前筛选状态。 */
  filters: VulnListFilters;
  /** 变更筛选（未列出的字段保持不变；页码会自动回到第 1 页）。 */
  onChange: (patch: Partial<VulnListFilters>) => void;
  /** 重置全部筛选。 */
  onReset: () => void;
  /** 命中总数（用于展示）。 */
  total?: number;
  /** 是否正在加载。 */
  loading?: boolean;
}

/** 搜索输入防抖时长（毫秒）。 */
const SEARCH_DEBOUNCE_MS = 400;

/** 多选项切换（纯函数）：存在则移除，否则追加。 */
function toggleItem<T>(items: T[], item: T): T[] {
  return items.includes(item) ? items.filter((entry) => entry !== item) : [...items, item];
}

/**
 * 多选筛选按钮。
 *
 * @param props 标题 / 选项 / 已选项 / 渲染函数 / 变更回调。
 * @returns 下拉多选按钮。
 */
function MultiSelect<T extends string>({
  label,
  options,
  selected,
  onToggle,
  renderOption,
}: {
  label: string;
  options: readonly T[];
  selected: readonly T[];
  onToggle: (value: T) => void;
  renderOption?: (value: T) => JSX.Element;
}): JSX.Element {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-9 gap-2">
          <Filter className="size-4" aria-hidden />
          {label}
          {selected.length > 0 ? (
            <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[11px]">
              {selected.length}
            </Badge>
          ) : null}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-48">
        <DropdownMenuLabel>{label}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {options.map((option) => (
          <DropdownMenuCheckboxItem
            key={option}
            checked={selected.includes(option)}
            onSelect={(event) => {
              event.preventDefault();
              onToggle(option);
            }}
          >
            {renderOption ? renderOption(option) : option}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/**
 * 筛选栏主体。
 *
 * @param props 见 :interface:`FilterBarProps`。
 * @returns 筛选栏元素。
 */
export function FilterBar({
  filters,
  onChange,
  onReset,
  total,
  loading,
}: FilterBarProps): JSX.Element {
  const [keyword, setKeyword] = useState(filters.q);

  useEffect(() => {
    setKeyword(filters.q);
  }, [filters.q]);

  useEffect(() => {
    if (keyword === filters.q) {
      return undefined;
    }
    const timer = window.setTimeout(() => onChange({ q: keyword, page: 1 }), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [keyword, filters.q, onChange]);

  return (
    <div className="space-y-3 rounded-xl border border-border/70 bg-card p-4 shadow-card">
      <div className="flex flex-wrap items-center gap-2">
        <SlidersHorizontal className="size-4 text-muted-foreground" aria-hidden />
        <span className="text-sm font-medium">筛选</span>

        <MultiSelect
          label="严重度"
          options={SEVERITY_OPTIONS}
          selected={filters.severities}
          onToggle={(value) =>
            onChange({ severities: toggleItem(filters.severities, value), page: 1 })
          }
          renderOption={(value) => {
            const meta = LEVEL_META[toLevelKey(value)];
            return (
              <span className="flex items-center gap-2">
                <span
                  className="size-2.5 rounded-full"
                  style={{ backgroundColor: meta.color }}
                  aria-hidden
                />
                {meta.label}
                <span className="text-xs text-muted-foreground">{value}</span>
              </span>
            );
          }}
        />

        <MultiSelect
          label="来源"
          options={SOURCE_OPTIONS}
          selected={filters.sources}
          onToggle={(value) => onChange({ sources: toggleItem(filters.sources, value), page: 1 })}
          renderOption={(value) => <span className="uppercase">{value}</span>}
        />

        <div
          className="flex items-center rounded-lg border border-border p-0.5"
          role="group"
          aria-label="时间范围"
        >
          {TIME_RANGES.map((range) => (
            <button
              key={range.key}
              type="button"
              onClick={() => onChange({ range: range.key as TimeRangeKey, page: 1 })}
              className={cn(
                "rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors",
                filters.range === range.key
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )}
              aria-pressed={filters.range === range.key}
            >
              {range.label}
            </button>
          ))}
        </div>

        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={filters.kev}
            onCheckedChange={(checked) => onChange({ kev: checked, page: 1 })}
            aria-label="仅 KEV"
          />
          仅 KEV
        </label>

        <label className="flex items-center gap-2 text-sm">
          <Switch
            checked={filters.hasPoc}
            onCheckedChange={(checked) => onChange({ hasPoc: checked, page: 1 })}
            aria-label="仅有 PoC"
          />
          有 PoC
        </label>

        <div className="relative ml-auto w-full sm:w-64">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            placeholder="搜索 CVE 编号 / 关键词…"
            aria-label="搜索漏洞"
            className="h-9 pl-8"
          />
        </div>

        <Button
          variant="ghost"
          size="sm"
          className="h-9"
          onClick={onReset}
          disabled={!hasActiveFilters(filters)}
        >
          <RotateCcw className="mr-2 size-4" aria-hidden />
          重置
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>
          命中 <span className="font-medium text-foreground">{formatCount(total ?? 0)}</span> 条
        </span>
        {filters.severities.length > 0 ? (
          <span>严重度：{filters.severities.join(" / ")}</span>
        ) : null}
        {filters.sources.length > 0 ? <span>来源：{filters.sources.join(" / ")}</span> : null}
        {filters.kev ? <span>仅 KEV</span> : null}
        {filters.hasPoc ? <span>仅有 PoC</span> : null}
        {filters.q ? <span>关键词：{filters.q}</span> : null}
        {loading ? <span className="text-primary">加载中…</span> : null}
      </div>
    </div>
  );
}
