/**
 * 占位页面（Day14：除首页仪表盘外的路由先占位，P8 逐页替换为完整实现）。
 */

import { Construction } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/** 组件属性。 */
export interface PlaceholderPageProps {
  /** 页面标题。 */
  title: string;
  /** 该页职责说明。 */
  description: string;
  /** 计划落地的接口 / 数据来源。 */
  plan: string[];
  /** 额外内容（可选）。 */
  children?: ReactNode;
}

/**
 * 渲染占位页。
 *
 * @param props 见 :interface:`PlaceholderPageProps`。
 * @returns 卡片式占位内容。
 */
export function PlaceholderPage({
  title,
  description,
  plan,
  children,
}: PlaceholderPageProps): JSX.Element {
  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </header>
      <Card className="border-dashed shadow-none">
        <CardHeader className="flex-row items-center gap-3 space-y-0">
          <span className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Construction className="size-5" aria-hidden />
          </span>
          <div>
            <CardTitle className="text-base">页面开发中</CardTitle>
            <CardDescription>本轮（Day14）先完成工程化骨架与首页仪表盘，本页为占位。</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <p className="mb-2 text-sm font-medium">计划数据来源：</p>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {plan.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          {children}
        </CardContent>
      </Card>
    </div>
  );
}
