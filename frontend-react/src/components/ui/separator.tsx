/**
 * shadcn/ui · Separator（官方源码等价实现，依赖 ``@radix-ui/react-separator``）。
 */

import * as SeparatorPrimitive from "@radix-ui/react-separator";
import * as React from "react";

import { cn } from "@/lib/utils";

/** 分隔线。 */
const Separator = React.forwardRef<
  React.ElementRef<typeof SeparatorPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof SeparatorPrimitive.Root>
>(({ className, orientation = "horizontal", decorative = true, ...props }, ref) => (
  <SeparatorPrimitive.Root
    ref={ref}
    decorative={decorative}
    orientation={orientation}
    className={cn(
      "shrink-0 bg-border",
      orientation === "horizontal" ? "h-[1px] w-full" : "h-full w-[1px]",
      className,
    )}
    {...props}
  />
));
Separator.displayName = SeparatorPrimitive.Root.displayName;

export { Separator };
