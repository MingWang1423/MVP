/**
 * Markdown 渲染（Day16 任务 3.2：主答案）。
 *
 * 说明：未引入 ``@tailwindcss/typography``（新增依赖需评审，且本项目样式尽量走原子类），
 * 因此用 react-markdown 的 ``components`` 映射逐个给标题 / 段落 / 列表 / 代码 / 表格套 Tailwind 类。
 */

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** 组件属性。 */
export interface MarkdownProps {
  /** Markdown 原文（问答层 ``QAResponse.answer``）。 */
  content: string;
}

/**
 * 渲染 Markdown 正文。
 *
 * @param props 见 :interface:`MarkdownProps`。
 * @returns 已套用项目样式的 Markdown 元素。
 */
export function Markdown({ content }: MarkdownProps): JSX.Element {
  return (
    <div className="space-y-2 text-sm leading-relaxed">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="mt-3 text-base font-semibold first:mt-0">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 className="mt-3 text-[15px] font-semibold first:mt-0">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="mt-2 text-sm font-semibold first:mt-0">{children}</h3>
          ),
          p: ({ children }) => <p className="my-1.5">{children}</p>,
          ul: ({ children }) => <ul className="my-1.5 list-disc space-y-1 pl-5">{children}</ul>,
          ol: ({ children }) => <ol className="my-1.5 list-decimal space-y-1 pl-5">{children}</ol>,
          li: ({ children }) => <li className="marker:text-muted-foreground">{children}</li>,
          strong: ({ children }) => <strong className="font-semibold">{children}</strong>,
          blockquote: ({ children }) => (
            <blockquote className="my-2 border-l-2 border-primary/40 pl-3 text-muted-foreground">
              {children}
            </blockquote>
          ),
          hr: () => <hr className="my-3 border-border" />,
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer"
              className="break-all text-primary hover:underline"
            >
              {children}
            </a>
          ),
          code: ({ className, children }) => {
            const isBlock = typeof className === "string" && className.includes("language-");
            if (isBlock) {
              return (
                <code className="block overflow-x-auto rounded-lg bg-muted p-3 font-mono text-[12px]">
                  {children}
                </code>
              );
            }
            return (
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-[12px]">{children}</code>
            );
          },
          pre: ({ children }) => <pre className="my-2">{children}</pre>,
          table: ({ children }) => (
            <div className="my-2 overflow-x-auto rounded-lg border">
              <table className="w-full text-xs">{children}</table>
            </div>
          ),
          thead: ({ children }) => <thead className="bg-muted/50">{children}</thead>,
          th: ({ children }) => (
            <th className="border-b px-2 py-1.5 text-left font-medium">{children}</th>
          ),
          td: ({ children }) => <td className="border-b px-2 py-1.5 align-top">{children}</td>,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
