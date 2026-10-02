/**
 * 智能问答页（Day16 任务 3）。
 *
 * 能力对照：
 * - 3.1 对话界面：气泡 + 头像（用户右 / AI 左）、Enter 发送、Shift+Enter 换行、自动滚到底部；
 * - 3.2 答案展示：Markdown 主答案 + 引用卡片 + 多跳推理链时间线；
 * - 3.3 快捷问题：4 个预设问题按钮；
 * - 3.4 多轮会话：``session_id`` 存 localStorage，「新对话」按钮重置，等待期显示「AI 思考中」动画。
 */

import { Send, Sparkles, User } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import {
  CitationCard,
  QuickPrompts,
  ReasoningTimeline,
  ThinkingDots,
} from "@/components/qa/qa-parts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useQA } from "@/lib/queries";
import type { QAResponse } from "@/lib/types";
import { cn } from "@/lib/utils";

/** localStorage 键名：多轮会话 ID。 */
const SESSION_KEY = "aisec-intel-qa-session";

/** 单轮对话。 */
interface ChatTurn {
  /** 唯一键（React key）。 */
  id: string;
  /** 角色。 */
  role: "user" | "assistant";
  /** 用户文本（assistant 的失败提示也走这里）。 */
  text?: string;
  /** 结构化回答（assistant 成功时）。 */
  response?: QAResponse;
}

/**
 * 生成新的会话 ID。
 *
 * @returns 形如 ``sess-<uuid>`` 的会话 ID。
 */
function newSessionId(): string {
  const random =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `sess-${random}`;
}

/**
 * 读取（或初始化）localStorage 中的会话 ID。
 *
 * @returns 会话 ID（首次访问时生成并写入）。
 */
function readSessionId(): string {
  const existing = window.localStorage.getItem(SESSION_KEY);
  if (existing) {
    return existing;
  }
  const created = newSessionId();
  window.localStorage.setItem(SESSION_KEY, created);
  return created;
}

/**
 * AI 回答主体：Markdown + 引用卡片 + 推理链。
 *
 * @param props 结构化回答。
 * @returns 回答元素。
 */
function AssistantAnswer({ response }: { response: QAResponse }): JSX.Element {
  return (
    <div className="space-y-3">
      <Markdown content={response.answer} />

      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <Badge variant="outline" className="text-[10px]">
          置信度 {(response.confidence * 100).toFixed(0)}%
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          引用 {response.citations.length}
        </Badge>
        {response.degraded ? (
          <Badge variant="secondary" className="text-[10px]">
            降级链路（无 LLM）
          </Badge>
        ) : null}
      </div>

      {response.citations.length > 0 ? (
        <div className="grid gap-2 sm:grid-cols-2">
          {response.citations.slice(0, 8).map((citation) => (
            <CitationCard
              key={`${citation.source_type}-${citation.locator}-${citation.trace_id ?? ""}`}
              citation={citation}
            />
          ))}
        </div>
      ) : null}

      {response.reasoning_chain.length > 0 ? (
        <Card className="shadow-none">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-wide text-muted-foreground">
              推理链（{response.reasoning_chain.length} 跳）
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Separator />
            <ReasoningTimeline steps={response.reasoning_chain} />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

/**
 * 问答页组件。
 *
 * @returns 问答页元素。
 */
export function QAPage(): JSX.Element {
  const [sessionId, setSessionId] = useState<string>(() => readSessionId());
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [input, setInput] = useState("");
  const { mutate, isPending } = useQA();
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = scrollRef.current;
    if (container) {
      container.scrollTo({ top: container.scrollHeight, behavior: "smooth" });
    }
  }, [turns, isPending]);

  const history = useMemo(
    () =>
      turns.filter((turn) => turn.role === "user" && turn.text).map((turn) => turn.text as string),
    [turns],
  );

  const send = useCallback(
    (question: string) => {
      const query = question.trim();
      if (!query || isPending) {
        return;
      }
      setTurns((prev) => [...prev, { id: `${Date.now()}-u`, role: "user", text: query }]);
      setInput("");
      mutate(
        {
          query,
          session_id: sessionId,
          session_context: [...history.slice(-4), query],
          top_k: 8,
          max_hops: 2,
        },
        {
          onSuccess: (response) => {
            setTurns((prev) => [
              ...prev,
              { id: `${Date.now()}-a`, role: "assistant", response },
            ]);
          },
          onError: (error) => {
            setTurns((prev) => [
              ...prev,
              { id: `${Date.now()}-e`, role: "assistant", text: `请求失败：${error.message}` },
            ]);
          },
        },
      );
    },
    [history, isPending, mutate, sessionId],
  );

  const handleReset = useCallback(() => {
    const id = newSessionId();
    window.localStorage.setItem(SESSION_KEY, id);
    setSessionId(id);
    setTurns([]);
    toast.info("已开始新对话", { description: `会话 ID：${id.slice(0, 18)}…` });
  }, []);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        send(input);
      }
    },
    [input, send],
  );

  return (
    <div className="space-y-4">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">智能问答</h1>
          <p className="text-sm text-muted-foreground">
            LangGraph 多 Agent（Supervisor → Reasoner → Synthesizer）· 答案强制带可回溯引用
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="font-mono text-[10px]">
            会话 {sessionId.slice(0, 14)}…
          </Badge>
          <Button variant="outline" size="sm" onClick={handleReset}>
            <Sparkles className="mr-2 size-4" aria-hidden />
            新对话
          </Button>
        </div>
      </header>

      <QuickPrompts onPick={send} disabled={isPending} />

      <div className="flex flex-col rounded-xl border border-border/70 bg-card shadow-card">
        <div
          ref={scrollRef}
          className="h-[calc(100vh-24rem)] min-h-[320px] space-y-4 overflow-y-auto p-4"
          aria-live="polite"
        >
          {turns.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
              <Sparkles className="size-8" aria-hidden />
              <p className="text-sm">提问关于 CVE、资产影响、PoC 与修复的问题</p>
              <p className="text-xs">可点击上方快捷问题开始</p>
            </div>
          ) : (
            turns.map((turn) => (
              <div
                key={turn.id}
                className={cn("flex gap-3", turn.role === "user" ? "flex-row-reverse" : "flex-row")}
              >
                <span
                  className={cn(
                    "flex size-8 shrink-0 items-center justify-center rounded-full",
                    turn.role === "user"
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground",
                  )}
                  aria-hidden
                >
                  {turn.role === "user" ? (
                    <User className="size-4" />
                  ) : (
                    <Sparkles className="size-4" />
                  )}
                </span>

                <div
                  className={cn(
                    "max-w-[85%] rounded-xl px-4 py-3",
                    turn.role === "user"
                      ? "bg-primary text-primary-foreground"
                      : "border bg-background",
                  )}
                >
                  {turn.text ? <p className="whitespace-pre-wrap text-sm">{turn.text}</p> : null}
                  {turn.response ? <AssistantAnswer response={turn.response} /> : null}
                </div>
              </div>
            ))
          )}

          {isPending ? (
            <div className="flex items-center gap-3">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <Sparkles className="size-4" aria-hidden />
              </span>
              <ThinkingDots />
            </div>
          ) : null}
        </div>

        <div className="sticky bottom-0 rounded-b-xl border-t bg-background/95 p-3 backdrop-blur">
          <div className="flex items-end gap-2">
            <textarea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              placeholder="输入问题，Enter 发送，Shift+Enter 换行…"
              aria-label="问题输入框"
              className="max-h-32 min-h-[48px] flex-1 resize-y rounded-lg border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            />
            <Button
              onClick={() => send(input)}
              disabled={isPending || input.trim().length === 0}
              className="h-11"
            >
              <Send className="mr-2 size-4" aria-hidden />
              发送
            </Button>
          </div>
          <p className="mt-2 text-[11px] text-muted-foreground">
            会话 ID 保存在 localStorage，可多轮追问；「新对话」会开新的会话上下文。
          </p>
        </div>
      </div>
    </div>
  );
}

export default QAPage;
