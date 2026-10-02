/**
 * 智能问答页占位（P8 落地：推理链 + 引用卡片 + 多轮会话）。
 */

import { PlaceholderPage } from "@/components/placeholder-page";

/**
 * 问答页。
 *
 * @returns 占位页面。
 */
export function QAPage(): JSX.Element {
  return (
    <PlaceholderPage
      title="智能问答"
      description="LangGraph 多 Agent（Supervisor → Reasoner → Synthesizer），答案强制带可回溯引用"
      plan={[
        "POST /api/v1/qa/ask（query / session_id / top_k / max_hops）",
        "GET /api/v1/qa/health（链路探活：LLM 开关 / 向量后端 / 降级模式）",
      ]}
    />
  );
}

export default QAPage;
