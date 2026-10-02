/**
 * 数据质量页占位（P8 落地：数据质量报告可视化）。
 */

import { PlaceholderPage } from "@/components/placeholder-page";

/**
 * 质量页。
 *
 * @returns 占位页面。
 */
export function QualityPage(): JSX.Element {
  return (
    <PlaceholderPage
      title="数据质量"
      description="字段完整率 / 源覆盖率 / 富化五维命中率 / 引用可回溯率"
      plan={[
        "reports/data_quality.md（采集数据质量报告，Markdown 交付）",
        "GET /api/v1/tasks（P8 新增：采集与富化任务运行状态）",
      ]}
    />
  );
}

export default QualityPage;
