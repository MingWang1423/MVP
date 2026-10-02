/**
 * 漏洞列表页占位（P8 落地：筛选 / 分页 / 排序）。
 */

import { PlaceholderPage } from "@/components/placeholder-page";

/**
 * 漏洞列表页。
 *
 * @returns 占位页面。
 */
export function VulnListPage(): JSX.Element {
  return (
    <PlaceholderPage
      title="漏洞情报列表"
      description="按严重度 / 来源 / 时间窗筛选漏洞，支持分页与 KEV 过滤"
      plan={[
        "GET /api/v1/vulnerabilities?severity&source&days&kev_only&limit&offset",
        "GET /api/v1/stats（右上角统计条）",
      ]}
    />
  );
}

export default VulnListPage;
