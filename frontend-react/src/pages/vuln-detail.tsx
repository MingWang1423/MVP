/**
 * 漏洞详情页占位（P8 落地：事实层 + 富化七维视图）。
 */

import { useParams } from "react-router-dom";

import { PlaceholderPage } from "@/components/placeholder-page";

/**
 * 漏洞详情页。
 *
 * @returns 占位页面（展示路由参数以验证路由生效）。
 */
export function VulnDetailPage(): JSX.Element {
  const { cveId } = useParams<{ cveId: string }>();
  return (
    <PlaceholderPage
      title={`漏洞详情 · ${cveId ?? "未指定"}`}
      description="事实层（CVSS / CPE / 引用）+ 富化层（资产 / PoC / 论文 / 攻击链 / 修复建议）"
      plan={[
        `GET /api/v1/vulnerabilities/${cveId ?? ":cveId"}（unified + enriched 双契约）`,
        "POST /api/v1/qa/ask（针对该漏洞追问）",
      ]}
    />
  );
}

export default VulnDetailPage;
