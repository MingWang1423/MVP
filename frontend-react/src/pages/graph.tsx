/**
 * 知识图谱页占位（P8 落地：React Flow 子图交互）。
 */

import { PlaceholderPage } from "@/components/placeholder-page";

/**
 * 图谱页。
 *
 * @returns 占位页面。
 */
export function GraphPage(): JSX.Element {
  return (
    <PlaceholderPage
      title="知识图谱"
      description="CVE / CWE / 资产 / 攻击技术 / 论文多跳关联子图（React Flow 渲染）"
      plan={[
        "GET /api/v1/graph/subgraph?cve_id=&hops=（P8 新增）",
        "Neo4j 多跳查询 + 节点类型着色（复用首页设计 token）",
      ]}
    />
  );
}

export default GraphPage;
