/**
 * 应用路由（Day14 任务 4）。
 *
 * 路由表：
 * =============================  ==========================================
 * ``/``                          首页仪表盘（本轮完整实现）
 * ``/vulnerabilities``           漏洞列表（占位）
 * ``/vulnerabilities/:cveId``    漏洞详情（占位，路由参数已通）
 * ``/qa``                        智能问答（占位）
 * ``/graph``                     知识图谱（占位）
 * ``/quality``                   数据质量（占位）
 * ``*``                          404 兜底
 * =============================  ==========================================
 */

import { Navigate, Route, Routes } from "react-router-dom";

import { Layout } from "@/components/layout";
import { PlaceholderPage } from "@/components/placeholder-page";
import { Dashboard } from "@/pages/dashboard";
import { GraphPage } from "@/pages/graph";
import { QAPage } from "@/pages/qa";
import { QualityPage } from "@/pages/quality";
import { VulnDetailPage } from "@/pages/vuln-detail";
import { VulnListPage } from "@/pages/vuln-list";

/**
 * 应用根组件（路由出口）。
 *
 * @returns 路由树。
 */
export function App(): JSX.Element {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="vulnerabilities" element={<VulnListPage />} />
        <Route path="vulnerabilities/:cveId" element={<VulnDetailPage />} />
        <Route path="qa" element={<QAPage />} />
        <Route path="graph" element={<GraphPage />} />
        <Route path="quality" element={<QualityPage />} />
        <Route path="dashboard" element={<Navigate to="/" replace />} />
        <Route
          path="*"
          element={
            <PlaceholderPage
              title="页面不存在"
              description="请检查地址是否正确，或通过顶部菜单返回首页"
              plan={["可用路径：/ 、/vulnerabilities 、/qa 、/graph 、/quality"]}
            />
          }
        />
      </Route>
    </Routes>
  );
}

export default App;
