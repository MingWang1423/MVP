/**
 * 全局搜索框（Day14 任务 3）。
 *
 * 行为：
 * 1. 输入形如 ``CVE-2024-3400`` → 直接跳转漏洞详情页；
 * 2. 其他关键词 → 跳转漏洞列表页并带上 ``q`` 查询参数（列表页占位，P8 落地筛选）；
 * 3. 空输入 → 提示后不跳转。
 */

import { Search } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { Input } from "@/components/ui/input";

/** CVE 编号识别（大小写不敏感，允许 ``CVE-2024-3400`` / ``cve-2024-3400``）。 */
const CVE_PATTERN = /^cve-\d{4}-\d{4,7}$/i;

/**
 * 渲染全局搜索框。
 *
 * @returns 搜索表单元素。
 */
export function GlobalSearch(): JSX.Element {
  const [keyword, setKeyword] = useState("");
  const navigate = useNavigate();

  /**
   * 提交搜索。
   *
   * @param event 表单提交事件。
   */
  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const query = keyword.trim();
    if (!query) {
      toast.info("请输入 CVE 编号或关键词");
      return;
    }
    if (CVE_PATTERN.test(query)) {
      navigate(`/vulnerabilities/${query.toUpperCase()}`);
      return;
    }
    navigate(`/vulnerabilities?q=${encodeURIComponent(query)}`);
  }

  return (
    <form onSubmit={handleSubmit} className="relative hidden w-64 md:block" role="search">
      <Search
        className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
        aria-hidden
      />
      <Input
        value={keyword}
        onChange={(event) => setKeyword(event.target.value)}
        placeholder="搜索 CVE 编号 / 关键词…"
        aria-label="全局搜索"
        className="h-9 pl-8"
      />
    </form>
  );
}
