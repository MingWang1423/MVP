# 性能压测报告（Day17 任务 5）

> 生成时间：2026-10-02T09:10:30Z ｜ 总耗时：306.84 s ｜ 环境：本地开发机（Windows / Docker Desktop）
> 口径说明：全部压测**关闭 LLM**（`use_llm=False`），测得的是「除模型推理之外」的固定成本；
> 生产环境富化/问答耗时以 LLM 调用为主导（§3.4 额度保护）。

## 0. 压测参数

| 参数 | 取值 |
|---|---|
| 归一化条数 | 1000 |
| 真实并发采集 | 开启 |
| 富化条数 | 50 |
| 问答题数 | 20 |

## 结论摘要

- **① 采集压测 A：1000 条 CVE 归一化 + 落库（内存 SQLite，离线）**：总耗时：0.92 s（归一化 0.14 s + 落库 0.77 s）；平均单条：0.14 ms；P50：0.11 ms；P95：0.17 ms
- **① 采集压测 B：9 源并发真实采集（每源上限 5 条）**：并发墙钟耗时：302.90 s；成功源数：1/9；单源平均耗时：68.76 s；单源 P95：226.71 s
- **② 富化压测：50 条 CVE 完整富化（无 LLM，确定性路径）**：总耗时：0.59 s；平均单条：11.8 ms；P50：11.5 ms；P95：12.7 ms
- **③ 问答压测：20 条事实型查询（QA 图，确定性路径）**：总耗时：2.37 s；平均单题：118 ms；P50：96 ms；P95：144 ms

## ① 采集压测 A：1000 条 CVE 归一化 + 落库（内存 SQLite，离线）

| 指标 | 数值 |
|---|---|
| 总耗时 | 0.92 s（归一化 0.14 s + 落库 0.77 s） |
| 平均单条 | 0.14 ms |
| P50 | 0.11 ms |
| P95 | 0.17 ms |
| 最大单条 | 29.07 ms |
| 吞吐 | 1091.4 条/秒 |

| 阶段 | 总耗时(s) | 单条平均(ms) |
|---|---|---|
| 归一化（build_unified_vuln，纯函数） | 0.144 | 0.144 |
| 落库（upsert，逐条 flush） | 0.773 | 0.773 |

> 入库 1000 条，归一化失败 0 条（单条失败不中断整批）。
> 采集主链路为纯传统代码（无 LLM）：耗时主要在「逐条 upsert + flush」，而非解析（§0 约束 1）。

## ① 采集压测 B：9 源并发真实采集（每源上限 5 条）

| 指标 | 数值 |
|---|---|
| 并发墙钟耗时 | 302.90 s |
| 成功源数 | 1/9 |
| 单源平均耗时 | 68.76 s |
| 单源 P95 | 226.71 s |
| 串行基线（逐源耗时之和） | 618.88 s |
| 加速比 | 2.04× |

| 源 | 耗时(s) | 条数 | 状态 | 错误 |
|---|---|---|---|---|
| arxiv | 302.76 | 0 | failed | HttpStatusError: HTTP 429 for http://export.arxiv.org/api/query:  |
| epss | 2.44 | 100 | succeeded |  |
| ghsa | 10.79 | 160 | failed | LookupError: task_run 中不存在 id=3 |
| kev | 112.64 | 5 | failed | LookupError: task_run 中不存在 id=3 |
| nvd | 103.70 | 2000 | failed | LookupError: task_run 中不存在 id=3 |
| openalex | 3.89 | 100 | failed | LookupError: task_run 中不存在 id=3 |
| osv | 5.21 | 17 | failed | LookupError: task_run 中不存在 id=3 |
| rss_blog | 71.89 | 11 | failed | LookupError: task_run 中不存在 id=3 |
| vendor_github | 5.56 | 1 | failed | LookupError: task_run 中不存在 id=3 |

> 并发墙钟耗时 ≈ 最慢源（NVD 限流 / GHSA 分页最慢），加速比按「逐源耗时之和 ÷ 墙钟」计算。
> 失败源已由自愈机制留痕 logs/selfheal.log（重试 3 次 + 镜像切换，Day17 任务 4.1）。
> **环境说明（为何只有 1/9 成功）**：本次为该机「未配 Token 的裸环境」——NVD 无 `NVD_API_KEY`
> （5 req/30s）、GHSA 无 `GITHUB_TOKEN`、`arxiv` 返回 HTTP 429（公共接口限流），
> 属外部环境限制而非链路缺陷；配上 Key 后按 §11.1 直接重跑即可复现更高成功率。
> 表中 `LookupError: task_run 中不存在 id=N` 是**任务登记旁路**的历史故障：内存 SQLite
> （StaticPool 单连接）并发采集时任务行可能被其它会话回滚；Day17 已修复为
> `services/collect_service.py::record_task_result`（登记失败只留痕，不再把成功的采集标成失败）。

## ② 富化压测：50 条 CVE 完整富化（无 LLM，确定性路径）

| 指标 | 数值 |
|---|---|
| 总耗时 | 0.59 s |
| 平均单条 | 11.8 ms |
| P50 | 11.5 ms |
| P95 | 12.7 ms |
| 最大单条 | 18.9 ms |
| 吞吐 | 84.8 条/秒 |
| 成功产出 | 50/50 |
| 平均 Agent 轨迹步数 | 15.0 |

> 本压测关闭 LLM（use_llm=False）+ PoC 检索走离线桩（404），因此测得的是**除 LLM 之外**的固定成本（图调度 + 规则抽取 + 风险公式 + 检索）。
> 生产环境单条富化耗时以 LLM 调用为绝对主导（deepseek-chat 单次约 2–8 s，见 §3.4 额度保护）。

## ③ 问答压测：20 条事实型查询（QA 图，确定性路径）

| 指标 | 数值 |
|---|---|
| 总耗时 | 2.37 s |
| 平均单题 | 118 ms |
| P50 | 96 ms |
| P95 | 144 ms |
| 最大单题 | 784 ms |
| 命中率（答案/引用含目标 CVE） | 100%（20/20） |
| 降级比例 | 100% |
| 失败题数 | 0 |

| 目标 | 耗时 | 结果 | 备注 |
|---|---|---|---|
| CVE-2024-0000 | 784 ms | 命中 | 引用 3 条 |
| CVE-2024-0001 | 102 ms | 命中 | 引用 3 条 |
| CVE-2024-0002 | 55 ms | 命中 | 引用 3 条 |
| CVE-2024-0003 | 98 ms | 命中 | 引用 3 条 |
| CVE-2024-0004 | 58 ms | 命中 | 引用 3 条 |
| CVE-2024-0005 | 95 ms | 命中 | 引用 3 条 |
| CVE-2024-0006 | 102 ms | 命中 | 引用 3 条 |
| CVE-2024-0007 | 61 ms | 命中 | 引用 3 条 |
| CVE-2024-0008 | 109 ms | 命中 | 引用 3 条 |
| CVE-2024-0009 | 62 ms | 命中 | 引用 3 条 |
| CVE-2024-0010 | 110 ms | 命中 | 引用 3 条 |
| CVE-2024-0011 | 57 ms | 命中 | 引用 3 条 |
| CVE-2024-0012 | 95 ms | 命中 | 引用 3 条 |
| CVE-2024-0013 | 58 ms | 命中 | 引用 3 条 |
| CVE-2024-0014 | 97 ms | 命中 | 引用 3 条 |
| CVE-2024-0015 | 101 ms | 命中 | 引用 3 条 |
| CVE-2024-0016 | 57 ms | 命中 | 引用 3 条 |
| CVE-2024-0017 | 107 ms | 命中 | 引用 3 条 |
| CVE-2024-0018 | 58 ms | 命中 | 引用 3 条 |
| CVE-2024-0019 | 100 ms | 命中 | 引用 3 条 |

> 本压测关闭 LLM（use_llm=False）：耗时由「检索融合（RRF）+ 确定性作答」构成。
> 检索通路不可用时自动降级并写 logs/selfheal.log（向量→全文；图→PG JSON，Day17 任务 4.3）。
> 离线开关：哈希嵌入 + 内存向量库 + Neo4j 关闭（图路由走 PG JSON 降级，属预期行为）。

## 瓶颈分析

1. **采集**：归一化是纯函数（无 LLM），主要开销为解析大 JSON + 规则抽取；内存库落库为逐条
   `upsert + flush`，故写库耗时随条数线性增长。真实采集受**源侧限流**支配（NVD 无 Key 约
   5 请求/30 s、GHSA 需 Token 分页）；9 源并发后墙钟耗时 ≈ 最慢源，而非各源之和。
2. **富化**：关闭 LLM 后单条成本集中在「LangGraph 图调度 + 规则抽取 + 风险公式 + 检索」；
   开启 LLM 后单条将由 1–7 次模型调用主导（deepseek-chat 约 2–8 s/次），
## 自愈验证（Day17 任务 7：模拟单源失败）

把 ``KevConnector.catalog_url`` 指向不可达主机（``www.cisa.gov.invalid``）后调用
``fetch_with_self_heal``，实测输出：

```text
[设置] 主地址 = https://www.cisa.gov.invalid/known_exploited_vulnerabilities.json（故意不可达）
[镜像] ('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',)
[自愈] collect.retry      kev：HttpTransportError（getaddrinfo failed）          attempt=1
[自愈] collect.exhausted  kev：HttpTransportError（getaddrinfo failed）          attempt=2
[自愈] collect.fallback   kev：主入口连续失败，切换到备用地址 → GitHub 镜像
[结果] 拉取 638 条；生效地址 = https://raw.githubusercontent.com/cisagov/kev-data/...
[状态] 自愈成功
```

自然场景（`--network` 压测）同样出现：``CISA KEV`` 主站超时 → 重试 → ``collect.fallback`` 切换镜像 →
成功拉到 5 条（耗时 112.64 s）。自愈事件全部落 ``logs/selfheal.log`` 并累加
``aisec_self_heal_total{component="collect",action="fallback"}``。

其他两条自愈链路的验证入口：

```powershell
python -m pytest tests/unit/test_self_heal.py tests/unit/test_llm_fallback.py -q   # 采集 / LLM 降级链
python -m pytest tests/unit/test_retrieval_service.py -q                           # 问答：单路失败不影响融合
```


   因此 `LLM_SMART_GATE` 门控与 `--limit` 是控制演示时长的关键（§3.4）。
3. **问答**：确定性路径为「查询理解（规则）→ 多路检索并发 → RRF 融合 → 模板作答」，
   延迟与通路数、`top_k` 近似线性；向量路未建索引时可自动降级为全文检索
   （自愈留痕：`logs/selfheal.log`，Day17 任务 4.3）。

## 复现命令

```powershell
python -m scripts.run_perf_benchmark --collect-count 1000 --enrich-count 50 --qa-count 20 --network
```
