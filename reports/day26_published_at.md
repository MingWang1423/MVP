# Day26 报告：发布时间口径修复（`published_at` 与入库时间解耦）

> 对应 `PROJECT_PLAN.md` §12.22；证据日志：`reports/day26_backfill_full.txt`、
> `reports/day26_backfill_apply.txt`、`reports/day26_backfill_verify.txt`、
> `reports/day26_skipped_null_probe.txt`。

## 1. 问题

`unified_vuln.published_at`（以及 API 的 `VulnSummary.published_at`）会被非「源侧披露时间」的值填充：

| 位置 | 旧行为 |
|---|---|
| `api/schemas/vuln.py::VulnSummary.from_unified` | `published_at=vuln.published_at or vuln.normalized_at` → **入库时间冒充发布时间** |
| `normalize/pipeline.py::build_unified_vuln` | `modified_at = fields.modified_at or published_at`；EPSS 模型 `date` 进 `published_at` |
| `normalize/cve.py::_epss_fields` | EPSS 模型 `date` → `published_at` |

后果：源未提供发布时间的行在列表页显示成「入库当天发布」；EPSS-only 行把**模型评分日期**当披露日。

## 2. 修复后的口径（不变式）

| 字段 | 含义 | 缺失时 |
|---|---|---|
| `published_at` | **源侧**披露时间（nvd `cve.published` / kev `dateAdded` / ghsa `publishedAt` / osv `published` / vendor_github `advisory.publishedAt` / rss_blog `published`·`pubDate` …） | `None`（前端 `—`），**永不**用 `fetched_at` / `normalized_at` 顶替 |
| `modified_at` | 源侧最后修改时间（EPSS 模型 `date` 归此） | `None` |
| `normalized_at` | 入库时间，语义独立 | 必有 |

实现要点：

- 新增纯函数 `extract_published_at(raw, *, source=None)` + 助手 `lookup_field` / `_as_datetime`；
- 常量 `PUBLISHED_AT_SOURCE_PATHS`（源特有路径）、`PUBLISHED_AT_FALLBACK_PATHS`（通用回退路径）、
  `NO_PUBLISHED_AT_SOURCES = frozenset({"epss"})`；
- 解析顺序：源特有路径 → 通用回退路径 → `raw.published_at` → `None`；
- 排序 / 统计仍可走「时间轴回退」（`timeline_column()` / `list_recent_high_risk` / `count_since`），
  那是**排序口径**，不修改字段值。

## 3. 回填实测（真实 PG）

```text
[读取] raw_item=8670 条 | unified_vuln=5592 条

回填前：epss 107/107(100%) · ghsa 306/306 · kev 501/501 · nvd 4552/4552 · osv 177/177 · rss_blog 25/25 · vendor_github 11/11
--apply --null-out：[合计] updated=100 unchanged=5489 skipped-null=0 unresolved=3
  → 100 行全部为 **EPSS-only** 行（探测 `day26_skipped_null_probe.txt`：来源分布 ('epss',) -> 100；
    库内 published_at = 2026-09-23 / 09-29 等模型评分日期；库内 modified_at 非空 100/100），
    摘除后 published_at=NULL，`modified_at` 未被脚本改写（仍为库内原值）
回填后：epss 7/107(6.5%)（余 7 行与 nvd/osv 合并、披露日由它们提供）· 其余源仍 100%
复核：再次 dry-run → [合计] updated=0 unchanged=5589 skipped-null=0 unresolved=3（库 = 代码口径）
```

用法（`scripts/backfill_published_at.py`，**默认 dry-run**）：

```powershell
python -m scripts.backfill_published_at                    # 只报告
python -m scripts.backfill_published_at --apply            # 仅写非空更新
python -m scripts.backfill_published_at --apply --null-out  # 同时把「重算为空」的行置 NULL
```

## 4. 验证

| 项 | 命令 | 结果 |
|---|---|---|
| 新增回归用例 | `python -m pytest -q tests/unit/test_published_at.py` | **25 passed**（junit 明细 `classname=tests.unit.test_published_at` 计数 25，失败 0） |
| 归一化用例 | `python -m pytest -q tests/unit/test_normalize_pipeline.py tests/unit/test_normalize_cve.py` | passed（EPSS 断言改为 `published_at is None`、`modified_at == 2024-04-15`） |
| 全量回归 | `python -m pytest -q --junitxml=reports/day26_junit.xml` | **tests=1083 / failures=0 / errors=0 / skipped=0**，进程退出码 0（日志 `reports/day26_pytest_full.txt`、明细 `reports/day26_junit.xml`） |
| 静态检查 | `python -m ruff check src tests scripts migrations` | `All checks passed!`（`reports/day26_lint.txt`） |
| 前端类型 | `cd frontend-react; npm run typecheck` | `tsc --noEmit` 通过，退出码 0（`reports/day26_typecheck.txt`） |
| 库口径复核 | `python -m scripts.backfill_published_at` | updated=0（库 = 代码口径） |

## 5. 前端表现

- 列表「发布时间」：空值显示 `—`（`formatDateTime(null)`），`title` 提示「源未提供发布时间（不以入库时间替代）」；
- 详情时间线（`buildTimeline`）：新增「入库（归一化）」项；`published_at` 缺失时以推断项
  「漏洞披露 · 源未提供发布时间（不以入库时间替代）」占位；
- 仪表盘「最近高危漏洞」说明补「发布时间缺失时按入库时间排序」。

## 6. 遗留 / 注意

- 被置空的 100 行 EPSS-only 记录，库内 `modified_at` 仍是历史值 `2026-10-06`，
  而按新口径重算应为模型评分日期（`2026-09-23` / `09-29`）。本次回填**只动** `published_at`，
  未刷新 `modified_at`；若要补齐，可重跑归一化，或给脚本加 `--sync-modified`（本次未做，
  不影响 `published_at` 口径与前端展示）。
- 3 行 `unresolved` 为历史别名残留（库中主键在 `raw_item` 里找不到对应条目），保持原值不动，属预期。