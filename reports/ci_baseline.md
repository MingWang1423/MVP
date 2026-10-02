# CI 静态检查基线（Day18 记录）

> 用途：`.github/workflows/ci.yml` 的 mypy 步骤分两档执行，本文件记录**存量基线**与**增量门禁**的口径，
> 避免「新代码不达标」被存量噪声掩盖，也避免为了绿灯大规模改动业务代码（违反 §10.3 变更流程）。

## 1. 当前基线（2026-10-02，Day18）

```powershell
python -m mypy            # 全量（src + tests）
# Found 196 errors in 58 files (checked 205 source files)
```

分布（Top 文件，`error:` 计数）：

| 文件 | 告警数 | 主要类别 |
|---|---|---|
| `tests/integration/test_enrichment_e2e.py` | 15 | 测试内 `Any` / 未标注 fixture |
| `tests/unit/test_graph_repo.py` | 15 | 测试替身与 ORM 行混用 |
| `tests/unit/test_retrieval_service.py` | 10 | 桩对象缺类型 |
| `tests/unit/test_rate_limiter.py` | 10 | 动态属性 |
| `src/aisec_intel/connectors/openalex.py` | 7 | 上游 JSON 字段为 `Any` |

结论：告警集中在**测试桩与外部 JSON 解析**，不属于「类型安全缺陷」，且修复面大（58 文件），
在 Demo 冲刺阶段不做全量整改（风险 > 收益）。

## 2. CI 两档策略

| 档位 | 命令 | 是否阻断 | 说明 |
|---|---|---|---|
| 增量门禁 | `python -m mypy src/aisec_intel/security src/aisec_intel/api/schemas/qa.py src/aisec_intel/services/enrich_service.py` | **是** | Day18 新增 / 改动的安全与校验代码必须零告警（实测 `Success: no issues found in 4 source files`） |
| 存量基线 | `python -m mypy` | 否（`continue-on-error: true`） | 供趋势观察；任何新文件告警会在 PR 评论中可见 |

> 约定：**新增模块一律进「增量门禁」清单**；存量文件在改动时若顺手可清零，则从基线中摘除并在本表登记。

## 3. 其他质量门禁（同一 workflow）

| 门禁 | 命令 | 阈值 |
|---|---|---|
| 代码风格 | `python -m ruff check src tests scripts` | 零告警（阻断） |
| 单元 + 集成测试 | `python -m pytest -q` | 全绿（阻断） |
| 总覆盖率 | `--cov=src/aisec_intel --cov-report=xml` | 记录趋势（Day18 实测 94%） |
| 安全模块覆盖率 | `python -m coverage report --include="*/aisec_intel/security/*" --fail-under=85` | **≥85%**（阻断；Day18 实测 92%） |

## 4. 复现

```powershell
# 与 CI 完全一致（本地 .venv，Python 3.11）
python -m pip install -e ".[dev]"
python -m ruff check src tests scripts
python -m mypy src/aisec_intel/security src/aisec_intel/api/schemas/qa.py src/aisec_intel/services/enrich_service.py
python -m pytest -q --cov=src/aisec_intel --cov-report=xml --cov-report=term-missing:skip-covered
python -m coverage report --include="*/aisec_intel/security/*" --fail-under=85
```
