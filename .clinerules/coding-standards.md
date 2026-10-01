# 项目规范
- 采集层、归一化层：纯传统代码，禁止 LLM
- 富化、问答层：LangGraph 多 Agent
- 所有数据模型用 Pydantic
- Python 必须有 type hints 和 docstring
- 采集器继承 BaseConnector
- 归一化函数必须是纯函数
- 禁止修改 .clineignore 排除的目录

## 环境约束
- 所有 Python 命令必须在仓库内 .venv 执行（`d:\MVP\.venv`）
- 禁止使用 `d:\venvs\` 下的任何虚拟环境
- 跑测试统一用 `python -m pytest`，禁止直接敲 `pytest`
- 装依赖统一用清华镜像：`python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ...`
## 计划书引用规则
- PROJECT_PLAN.md 只按章节引用，禁止整文件读取
- 每阶段只读对应 §5.X（文件清单）和 §6.X（验收标准）
- 需要架构时读 §1，需要接口时读 §10
## 环境约束
- 所有 Python 命令必须在仓库内 .venv 执行（d:\MVP\.venv）
- 禁止使用 d:\venvs\ 下的任何虚拟环境
- 跑测试统一用 `python -m pytest`，禁止直接敲 `pytest`
- 装依赖统一用 `python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ...`
## 提交规范
- 每天任务结束时必须 git commit
- commit message 格式：Day N: <模块>（<关键产出>）
- 禁止跨天堆积未提交改动
## 包导入规范
- 项目采用 src 布局，aisec_intel 在 src/ 下
- 已通过 `pip install -e .` 可编辑安装，任何目录都能 import
- 新增依赖后如 import 失败，先检查是否在仓库内 .venv 且已激活
- 不要用 sys.path.insert 硬编码路径
## 计划书读取硬约束
- 禁止整文件读取 PROJECT_PLAN.md
- 每个任务只读对应章节：
  - 采集任务：§5.4 + §10
  - 富化任务：§5.6 + §10
  - 问答任务：§5.7 + §10
  - 工程任务：§2 + §11
- 需要架构时只读 §1
- 需要接口时只读 §10
## 规则文件维护
- `.clinerules/plan-reference.md` 允许在 Day 任务中自动刷新行号；其他 `.clinerules/` 文件禁改
## 测试范围硬约束
必须写测试：
- 核心契约（Pydantic 模型校验）
- 纯函数算法（CVSS 计算、去重、合并）
- Agent 编排逻辑（mock LLM）
- 采集器解析逻辑（mock 响应）

不写测试：
- 简单 getter/setter/property
- 纯配置类（Settings 字段）
- 一次性脚本（scripts/ 下的一次性工具）
- UI 渲染（Streamlit 页面）
- 日志格式、异常消息文案
- 内部私有方法（除非算法复杂）