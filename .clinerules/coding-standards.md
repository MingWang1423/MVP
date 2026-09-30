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