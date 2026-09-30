# 项目规范
- 采集层、归一化层：纯传统代码，禁止 LLM
- 富化、问答层：LangGraph 多 Agent
- 所有数据模型用 Pydantic
- Python 必须有 type hints 和 docstring
- 采集器继承 BaseConnector
- 归一化函数必须是纯函数
- 禁止修改 .clineignore 排除的目录
## 计划书引用规则
- PROJECT_PLAN.md 只按章节引用，禁止整文件读取
- 每阶段只读对应 §5.X（文件清单）和 §6.X（验收标准）
- 需要架构时读 §1，需要接口时读 §10