"""全局配置（来源：PROJECT_PLAN.md §11.1）。

使用 ``pydantic-settings`` 从 ``.env`` / 环境变量加载，字段名与 ``.env`` 中的大写键
大小写不敏感匹配（``llm_api_key`` ← ``LLM_API_KEY``）。

安全约定：
    - 密钥类字段统一使用 ``SecretStr``，日志与异常中不得输出明文；
      需要明文时显式调用 ``get_secret_value()``。
    - ``degraded_mode`` 打开时，自动把存储 / 向量后端切到本地降级实现（§11.1、P9.1）。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

StorageBackend = Literal["postgres", "sqlite"]
"""存储后端：PostgreSQL（默认）或 SQLite（降级）。"""

VectorBackend = Literal["chroma_persistent", "chroma_memory"]
"""向量后端：Chroma 持久化或内存模式（降级）。"""

LLMProviderName = Literal["deepseek", "qwen", "zhipu", "ollama"]
"""LLM 提供方（§3.1）。"""

OLLAMA_BASE_URL: str = "http://localhost:11434/v1"
"""Ollama OpenAI 兼容入口（§3.3）。"""

OLLAMA_MODEL_FAST: str = "qwen2.5:7b"
"""离线兜底的轻量模型。"""

OLLAMA_MODEL_SMART: str = "deepseek-r1:7b"
"""离线兜底的推理模型。"""

DEEPSEEK_BASE_URL: str = "https://api.deepseek.com/v1"
"""DeepSeek OpenAI 兼容入口默认值。"""

DEEPSEEK_MODEL_FAST: str = "deepseek-chat"
"""默认轻量模型（抽取 / 简单富化）。"""

DEEPSEEK_MODEL_SMART: str = "deepseek-reasoner"
"""默认推理模型（跨文档推理 / Reviewer）。"""

DEFAULT_SQLITE_DSN: str = "sqlite+aiosqlite:///./data/aisec.db"
"""降级模式下未显式配置 ``SQLITE_DSN`` 时使用的默认 SQLite DSN（``data/`` 仅运行时使用）。"""


class Settings(BaseSettings):
    """项目全局配置对象。

    Attributes:
        app_env: 运行环境标识（``dev`` / ``test`` / ``prod``）。
        log_level: 日志级别。
        log_json: 是否输出 JSON 结构化日志。
        log_file_path: 滚动日志文件路径（Day17 任务 3.1）。
        log_max_bytes: 单个日志文件滚动阈值（字节）。
        log_backup_count: 滚动日志保留份数。
        alert_log_path: 告警日志路径（Day17 任务 3.3）。
        self_heal_log_path: 自愈事件日志路径（Day17 任务 4）。
        alert_webhook_url: 告警 Webhook 地址（可选，留空则仅落日志）。
        degraded_mode: 降级模式开关（SQLite + 内存 Chroma + 跳过多跳推理）。
        storage_backend: 结构化存储后端。
        pg_dsn: PostgreSQL 异步 DSN。
        sqlite_dsn: 降级用 SQLite DSN。
        database_url: 显式覆盖的数据库 DSN（环境变量 ``DATABASE_URL``）。
        neo4j_uri: Neo4j Bolt 地址。
        neo4j_user: Neo4j 用户名。
        neo4j_password: Neo4j 密码（SecretStr）。
        neo4j_enabled: 是否启用图数据库（关闭时图谱降级为 PG JSON）。
        vector_backend: 向量后端。
        chroma_path: Chroma 持久化目录。
        embedding_model: 嵌入模型标识。
        embedding_backend: 嵌入后端（``auto`` / ``sentence_transformers`` / ``hashing``）。
        embedding_device: 嵌入模型推理设备。
        embedding_dim: 哈希嵌入维度（无权重降级路径）。
        embedding_query_prefix: 查询侧指令前缀覆盖值（空表示按模型名推导）。
        embedding_local_files_only: 是否只用本地模型缓存（断网演练）。
        embedding_fallback_to_hash: 本地模型不可用时是否自动降级为哈希嵌入。
        llm_provider: LLM 提供方。
        llm_base_url: OpenAI 兼容入口地址。
        llm_api_key: LLM 密钥（SecretStr）。
        llm_model_fast: 轻量模型（抽取类任务）。
        llm_model_smart: 推理模型（跨文档推理 / Reviewer）。
        llm_timeout_s: 单次调用超时（秒）。
        llm_max_retries: 结构化校验失败重试次数。
        llm_structured_method: ``with_structured_output`` 的实现方式
            （``function_calling`` / ``json_mode`` / ``json_schema``；空或 ``auto`` 自动推断 ——
            DeepSeek 不支持 ``json_schema``，思考型模型不支持 ``function_calling``）。
        llm_smart_gate: 推理模型门控开关（Day9）：``True`` 时仅 ``kev=True`` 或
            ``risk_level ∈ {high, critical}`` 的攻击链映射才使用 ``LLM_MODEL_SMART``，
            其余走 ``LLM_MODEL_FAST``（省 token、降延迟）。
        llm_fallback_enabled: LLM 降级链开关（Day17 任务 4.2）。
        enrich_daily_budget: 富化 token 日预算。
        enrich_min_confidence: 富化自动通过阈值（低于该值触发回流，§3.2 闸门④）。
        enrich_max_rounds: 富化最大回流次数（防死循环）。
        nvd_api_key: NVD API Key（SecretStr，可为空）。
        nvd_rate_limit_no_key: 无 Key 时 NVD 限流（``次数/秒``）。
        nvd_rate_limit_with_key: 有 Key 时 NVD 限流（``次数/秒``）。
        ai_package_watchlist: AI/ML 包监听清单（逗号分隔字符串）。
        github_token: GitHub Token（GHSA GraphQL 必需，SecretStr）。
        collect_default_days: 增量采集默认回看天数。
        raw_snapshot_dir: 原文快照目录（``data/`` 被 .clineignore 排除，仅运行时使用）。
        api_base_url: 前端与 API 客户端使用的服务地址。
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------- 应用 ----------
    app_env: str = "dev"
    log_level: str = "INFO"
    log_json: bool = True
    degraded_mode: bool = False

    # ---------- 可观测性（Day17 任务 3：日志聚合 / 告警落盘） ----------
    log_file_path: str = Field(
        default="logs/app.log",
        description="滚动日志文件路径（logs/ 已被 .clineignore 排除，仅运行时写入）",
    )
    log_max_bytes: int = Field(default=5_000_000, ge=1024, description="单个日志文件滚动阈值（字节）")
    log_backup_count: int = Field(default=5, ge=0, description="滚动日志保留份数")
    alert_log_path: str = Field(default="logs/alerts.log", description="告警日志路径（JSON 单行）")
    self_heal_log_path: str = Field(default="logs/selfheal.log", description="自愈事件日志路径（JSON 单行）")
    alert_webhook_url: str = Field(
        default="", description="告警 Webhook（可选，如企业微信 / 飞书机器人；留空则仅写日志）"
    )

    # ---------- PostgreSQL（可降级为 SQLite） ----------
    storage_backend: StorageBackend = "postgres"
    pg_dsn: str = "postgresql+asyncpg://aisec:aisec@localhost:5432/aisec"
    sqlite_dsn: str | None = None
    database_url: str | None = Field(
        default=None,
        description="显式指定数据库 DSN（环境变量 DATABASE_URL），优先级高于 STORAGE_BACKEND 推导",
    )

    # ---------- Neo4j ----------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("aisec_dev_pwd")
    neo4j_enabled: bool = True

    # ---------- ChromaDB ----------
    vector_backend: VectorBackend = "chroma_persistent"
    chroma_path: str = "./data/chroma"
    embedding_model: str = "BAAI/bge-small-zh-v1.5"
    embedding_backend: str = Field(
        default="auto",
        description="嵌入后端（Day10）：auto=先试本地模型、失败降级哈希 / sentence_transformers / hashing",
    )
    embedding_device: str = Field(default="cpu", description="嵌入模型推理设备（cpu / cuda）")
    embedding_dim: int = Field(default=512, ge=8, description="哈希嵌入维度（无权重降级路径 / 单测）")
    embedding_query_prefix: str = Field(
        default="",
        description="查询侧指令前缀覆盖值；留空时按 EMBEDDING_MODEL 自动推导（bge 中文系列加指令）",
    )
    embedding_local_files_only: bool = Field(default=False, description="仅使用本地模型缓存（断网演练）")
    embedding_fallback_to_hash: bool = Field(
        default=True,
        description="本地嵌入模型不可用时是否自动降级为哈希嵌入（保持链路可跑通）",
    )

    # ---------- 富化 / 图谱容量保护（Day11：修「边爆炸」） ----------
    asset_max_per_vuln: int = Field(
        default=10,
        ge=1,
        le=50,
        description="单条漏洞最多保留的受影响资产数（防组件×资产笛卡尔积把图谱撑爆）",
    )
    installed_on_max_per_component: int = Field(
        default=50,
        ge=1,
        le=500,
        description="单个组件最多连出的 INSTALLED_ON 边数（超出按 confidence 降序截断）",
    )
    component_max_per_vuln: int = Field(
        default=5,
        ge=1,
        le=50,
        description="单条漏洞最多保留的 Component 节点数（Day12 任务 1：按 confidence 降序取 top N）",
    )

    # ---------- LLM ----------
    llm_provider: LLMProviderName = "deepseek"
    llm_base_url: str = DEEPSEEK_BASE_URL
    llm_api_key: SecretStr = SecretStr("")
    llm_model_fast: str = DEEPSEEK_MODEL_FAST
    llm_model_smart: str = DEEPSEEK_MODEL_SMART
    llm_timeout_s: int = Field(default=60, gt=0, description="单次 LLM 调用超时（秒）")
    llm_max_retries: int = Field(default=2, ge=0, description="结构化校验失败重试次数")
    llm_structured_method: str | None = Field(
        default=None,
        description="结构化输出方式：function_calling / json_mode / json_schema；空或 auto 表示按模型能力自动推断",
    )
    llm_smart_gate: bool = Field(
        default=True,
        description="推理模型门控（Day9）：仅 kev=True 或 risk_level∈{high,critical} 时用 LLM_MODEL_SMART",
    )
    llm_fallback_enabled: bool = Field(
        default=True,
        description="LLM 降级链开关（Day17 任务 4.2）：失败自动降级 reasoner → chat → Ollama",
    )
    enrich_daily_budget: int = Field(default=2_000_000, ge=0, description="富化 token 日预算")
    enrich_min_confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="富化自动通过阈值")
    enrich_max_rounds: int = Field(default=2, ge=0, le=5, description="富化最大回流次数（防死循环）")

    # ---------- 采集 ----------
    nvd_api_key: SecretStr = SecretStr("")
    nvd_rate_limit_no_key: str = "5/30"
    nvd_rate_limit_with_key: str = "50/30"
    collect_default_days: int = Field(default=7, ge=1)
    raw_snapshot_dir: str = "./data/raw"

    # ---------- 采集（P3 扩展） ----------
    ai_package_watchlist: str = Field(
        default="vllm,ollama,transformers,langchain,torch",
        description="AI/ML 包监听清单（逗号分隔），供 OSV 连接器按包查询",
    )
    github_token: SecretStr = SecretStr("")
    """GitHub Token（SecretStr）：GHSA GraphQL 查询必需（未配置时该源跳过）。"""

    # ---------- 调度（分层 pipeline：采集 2h / 富化 6h / 图谱 12h / 向量 12h） ----------
    scheduler_mode: str = Field(
        default="pipeline",
        description="调度模式：pipeline=分层流水线（每层一个 job）；per_source=每源一个 job",
    )
    pipeline_collect_interval_hours: int = Field(default=2, ge=1, description="pipeline 采集层间隔（小时）")
    pipeline_enrich_interval_hours: int = Field(default=6, ge=1, description="pipeline 富化层间隔（小时）")
    pipeline_graph_interval_hours: int = Field(default=12, ge=1, description="pipeline 图谱层间隔（小时）")
    pipeline_vector_interval_hours: int = Field(default=12, ge=1, description="pipeline 向量层间隔（小时）")
    pipeline_enrich_batch_size: int = Field(
        default=50, ge=1, description="pipeline 富化层每轮条数上限（run_enrich --limit N）"
    )
    pipeline_enrich_only_high_risk: bool = Field(
        default=True,
        description="pipeline 富化层只处理高危条目（KEV 或事实层 severity∈{HIGH,CRITICAL}）",
    )

    # ---------- 服务 ----------
    api_base_url: str = "http://localhost:8000/api/v1"

    # ---------- 采集源声明式配置（P3 新增） ----------
    sources_config_path: str = Field(
        default="configs/sources.yaml",
        description="采集源配置（YAML）路径；文件不存在时按注册表默认值工作",
    )

    # ---------- LLM 派生视图（Ollama 离线兜底自动补全，§3.3） ----------

    @property
    def effective_llm_base_url(self) -> str:
        """实际使用的 LLM 入口地址。

        当 ``llm_provider="ollama"`` 且地址仍是 DeepSeek 默认值时，自动回退到本地 Ollama，
        使「现场断网只改 LLM_PROVIDER 即可」成立（§3.3）。
        """
        if self.llm_provider == "ollama" and self.llm_base_url == DEEPSEEK_BASE_URL:
            return OLLAMA_BASE_URL
        return self.llm_base_url

    @property
    def effective_llm_model_fast(self) -> str:
        """实际使用的轻量模型名（``ollama`` 且未显式配置时回退到 ``qwen2.5:7b``）。"""
        if self.llm_provider == "ollama" and self.llm_model_fast == DEEPSEEK_MODEL_FAST:
            return OLLAMA_MODEL_FAST
        return self.llm_model_fast

    @property
    def effective_llm_model_smart(self) -> str:
        """实际使用的推理模型名（``ollama`` 且未显式配置时回退到 ``deepseek-r1:7b``）。"""
        if self.llm_provider == "ollama" and self.llm_model_smart == DEEPSEEK_MODEL_SMART:
            return OLLAMA_MODEL_SMART
        return self.llm_model_smart

    # ---------- 派生视图（降级与安全检查） ----------


    @property
    def effective_storage_backend(self) -> StorageBackend:
        """实际生效的存储后端（降级模式下强制为 SQLite）。"""
        return "sqlite" if self.degraded_mode else self.storage_backend

    @property
    def effective_vector_backend(self) -> VectorBackend:
        """实际生效的向量后端（降级模式下强制为内存模式）。"""
        return "chroma_memory" if self.degraded_mode else self.vector_backend

    @property
    def effective_storage_dsn(self) -> str:
        """实际生效的存储 DSN。

        优先级：``DATABASE_URL``（显式覆盖） > 降级 SQLite > ``PG_DSN``。
        """
        if self.database_url:
            return self.database_url
        if self.effective_storage_backend == "sqlite":
            return self.sqlite_dsn or DEFAULT_SQLITE_DSN
        return self.pg_dsn

    @property
    def has_llm_api_key(self) -> bool:
        """是否已配置非空的 LLM API Key。"""
        return bool(self.llm_api_key.get_secret_value().strip())

    @property
    def has_nvd_api_key(self) -> bool:
        """是否已配置非空的 NVD API Key（未配置时按 5 req/30s 限流）。"""
        return bool(self.nvd_api_key.get_secret_value().strip())

    @property
    def has_github_token(self) -> bool:
        """是否已配置非空的 GitHub Token（GHSA 源必需）。"""
        return bool(self.github_token.get_secret_value().strip())

    @property
    def has_alert_webhook(self) -> bool:
        """是否已配置告警 Webhook（留空时告警只落 ``logs/alerts.log``）。"""
        return bool(self.alert_webhook_url.strip())

    @property
    def watchlist(self) -> list[str]:
        """AI/ML 包监听清单（把逗号分隔字符串解析为去空列表）。

        Returns:
            去重后的包名列表（保持输入顺序）。
        """
        seen: set[str] = set()
        packages: list[str] = []
        for part in self.ai_package_watchlist.split(","):
            name = part.strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                packages.append(name)
        return packages

    def masked(self) -> dict[str, object]:
        """返回可用于日志的配置快照（所有密钥替换为掩码）。

        Returns:
            键为配置项名、值为脱敏结果的字典。
        """
        return {
            "app_env": self.app_env,
            "log_level": self.log_level,
            "log_file_path": self.log_file_path,
            "alert_webhook_url": "***" if self.has_alert_webhook else "",
            "degraded_mode": self.degraded_mode,
            "storage_backend": self.effective_storage_backend,
            "vector_backend": self.effective_vector_backend,
            "embedding_model": self.embedding_model,
            "embedding_backend": self.embedding_backend,
            "neo4j_uri": self.neo4j_uri,
            "neo4j_enabled": self.neo4j_enabled,
            "neo4j_password": "***" if self.neo4j_password.get_secret_value() else "",
            "llm_provider": self.llm_provider,
            "llm_base_url": self.effective_llm_base_url,
            "llm_model_fast": self.effective_llm_model_fast,
            "llm_model_smart": self.effective_llm_model_smart,
            "llm_structured_method": self.llm_structured_method or "auto",
            "llm_smart_gate": self.llm_smart_gate,
            "llm_fallback_enabled": self.llm_fallback_enabled,
            "llm_api_key": "***" if self.has_llm_api_key else "",
            "nvd_api_key": "***" if self.has_nvd_api_key else "",
            "github_token": "***" if self.has_github_token else "",
            "watchlist": self.watchlist,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """返回进程级单例配置（首次调用时读取 ``.env`` 与环境变量）。

    Note:
        测试中如需重新读取环境变量，请先调用 ``get_settings.cache_clear()``。

    Returns:
        全局唯一的 ``Settings`` 实例。
    """
    return Settings()


class SourceConfig(BaseModel):
    """单个采集源的声明式配置（``configs/sources.yaml``）。

    Attributes:
        enabled: 是否启用该源。
        interval_minutes: 调度间隔（分钟），供 P4 调度器使用。
        rate_limit: 限流规格（``次数/窗口秒``）；NVD 实际档位由 ``RateLimiter.for_source`` 决定。
        timeout_s: 单请求超时（秒）。
        params: 源特有参数（如 OSV 的 ``watchlist``、NVD 的 ``page_size``）。
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    interval_minutes: int = Field(default=60, ge=1)
    rate_limit: str = "10/1"
    timeout_s: float = Field(default=60.0, gt=0)
    params: dict[str, Any] = Field(default_factory=dict)


SchedulerMode = Literal["pipeline", "per_source"]
"""调度器模式：``pipeline``（分层流水线）/ ``per_source``（每源一个 job）。"""

SCHEDULER_MODES: tuple[SchedulerMode, ...] = ("pipeline", "per_source")
"""可用的调度器模式（供 CLI ``--mode`` 校验）。"""

PIPELINE_STAGES: tuple[str, ...] = ("collect", "enrich", "graph", "vector")
"""分层 pipeline 的阶段顺序（采集 → 富化 → 图谱 → 向量）。"""


def normalize_scheduler_mode(value: str | None, *, default: SchedulerMode = "pipeline") -> SchedulerMode:
    """把配置 / 命令行里的调度模式字符串归一化（纯函数）。

    兼容 ``per-source`` / ``per_source`` / ``perSource`` 等写法。

    Args:
        value: 待归一化的取值；``None`` 或空串表示「未指定」。
        default: 未指定时返回的默认模式。

    Returns:
        ``"pipeline"`` 或 ``"per_source"``。

    Raises:
        ValueError: 取值无法识别为受支持的模式。
    """
    text = (value or "").strip().lower().replace("-", "_")
    if not text:
        return default
    if text == "pipeline":
        return "pipeline"
    if text in {"per_source", "persource"}:
        return "per_source"
    raise ValueError(f"未知调度模式：{value!r}（可选：{' / '.join(SCHEDULER_MODES)}，写作 per-source 亦可）")


class PipelineEnrichConfig(BaseModel):
    """``scheduler.pipeline.enrich`` 段：富化层参数。

    Attributes:
        batch_size: 每轮富化条数上限（``run_enrich --limit N``）。
        only_high_risk: 是否只富化高危条目（KEV 或事实层 ``severity∈{HIGH,CRITICAL}``）。
    """

    model_config = ConfigDict(extra="forbid")

    batch_size: int = Field(default=50, ge=1, description="每轮富化条数上限")
    only_high_risk: bool = Field(default=True, description="仅处理高危条目")


class PipelineScheduleConfig(BaseModel):
    """``scheduler.pipeline`` 段：四层流水线间隔与富化参数。

    Attributes:
        collect_interval_hours: 采集层间隔（小时）。
        enrich_interval_hours: 富化层间隔（小时）。
        graph_interval_hours: 图谱层间隔（小时）。
        vector_interval_hours: 向量层间隔（小时）。
        enrich: 富化层参数。
    """

    model_config = ConfigDict(extra="forbid")

    collect_interval_hours: int = Field(default=2, ge=1)
    enrich_interval_hours: int = Field(default=6, ge=1)
    graph_interval_hours: int = Field(default=12, ge=1)
    vector_interval_hours: int = Field(default=12, ge=1)
    enrich: PipelineEnrichConfig = Field(default_factory=PipelineEnrichConfig)


class SchedulerConfig(BaseModel):
    """``scheduler:`` 段：调度模式与分层 pipeline 配置。

    Attributes:
        mode: 调度模式（``pipeline`` / ``per-source``）。
        pipeline: 分层流水线配置。
    """

    model_config = ConfigDict(extra="forbid")

    mode: str = Field(default="pipeline", description="pipeline / per-source（per_source 亦可）")
    pipeline: PipelineScheduleConfig = Field(default_factory=PipelineScheduleConfig)


class SourcesConfig(BaseModel):
    """``configs/sources.yaml`` 的完整结构。

    Attributes:
        version: 配置版本号。
        defaults: 未显式声明字段时的默认值。
        sources: 源标识 → 源配置。
        scheduler: 调度器配置段（``scheduler:``）；未声明时为 ``None``（回退 ``Settings``）。
    """

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    defaults: SourceConfig = Field(default_factory=SourceConfig)
    sources: dict[str, SourceConfig] = Field(default_factory=dict)
    scheduler: SchedulerConfig | None = Field(
        default=None,
        description="调度器配置段；未声明时由 Settings 决定（scheduler_mode / pipeline_* 字段）",
    )

    def for_source(self, name: str) -> SourceConfig | None:
        """取某源的配置（已与 ``defaults`` 合并）。

        Args:
            name: 源标识（大小写不敏感）。

        Returns:
            源配置；未声明时返回 ``None``（调用方回退注册表默认值）。
        """
        return self.sources.get(name.strip().lower())

    @property
    def enabled_sources(self) -> list[str]:
        """返回启用中的源标识（字典序）。"""
        return sorted(name for name, cfg in self.sources.items() if cfg.enabled)


def load_sources_config(
    path: str | Path | None = None,
    *,
    settings: Settings | None = None,
) -> SourcesConfig:
    """读取并校验采集源配置。

    设计取舍：**文件缺失不报错**，返回空配置，让调用方回退到「连接器注册表默认值」，
    从而在降级/离线环境下仍可运行（§11.1 DEGRADED_MODE 思路）。

    Args:
        path: YAML 路径；``None`` 时使用 ``Settings.sources_config_path``。
        settings: 配置对象；``None`` 时使用 :func:`get_settings`。

    Returns:
        :class:`SourcesConfig`（未声明任何源时为 ``sources={}``）。

    Raises:
        ValueError: YAML 内容不是对象或校验失败（结构错误应显式暴露）。
    """
    resolved = settings or get_settings()
    target = Path(path) if path is not None else Path(resolved.sources_config_path)
    if not target.is_file():
        return SourcesConfig()
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"采集源配置必须是对象：{target}")
    parsed = SourcesConfig.model_validate(raw)
    defaults = parsed.defaults
    merged: dict[str, SourceConfig] = {}
    for name, entry in parsed.sources.items():
        overrides: dict[str, Any] = {}
        if "enabled" not in entry.model_fields_set:
            overrides["enabled"] = defaults.enabled
        if "interval_minutes" not in entry.model_fields_set:
            overrides["interval_minutes"] = defaults.interval_minutes
        if "rate_limit" not in entry.model_fields_set:
            overrides["rate_limit"] = defaults.rate_limit
        if "timeout_s" not in entry.model_fields_set:
            overrides["timeout_s"] = defaults.timeout_s
        merged[name.strip().lower()] = entry.model_copy(update=overrides)
    return SourcesConfig(
        version=parsed.version,
        defaults=defaults,
        sources=merged,
        scheduler=parsed.scheduler,
    )
