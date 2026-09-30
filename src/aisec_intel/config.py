"""全局配置（来源：PROJECT_PLAN.md §11.1）。

使用 ``pydantic-settings`` 从 ``.env`` / 环境变量加载，字段名与 ``.env`` 中的大写键
大小写不敏感匹配（``llm_api_key`` ← ``LLM_API_KEY``）。

安全约定：
    - 密钥类字段统一使用 ``SecretStr``，日志与异常中不得输出明文；
      需要明文时显式调用 ``get_secret_value()``。
    - ``degraded_mode`` 打开时，自动把存储 / 向量后端切到本地降级实现（§11.1、P9.1）。
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
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


class Settings(BaseSettings):
    """项目全局配置对象。

    Attributes:
        app_env: 运行环境标识（``dev`` / ``test`` / ``prod``）。
        log_level: 日志级别。
        log_json: 是否输出 JSON 结构化日志。
        degraded_mode: 降级模式开关（SQLite + 内存 Chroma + 跳过多跳推理）。
        storage_backend: 结构化存储后端。
        pg_dsn: PostgreSQL 异步 DSN。
        sqlite_dsn: 降级用 SQLite DSN。
        neo4j_uri: Neo4j Bolt 地址。
        neo4j_user: Neo4j 用户名。
        neo4j_password: Neo4j 密码（SecretStr）。
        neo4j_enabled: 是否启用图数据库（关闭时图谱降级为 PG JSON）。
        vector_backend: 向量后端。
        chroma_path: Chroma 持久化目录。
        embedding_model: 嵌入模型标识。
        llm_provider: LLM 提供方。
        llm_base_url: OpenAI 兼容入口地址。
        llm_api_key: LLM 密钥（SecretStr）。
        llm_model_fast: 轻量模型（抽取类任务）。
        llm_model_smart: 推理模型（跨文档推理 / Reviewer）。
        llm_timeout_s: 单次调用超时（秒）。
        llm_max_retries: 结构化校验失败重试次数。
        enrich_daily_budget: 富化 token 日预算。
        nvd_api_key: NVD API Key（SecretStr，可为空）。
        nvd_rate_limit_no_key: 无 Key 时 NVD 限流（``次数/秒``）。
        nvd_rate_limit_with_key: 有 Key 时 NVD 限流（``次数/秒``）。
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

    # ---------- PostgreSQL（可降级为 SQLite） ----------
    storage_backend: StorageBackend = "postgres"
    pg_dsn: str = "postgresql+asyncpg://aisec:aisec@localhost:5432/aisec"
    sqlite_dsn: str | None = None

    # ---------- Neo4j ----------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = SecretStr("aisec_dev_pwd")
    neo4j_enabled: bool = True

    # ---------- ChromaDB ----------
    vector_backend: VectorBackend = "chroma_persistent"
    chroma_path: str = "./data/chroma"
    embedding_model: str = "BAAI/bge-small-zh-v1.5"

    # ---------- LLM ----------
    llm_provider: LLMProviderName = "deepseek"
    llm_base_url: str = DEEPSEEK_BASE_URL
    llm_api_key: SecretStr = SecretStr("")
    llm_model_fast: str = DEEPSEEK_MODEL_FAST
    llm_model_smart: str = DEEPSEEK_MODEL_SMART
    llm_timeout_s: int = Field(default=60, gt=0, description="单次 LLM 调用超时（秒）")
    llm_max_retries: int = Field(default=2, ge=0, description="结构化校验失败重试次数")
    enrich_daily_budget: int = Field(default=2_000_000, ge=0, description="富化 token 日预算")

    # ---------- 采集 ----------
    nvd_api_key: SecretStr = SecretStr("")
    nvd_rate_limit_no_key: str = "5/30"
    nvd_rate_limit_with_key: str = "50/30"
    collect_default_days: int = Field(default=7, ge=1)
    raw_snapshot_dir: str = "./data/raw"

    # ---------- 服务 ----------
    api_base_url: str = "http://localhost:8000/api/v1"

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
        """实际生效的存储 DSN（降级模式回退到 ``sqlite_dsn``）。"""
        if self.effective_storage_backend == "sqlite":
            return self.sqlite_dsn or "sqlite+aiosqlite:///./data/aisec.db"
        return self.pg_dsn

    @property
    def has_llm_api_key(self) -> bool:
        """是否已配置非空的 LLM API Key。"""
        return bool(self.llm_api_key.get_secret_value().strip())

    @property
    def has_nvd_api_key(self) -> bool:
        """是否已配置非空的 NVD API Key（未配置时按 5 req/30s 限流）。"""
        return bool(self.nvd_api_key.get_secret_value().strip())

    def masked(self) -> dict[str, object]:
        """返回可用于日志的配置快照（所有密钥替换为掩码）。

        Returns:
            键为配置项名、值为脱敏结果的字典。
        """
        return {
            "app_env": self.app_env,
            "log_level": self.log_level,
            "degraded_mode": self.degraded_mode,
            "storage_backend": self.effective_storage_backend,
            "vector_backend": self.effective_vector_backend,
            "neo4j_uri": self.neo4j_uri,
            "neo4j_enabled": self.neo4j_enabled,
            "neo4j_password": "***" if self.neo4j_password.get_secret_value() else "",
            "llm_provider": self.llm_provider,
            "llm_base_url": self.llm_base_url,
            "llm_model_fast": self.llm_model_fast,
            "llm_model_smart": self.llm_model_smart,
            "llm_api_key": "***" if self.has_llm_api_key else "",
            "nvd_api_key": "***" if self.has_nvd_api_key else "",
        }
