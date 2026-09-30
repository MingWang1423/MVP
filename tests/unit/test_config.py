"""Day1 基础设施测试：配置加载、LLM Provider 工厂、结构化日志 trace_id。

覆盖点：
    1. ``Settings`` 默认值与环境变量覆盖（§11.1）；
    2. Ollama 离线兜底的派生配置（§3.3）与降级模式派生视图（``DEGRADED_MODE``）；
    3. 密钥脱敏（``Settings.masked`` 不泄漏明文）；
    4. ``build_provider`` 工厂行为与 API Key 缺失防护（§3.1）；
    5. ``trace_context`` 绑定与 JSON 日志输出（§1.3）。
"""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import ValidationError

from aisec_intel.config import OLLAMA_BASE_URL, OLLAMA_MODEL_FAST, OLLAMA_MODEL_SMART, Settings
from aisec_intel.llm import LLMConfigError, LLMProvider, LLMUnsupportedProviderError, build_provider
from aisec_intel.logging_config import configure_logging, get_logger, get_trace_id, trace_context
from aisec_intel.models import RawItem

PROJECT_ENV_KEYS: tuple[str, ...] = (
    "APP_ENV",
    "LOG_LEVEL",
    "LOG_JSON",
    "DEGRADED_MODE",
    "STORAGE_BACKEND",
    "PG_DSN",
    "SQLITE_DSN",
    "NEO4J_URI",
    "NEO4J_USER",
    "NEO4J_PASSWORD",
    "NEO4J_ENABLED",
    "VECTOR_BACKEND",
    "CHROMA_PATH",
    "EMBEDDING_MODEL",
    "LLM_PROVIDER",
    "LLM_BASE_URL",
    "LLM_API_KEY",
    "LLM_MODEL_FAST",
    "LLM_MODEL_SMART",
    "LLM_TIMEOUT_S",
    "LLM_MAX_RETRIES",
    "ENRICH_DAILY_BUDGET",
    "NVD_API_KEY",
    "NVD_RATE_LIMIT_NO_KEY",
    "NVD_RATE_LIMIT_WITH_KEY",
    "COLLECT_DEFAULT_DAYS",
    "RAW_SNAPSHOT_DIR",
    "API_BASE_URL",
)
"""可能与断言冲突的项目环境变量名（测试前统一清理）。"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """清空可能干扰断言的项目环境变量，保证测试确定性。"""
    for key in PROJECT_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture()
def isolated_logging() -> Iterator[None]:
    """保存并恢复根 logger 状态，避免日志测试污染其他用例。"""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    yield
    root.handlers = saved_handlers
    root.setLevel(saved_level)


def make_settings(**overrides: Any) -> Settings:
    """构造不读取 ``.env`` 的 ``Settings``（避免本机 .env 干扰断言）。"""
    return Settings(_env_file=None, **overrides)


class TestSettings:
    """``Settings`` 配置加载测试。"""

    def test_defaults(self) -> None:
        """默认值符合 §11.1 的模板。"""
        settings = make_settings()
        assert settings.app_env == "dev"
        assert settings.degraded_mode is False
        assert settings.storage_backend == "postgres"
        assert settings.vector_backend == "chroma_persistent"
        assert settings.llm_provider == "deepseek"
        assert settings.llm_base_url == "https://api.deepseek.com/v1"
        assert settings.llm_model_fast == "deepseek-chat"
        assert settings.llm_model_smart == "deepseek-reasoner"
        assert settings.has_llm_api_key is False
        assert settings.has_nvd_api_key is False
        assert settings.nvd_rate_limit_no_key == "5/30"

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """环境变量可覆盖默认值（大小写不敏感）。"""
        monkeypatch.setenv("LLM_MODEL_FAST", "qwen-plus")
        monkeypatch.setenv("DEGRADED_MODE", "true")
        monkeypatch.setenv("LLM_API_KEY", "sk-env-value")
        monkeypatch.setenv("LLM_TIMEOUT_S", "120")
        settings = make_settings()
        assert settings.llm_model_fast == "qwen-plus"
        assert settings.degraded_mode is True
        assert settings.llm_timeout_s == 120
        assert settings.has_llm_api_key is True

    def test_ollama_effective_defaults(self) -> None:
        """``LLM_PROVIDER=ollama`` 时派生配置自动指向本地 Ollama（§3.3）。"""
        settings = make_settings(llm_provider="ollama")
        assert settings.effective_llm_base_url == OLLAMA_BASE_URL
        assert settings.effective_llm_model_fast == OLLAMA_MODEL_FAST
        assert settings.effective_llm_model_smart == OLLAMA_MODEL_SMART

    def test_ollama_respects_explicit_config(self) -> None:
        """显式配置的 ollama 地址与模型不被覆盖。"""
        settings = make_settings(
            llm_provider="ollama",
            llm_base_url="http://127.0.0.1:11434/v1",
            llm_model_fast="custom:7b",
        )
        assert settings.effective_llm_base_url == "http://127.0.0.1:11434/v1"
        assert settings.effective_llm_model_fast == "custom:7b"

    def test_degraded_mode_derived_views(self) -> None:
        """降级模式切换存储与向量后端（P9.1）。"""
        settings = make_settings(degraded_mode=True)
        assert settings.effective_storage_backend == "sqlite"
        assert settings.effective_vector_backend == "chroma_memory"
        assert settings.effective_storage_dsn.startswith("sqlite+aiosqlite")

    def test_masked_hides_secrets(self) -> None:
        """``masked()`` 不泄漏任何密钥明文。"""
        settings = make_settings(llm_api_key="sk-secret-value", nvd_api_key="nvd-secret-value")
        masked = settings.masked()
        dumped = json.dumps(masked, ensure_ascii=False)
        assert masked["llm_api_key"] == "***"
        assert masked["nvd_api_key"] == "***"
        assert "sk-secret-value" not in dumped
        assert "nvd-secret-value" not in dumped
        assert masked["llm_api_key"] != settings.llm_api_key.get_secret_value()

    def test_invalid_provider_rejected(self) -> None:
        """未支持的 LLM_PROVIDER 被配置层直接拒绝。"""
        with pytest.raises(ValidationError):
            make_settings(llm_provider="openai")

    def test_invalid_timeout_rejected(self) -> None:
        """超时必须为正数。"""
        with pytest.raises(ValidationError):
            make_settings(llm_timeout_s=0)


class TestLLMProviderFactory:
    """``build_provider`` 工厂测试（§3.1）。"""

    def test_build_deepseek_provider(self) -> None:
        """默认 deepseek 配置可构建 provider，且模型分层正确。"""
        provider = build_provider(make_settings(llm_api_key="sk-test-key"))
        assert isinstance(provider, LLMProvider)  # runtime_checkable Protocol
        assert provider.name == "deepseek"
        assert provider.model_for("fast") == "deepseek-chat"
        assert provider.model_for("smart") == "deepseek-reasoner"

    def test_missing_api_key_raises_on_use(self) -> None:
        """未配置 LLM_API_KEY 时：构建不报错，真正取模型时报可操作的错误。"""
        provider = build_provider(make_settings())
        with pytest.raises(LLMConfigError, match="LLM_API_KEY"):
            provider.chat()

    def test_ollama_provider_requires_no_key(self) -> None:
        """Ollama 离线兜底无需 API Key，且模型名自动切换（§3.3）。"""
        provider = build_provider(make_settings(llm_provider="ollama"))
        assert provider.name == "ollama"
        assert provider.model_for("fast") == OLLAMA_MODEL_FAST
        assert provider.model_for("smart") == OLLAMA_MODEL_SMART

    def test_unsupported_provider_raises(self) -> None:
        """qwen / zhipu 在 Day1 为 TODO，工厂必须显式报错而不是静默降级。"""
        with pytest.raises(LLMUnsupportedProviderError, match="尚未接入"):
            build_provider(make_settings(llm_provider="qwen"))

    def test_structured_binds_schema(self) -> None:
        """``structured()`` 返回绑定 schema 的 Runnable（§3.2 闸门 ①）。"""
        pytest.importorskip("langchain_openai", reason="需要 langchain-openai 才能构造 ChatModel")
        provider = build_provider(make_settings(llm_api_key="sk-test-key"))
        bound = provider.structured(RawItem, role="smart")
        assert callable(getattr(bound, "invoke", None))


class TestLoggingTraceId:
    """结构化日志与 ``trace_id`` 上下文测试（§1.3）。"""

    def test_trace_context_binds_and_restores(self) -> None:
        """``trace_context`` 内可见 trace_id，退出后恢复。"""
        assert get_trace_id() == "-"
        with trace_context("trace-abc") as tid:
            assert tid == "trace-abc"
            assert get_trace_id() == "trace-abc"
        assert get_trace_id() == "-"

    def test_nested_context_restores_outer(self) -> None:
        """嵌套上下文退出后恢复外层 trace_id。"""
        with trace_context("outer"):
            with trace_context("inner"):
                assert get_trace_id() == "inner"
            assert get_trace_id() == "outer"

    def test_json_log_line_contains_trace_id(self, isolated_logging: None) -> None:
        """JSON 日志行包含 trace_id / level / msg 字段。"""
        buffer = io.StringIO()
        configure_logging("INFO", json_output=True, stream=buffer, force=True)
        logger = get_logger("aisec_intel.test")
        with trace_context("trace-json"):
            logger.info("采集完成")
        line = buffer.getvalue().strip().splitlines()[-1]
        payload = json.loads(line)
        assert payload["trace_id"] == "trace-json"
        assert payload["level"] == "INFO"
        assert payload["logger"] == "aisec_intel.test"
        assert payload["msg"] == "采集完成"
        assert payload["ts"].endswith("Z")

    def test_plain_text_format_is_human_readable(self, isolated_logging: None) -> None:
        """``json_output=False`` 时输出人读格式且仍带 trace_id。"""
        buffer = io.StringIO()
        configure_logging("INFO", json_output=False, stream=buffer, force=True)
        logger = get_logger("aisec_intel.test")
        with trace_context("trace-plain"):
            logger.warning("源不可用")
        assert "trace-plain" in buffer.getvalue()
        assert "源不可用" in buffer.getvalue()
