"""Day5 采集源声明式配置测试（PROJECT_PLAN.md §5.4 `configs/sources.yaml`）。

覆盖：真实 YAML 解析、``defaults`` 合并、缺文件降级、非法结构显式暴露、
``seed_sources.build_specs`` 的「YAML 优先 / 注册表兜底 / 未注册源停用」行为。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aisec_intel.config import Settings, SourceConfig, SourcesConfig, load_sources_config
from scripts.seed_sources import build_specs

REPO_ROOT = Path(__file__).resolve().parents[2]
REAL_YAML = REPO_ROOT / "configs" / "sources.yaml"


def make_settings(**overrides: object) -> Settings:
    """构造不读取 ``.env`` 的配置对象。"""
    return Settings(_env_file=None, **overrides)


class TestLoadRealConfig:
    """真实 ``configs/sources.yaml``。"""

    def test_declares_all_sources(self) -> None:
        """声明了 9 个源（7 个既有 + ``vendor_github`` / ``rss_blog``）且全部启用。"""
        config = load_sources_config(REAL_YAML)
        assert set(config.sources) == {
            "nvd",
            "osv",
            "ghsa",
            "kev",
            "epss",
            "arxiv",
            "openalex",
            "vendor_github",
            "rss_blog",
        }
        assert config.enabled_sources == [
            "arxiv",
            "epss",
            "ghsa",
            "kev",
            "nvd",
            "openalex",
            "osv",
            "rss_blog",
            "vendor_github",
        ]

    def test_paper_sources_use_12h_interval(self) -> None:
        """P4 新增论文源每 12 小时调度一次，并声明 query / max_results 参数。"""
        config = load_sources_config(REAL_YAML)
        arxiv = config.for_source("arxiv")
        openalex = config.for_source("openalex")
        assert arxiv is not None and openalex is not None
        assert arxiv.interval_minutes == 720
        assert openalex.interval_minutes == 720
        assert "cs.CR" in arxiv.params["query"]
        assert arxiv.params["max_results"] == 100
        assert openalex.params["search"] == "AI security"
        assert openalex.params["max_results"] == 100

    def test_nvd_and_osv_parameters(self) -> None:
        """NVD 窗口 / 分页与 OSV 监听清单被正确解析。"""
        config = load_sources_config(REAL_YAML)
        nvd = config.for_source("nvd")
        assert nvd is not None
        assert nvd.rate_limit == "5/30"
        assert nvd.params["page_size"] == 2000
        assert nvd.params["window_days"] == 120

        osv = config.for_source("OSV")  # 大小写不敏感
        assert osv is not None
        assert osv.params["ecosystem"] == "PyPI"
        assert osv.params["watchlist"] == ["vllm", "ollama", "transformers", "langchain", "torch"]

    def test_defaults_are_inherited(self) -> None:
        """未显式声明的字段继承 ``defaults``（如 kev 未写 rate_limit）。"""
        config = load_sources_config(REAL_YAML)
        kev = config.for_source("kev")
        assert kev is not None
        assert kev.rate_limit == config.defaults.rate_limit
        assert kev.timeout_s == config.defaults.timeout_s
        assert kev.enabled is True


class TestLoadEdgeCases:
    """加载边界情况。"""

    def test_missing_file_returns_empty_config(self, tmp_path: Path) -> None:
        """文件缺失不报错（降级到注册表默认值）。"""
        config = load_sources_config(tmp_path / "not-exists.yaml")
        assert config.sources == {}
        assert isinstance(config, SourcesConfig)

    def test_custom_defaults_override(self, tmp_path: Path) -> None:
        """``defaults`` 中的限流 / 超时会被未显式声明的源继承。"""
        path = tmp_path / "sources.yaml"
        path.write_text(
            "version: 1\ndefaults:\n  rate_limit: '2/1'\n  timeout_s: 12\n  interval_minutes: 30\n"
            "sources:\n  demo:\n    enabled: false\n",
            encoding="utf-8",
        )
        config = load_sources_config(path)
        demo = config.for_source("demo")
        assert demo is not None
        assert demo.rate_limit == "2/1"
        assert demo.timeout_s == 12
        assert demo.interval_minutes == 30
        assert demo.enabled is False
        assert config.enabled_sources == []

    def test_non_mapping_yaml_raises(self, tmp_path: Path) -> None:
        """YAML 顶层不是对象时显式报错。"""
        path = tmp_path / "sources.yaml"
        path.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="必须是对象"):
            load_sources_config(path)

    def test_unknown_field_rejected(self, tmp_path: Path) -> None:
        """未知字段被 ``extra=forbid`` 拒绝（配置拼写错误应立刻暴露）。"""
        path = tmp_path / "sources.yaml"
        path.write_text("sources:\n  demo:\n    enabld: true\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_sources_config(path)

    def test_settings_default_path(self) -> None:
        """``Settings.sources_config_path`` 默认指向 configs/sources.yaml。"""
        assert make_settings().sources_config_path == "configs/sources.yaml"
        assert SourceConfig().interval_minutes == 60


class TestSeedSpecs:
    """``seed_sources.build_specs`` 的装配行为。"""

    def test_registered_sources_use_yaml_values(self) -> None:
        """已注册源采用 YAML 的限流 / 超时 / 间隔，并标注 config_source。"""
        settings = make_settings()
        config = load_sources_config(REAL_YAML, settings=settings)
        specs = {spec.name: spec for spec in build_specs(settings, sources_config=config)}

        assert set(specs) == {
            "nvd",
            "osv",
            "ghsa",
            "kev",
            "epss",
            "arxiv",
            "openalex",
            "vendor_github",
            "rss_blog",
        }
        assert specs["nvd"].rate_limit == "5/30"
        assert specs["nvd"].meta["config_source"] == "sources.yaml"
        assert specs["nvd"].meta["interval_minutes"] == "120"
        assert specs["nvd"].meta["page_size"] == "2000"
        assert specs["arxiv"].meta["interval_minutes"] == "720"

    def test_unregistered_yaml_source_is_registered_disabled(self, tmp_path: Path) -> None:
        """YAML 声明但未注册的源被登记为停用（便于运维页提示待实现）。"""
        path = tmp_path / "sources.yaml"
        path.write_text("sources:\n  exploitdb:\n    enabled: true\n", encoding="utf-8")
        settings = make_settings()
        specs = {spec.name: spec for spec in build_specs(settings, sources_config=load_sources_config(path))}

        assert specs["exploitdb"].enabled is False
        assert specs["exploitdb"].connector_class == "(未注册)"
        assert specs["exploitdb"].meta["registered"] == "false"

    def test_missing_yaml_falls_back_to_registry(self) -> None:
        """YAML 缺失时全部走注册表默认值。"""
        settings = make_settings()
        specs = {spec.name: spec for spec in build_specs(settings, sources_config=SourcesConfig())}
        assert set(specs) >= {"kev", "osv", "nvd"}
        assert all(spec.meta["config_source"] == "registry-default" for spec in specs.values())

    def test_ghsa_disabled_without_token(self) -> None:
        """连接器自身不可用（无 Token）时，即使 YAML 声明启用也登记为停用。"""
        settings = make_settings(github_token="")
        config = load_sources_config(REAL_YAML, settings=settings)
        specs = {spec.name: spec for spec in build_specs(settings, sources_config=config)}
        assert specs["ghsa"].enabled is False
        assert specs["kev"].enabled is True

    def test_ghsa_enabled_with_token(self) -> None:
        """配置 Token 后 GHSA 恢复启用。"""
        settings = make_settings(github_token="ghp_unit_test")
        config = load_sources_config(REAL_YAML, settings=settings)
        specs = {spec.name: spec for spec in build_specs(settings, sources_config=config)}
        assert specs["ghsa"].enabled is True
