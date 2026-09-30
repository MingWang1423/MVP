"""Day6 数据质量报告测试（PROJECT_PLAN.md §5.5 P4 任务 3）。

覆盖：单源指标计算（含归一化失败计数）、Markdown 渲染、SQLite 内存库读取与 CLI 落盘。
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from aisec_intel.config import Settings
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.storage.database import session_scope
from aisec_intel.storage.repositories.raw_repo import RawRepository
from aisec_intel.utils.hashing import sha256_text
from scripts.data_quality import (
    FIELD_NAMES,
    SourceQuality,
    collect_raw_items,
    evaluate_all,
    evaluate_source,
    parse_args,
    render_markdown,
    run,
)

NVD_FULL: dict[str, Any] = {
    "cve": {
        "id": "CVE-2024-3400",
        "published": "2024-04-12T00:00:00.000Z",
        "lastModified": "2024-04-20T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "PAN-OS command injection in GlobalProtect."}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-77"}]}],
        "references": [{"url": "https://example.org/advisory"}],
    }
}

NVD_MINIMAL: dict[str, Any] = {
    "cve": {
        "id": "CVE-2024-1111",
        "published": "2024-05-01T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "Minimal record without CVSS/CWE."}],
    }
}

KEV_ENTRY: dict[str, Any] = {
    "cveID": "CVE-2024-3400",
    "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection",
    "shortDescription": "PAN-OS command injection vulnerability.",
    "dateAdded": "2024-04-12",
    "cwes": ["CWE-77"],
}


def make_raw(source: str, source_id: str, payload: dict[str, Any]) -> RawItem:
    """构造一条 ``RawItem``（内容与指纹自洽）。"""
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return RawItem(
        trace_id=new_trace_id(),
        source=source,
        source_id=source_id,
        url=f"https://example.org/{source}/{source_id}",
        title=None,
        raw_text=text,
        lang="en",
        published_at=datetime(2024, 5, 1, tzinfo=UTC),
        fetched_at=utc_now(),
        sha256=sha256_text(text),
        meta={},
    )


class TestEvaluateSource:
    """单源指标计算（纯函数）。"""

    def test_counts_and_completeness(self) -> None:
        """归一化成功率与四字段完整率按条数计算。"""
        items = [
            make_raw("nvd", "CVE-2024-3400", NVD_FULL),
            make_raw("nvd", "CVE-2024-1111", NVD_MINIMAL),
        ]
        quality = evaluate_source("nvd", items)
        assert quality.kind == "vuln"
        assert quality.raw_count == 2
        assert quality.normalized_ok == 2
        assert quality.normalized_failed == 0
        assert quality.success_rate == 1.0
        assert quality.completeness("description") == 1.0
        assert quality.completeness("cvss") == 0.5
        assert quality.completeness("cwe") == 0.5
        # references 兜底为 RawItem.url（L2 行为），故恒为 100%
        assert quality.completeness("references") == 1.0

    def test_paper_source_is_marked(self) -> None:
        """论文源被标记为 ``paper`` 类型（报告脚注据此解释 cvss/cwe 缺失）。"""
        quality = evaluate_source("arxiv", [])
        assert quality.kind == "paper"
        assert quality.raw_count == 0
        assert quality.success_rate == 0.0
        assert quality.completeness("description") == 0.0

    def test_failed_normalization_is_counted(self) -> None:
        """无法确定主键的条目计入归一化失败，且不影响其它条目统计。"""
        broken = SimpleNamespace(
            trace_id="t-broken",
            source="nvd",
            source_id="",
            url="",
            title=None,
            raw_text='{"cve": {"id": ""}}',
            lang=None,
            published_at=None,
        )
        quality = evaluate_source("nvd", [make_raw("kev", "CVE-2024-3400", KEV_ENTRY), broken])  # type: ignore[list-item]
        assert quality.raw_count == 2
        assert quality.normalized_ok == 1
        assert quality.normalized_failed == 1
        assert quality.success_rate == 0.5


class TestEvaluateAll:
    """多源评估（含零数据源）。"""

    def test_zero_data_sources_are_kept(self) -> None:
        """没有数据的源仍出现在结果中（暴露采集缺口）。"""
        grouped = {"kev": [make_raw("kev", "CVE-2024-3400", KEV_ENTRY)]}
        qualities = evaluate_all(grouped, sources=["kev", "ghsa", "arxiv"])
        assert [item.source for item in qualities] == ["arxiv", "ghsa", "kev"]
        assert {item.source: item.raw_count for item in qualities} == {"arxiv": 0, "ghsa": 0, "kev": 1}


class TestRenderMarkdown:
    """Markdown 渲染（纯函数，便于离线校验）。"""

    def make_qualities(self) -> list[SourceQuality]:
        """构造两条指标（一条有数据、一条无数据）。"""
        return [
            SourceQuality(
                source="kev",
                kind="vuln",
                raw_count=10,
                normalized_ok=10,
                normalized_failed=0,
                field_complete={"description": 10, "cvss": 5, "cwe": 5, "references": 10},
            ),
            SourceQuality(source="ghsa", kind="vuln", raw_count=0, normalized_ok=0, normalized_failed=0),
        ]

    def test_tables_and_totals(self) -> None:
        """报告含两张表格与合计行，数字口径正确。"""
        markdown = render_markdown(
            self.make_qualities(),
            declared=["kev", "ghsa"],
            since=datetime(2024, 1, 1, tzinfo=UTC),
            generated_at=datetime(2026, 9, 30, 6, 0, tzinfo=UTC),
        )
        assert "# 采集数据质量报告（P4）" in markdown
        assert "- 生成时间：2026-09-30T06:00:00Z" in markdown
        assert "since=2024-01-01T00:00:00Z" in markdown
        assert "| kev | 漏洞 | 10 | 10 | 0 | 100.0% |" in markdown
        assert "| **合计** | — | 10 | 10 | 0 | — |" in markdown
        assert "| kev | 100.0% | 50.0% | 50.0% | 100.0% |" in markdown
        assert "**源覆盖率：50.0%**" in markdown
        assert "以下启用源当前无数据" in markdown and "ghsa" in markdown
        assert "论文源（arxiv / openalex）" in markdown

    def test_full_coverage_message(self) -> None:
        """全部源都有数据时给出 ✅ 结论。"""
        markdown = render_markdown(
            self.make_qualities(),
            declared=["kev"],
            since=None,
            generated_at=datetime(2026, 9, 30, tzinfo=UTC),
        )
        assert "**源覆盖率：100.0%**" in markdown
        assert "所有声明的启用源均已有数据" in markdown
        assert "全量（不限时间）" in markdown


class TestCollectRawItems:
    """从 ``raw_item`` 表读取（SQLite 内存库，不依赖 PostgreSQL）。"""

    async def test_reads_per_source_counts(self, memory_engine: Any, monkeypatch: Any) -> None:
        """按源读取条目并完成评估（缺数据的源计 0）。"""
        async with session_scope(memory_engine) as session:
            repo = RawRepository(session)
            await repo.upsert(make_raw("kev", "CVE-2024-3400", KEV_ENTRY))
            await repo.upsert(make_raw("nvd", "CVE-2024-3400", NVD_FULL))
        monkeypatch.setattr("scripts.data_quality.get_engine", lambda settings: memory_engine)
        settings = Settings(_env_file=None)

        grouped = await collect_raw_items(settings, sources=["kev", "nvd", "epss"])
        qualities = {item.source: item for item in evaluate_all(grouped, sources=["kev", "nvd", "epss"])}

        assert qualities["kev"].raw_count == 1
        assert qualities["nvd"].raw_count == 1
        assert qualities["epss"].raw_count == 0
        assert qualities["nvd"].completeness("cvss") == 1.0

    async def test_since_filter_excludes_old_records(self, memory_engine: Any, monkeypatch: Any) -> None:
        """``since`` 过滤掉窗口外的记录（按发布时间回退采集时间）。"""
        async with session_scope(memory_engine) as session:
            await RawRepository(session).upsert(make_raw("kev", "CVE-2024-3400", KEV_ENTRY))
        monkeypatch.setattr("scripts.data_quality.get_engine", lambda settings: memory_engine)
        settings = Settings(_env_file=None)

        grouped = await collect_raw_items(
            settings, sources=["kev"], since=datetime(2030, 1, 1, tzinfo=UTC)
        )
        assert grouped["kev"] == []


class TestCli:
    """命令行参数与端到端落盘。"""

    def test_default_args(self) -> None:
        """默认输出到 ``reports/data_quality.md``，窗口为全量。"""
        args = parse_args([])
        assert args.out == "reports/data_quality.md"
        assert args.since is None
        assert args.days == 0
        assert args.limit == 0
        assert args.source is None

    def test_since_and_source_args(self) -> None:
        """``--since`` / ``--source`` / ``--limit`` 被正确解析。"""
        args = parse_args(["--since", "2024-01-01", "--source", "nvd,kev", "--limit", "5"])
        assert args.since == "2024-01-01"
        assert args.source == "nvd,kev"
        assert args.limit == 5

    async def test_run_writes_markdown(self, memory_engine: Any, monkeypatch: Any, tmp_path: Path) -> None:
        """``run`` 生成 Markdown 报告并返回 0。"""
        async with session_scope(memory_engine) as session:
            await RawRepository(session).upsert(make_raw("kev", "CVE-2024-3400", KEV_ENTRY))
        monkeypatch.setattr("scripts.data_quality.get_engine", lambda settings: memory_engine)
        target = tmp_path / "data_quality.md"

        code = await run(parse_args(["--source", "kev", "--out", str(target)]))

        assert code == 0
        text = target.read_text(encoding="utf-8")
        assert "| kev | 漏洞 | 1 | 1 | 0 | 100.0% |" in text
        assert set(FIELD_NAMES) == {"description", "cvss", "cwe", "references"}

    async def test_run_returns_two_on_bad_since(self, tmp_path: Path) -> None:
        """``--since`` 无法解析时返回 2（参数错误）。"""
        code = await run(parse_args(["--since", "not-a-date", "--out", str(tmp_path / "x.md")]))
        assert code == 2

