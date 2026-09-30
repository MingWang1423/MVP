"""采集器抽象基类（PROJECT_PLAN.md §5.3 P2，约束见 §0 第 1/4 条）。

所有采集器必须继承 :class:`BaseConnector`。基类负责：

1. **统一出口**：``fetch_incremental()`` 返回 ``list[RawItem]``，子类不得返回裸 dict；
2. **统一构造**：``build_raw_item()`` 负责生成 ``trace_id`` / ``fetched_at`` / ``sha256``（§10.2 不变式 5）；
3. **统一限流与超时**：按 ``source_name`` 自动选择限流规格（NVD 特例），HTTP 超时来自类属性 ``timeout``；
4. **禁止 LLM**：L1 采集层为纯传统代码（§0 约束 1），基类不引入任何模型依赖。
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import date, datetime
from typing import Any, ClassVar

from aisec_intel.config import Settings, get_settings
from aisec_intel.connectors.http_client import DEFAULT_TIMEOUT_S, HttpClient
from aisec_intel.connectors.rate_limiter import DEFAULT_RATE_LIMIT, RateLimiter
from aisec_intel.logging_config import get_logger
from aisec_intel.models.base import new_trace_id, utc_now
from aisec_intel.models.raw_item import RawItem
from aisec_intel.normalize.datetime_utils import parse_datetime
from aisec_intel.utils.hashing import sha256_text

logger = get_logger(__name__)

RAW_ITEM_FIELDS: frozenset[str] = frozenset(RawItem.model_fields)
"""``RawItem`` 的合法字段名集合（用于 ``normalize()`` 过滤未识别键）。"""


class BaseConnector(ABC):
    """采集器抽象基类。

    Attributes:
        source_name: 源标识（子类必须声明非空，如 ``"kev"``）。
        rate_limit: 限流规格字符串，形如 ``"5/30"``（默认 10 req/s）。
        timeout: 单次 HTTP 请求超时（秒）。
    """

    source_name: ClassVar[str] = ""
    rate_limit: ClassVar[str] = DEFAULT_RATE_LIMIT
    timeout: ClassVar[float] = DEFAULT_TIMEOUT_S

    def __init__(
        self,
        *,
        http: HttpClient | None = None,
        limiter: RateLimiter | None = None,
        settings: Settings | None = None,
        max_records: int | None = None,
    ) -> None:
        """初始化采集器。

        Args:
            http: 注入的 HTTP 客户端（测试时注入 ``MockTransport`` 版本）；
                为 ``None`` 时按 ``timeout`` 与 ``user_agent`` 自行创建。
            limiter: 注入的限流器；为 ``None`` 时按 ``source_name`` 自动创建。
            settings: 全局配置；默认使用 :func:`aisec_intel.config.get_settings`。
            max_records: 单次采集记录上限（``None`` = 不限）。子类可在分页/批量循环中
                用 :meth:`limit_reached` 提前停止，避免宽时间窗下无谓的 API 调用。

        Raises:
            ValueError: 子类未声明 ``source_name``。
        """
        if not self.source_name:
            raise ValueError(f"{type(self).__name__} 必须声明非空的 source_name")
        self._settings = settings or get_settings()
        self._max_records = max_records if (max_records is None or max_records > 0) else None
        self._owns_http = http is None
        self._http = http or HttpClient(timeout=self.timeout, user_agent=self.user_agent)
        self._limiter = limiter or RateLimiter.for_source(self.source_name, settings=self._settings)

    @property
    def max_records(self) -> int | None:
        """单次采集记录上限（``None`` 表示不限）。"""
        return self._max_records

    def limit_reached(self, count: int) -> bool:
        """判断已收集条数是否达到上限。

        Args:
            count: 已收集条数。

        Returns:
            达到上限返回 ``True``（子类据此提前停止分页）。
        """
        return self._max_records is not None and count >= self._max_records

    # ---------- 属性 ----------

    @property
    def source(self) -> str:
        """源标识（等价于 ``source_name``，供上层统一读取）。"""
        return self.source_name

    @property
    def http(self) -> HttpClient:
        """HTTP 客户端。"""
        return self._http

    @property
    def limiter(self) -> RateLimiter:
        """限流器（发请求前需 ``await limiter.acquire()``）。"""
        return self._limiter

    @property
    def settings(self) -> Settings:
        """全局配置。"""
        return self._settings

    @property
    def user_agent(self) -> str:
        """本采集器使用的 User-Agent。"""
        from aisec_intel import __version__  # 延迟导入以避免包初始化顺序问题

        return f"aisec-intel/{__version__} ({self.source_name}-collector)"

    @property
    def enabled(self) -> bool:
        """是否启用（子类可覆盖，例如无 API Key 时的行为差异）。"""
        return True

    def describe(self) -> dict[str, Any]:
        """返回采集器元信息（供前端「采集运维」页与日志使用）。

        Returns:
            含 ``source`` / ``rate_limit`` / ``timeout`` / ``enabled`` / ``class`` 的字典。
        """
        return {
            "source": self.source_name,
            "rate_limit": self.rate_limit,
            "timeout": self.timeout,
            "enabled": self.enabled,
            "class": type(self).__name__,
        }

    # ---------- 生命周期 ----------

    async def aclose(self) -> None:
        """释放自建的 HTTP 连接池（注入的客户端由调用方负责关闭）。"""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> BaseConnector:
        """进入异步上下文。

        Returns:
            自身实例。
        """
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """退出异步上下文并释放资源。

        Args:
            *exc_info: 异常信息（未使用）。
        """
        await self.aclose()

    # ---------- 子类必须实现 ----------

    @abstractmethod
    async def fetch_incremental(self, since: datetime) -> list[RawItem]:
        """拉取自 ``since``（UTC，含）之后的新增原始情报件。

        Args:
            since: 增量起点（UTC）；实现内部需先 ``await self.limiter.acquire()``。

        Returns:
            统一格式的 ``RawItem`` 列表（可能为空）。
        """
        raise NotImplementedError

    @abstractmethod
    async def health_check(self) -> bool:
        """源可用性探活。

        Returns:
            可用返回 ``True``；任何异常都应被吞掉并返回 ``False``（探活不得中断主流程）。
        """
        raise NotImplementedError


    # ---------- 默认实现（子类可覆盖） ----------

    def normalize(self, raw: dict[str, Any]) -> RawItem:
        """把源侧原始字典映射为统一 ``RawItem``。

        默认实现约定 ``raw`` 至少包含 ``source_id`` 与 ``raw_text``：其余字段按
        ``RawItem`` 的字段名透传，未识别的键会被扁平化写入 ``meta``
        （既不触发 ``extra="forbid"``，也不丢信息）。

        Args:
            raw: 源侧解析后的字典。

        Returns:
            统一格式的 ``RawItem``。

        Raises:
            ValueError: 缺少 ``source_id`` 或 ``raw_text``。
        """
        missing = {"source_id", "raw_text"} - set(raw)
        if missing:
            raise ValueError(f"normalize() 缺少必需字段：{sorted(missing)}")

        meta: dict[str, str] = {key: _flatten(value) for key, value in dict(raw.get("meta") or {}).items()}
        for key, value in raw.items():
            if key in RAW_ITEM_FIELDS or key == "meta":
                continue
            meta.setdefault(key, _flatten(value))

        return self.build_raw_item(
            source_id=str(raw["source_id"]),
            raw_text=str(raw["raw_text"]),
            url=str(raw.get("url") or ""),
            title=_optional_str(raw.get("title")),
            published_at=self.to_utc_datetime(raw.get("published_at")),
            lang=_optional_str(raw.get("lang")),
            meta=meta,
            trace_id=_optional_str(raw.get("trace_id")),
        )

    def build_raw_item(
        self,
        *,
        source_id: str,
        raw_text: str,
        url: str = "",
        title: str | None = None,
        published_at: datetime | None = None,
        lang: str | None = None,
        meta: dict[str, str] | None = None,
        trace_id: str | None = None,
    ) -> RawItem:
        """统一构造 ``RawItem``（自动生成 ``trace_id`` / ``fetched_at`` / ``sha256``）。

        Args:
            source_id: 源内唯一 ID（CVE ID / GHSA ID / arXiv ID）。
            raw_text: 保真原文（JSON 或正文）。
            url: 原文链接；缺省时回退为 ``source_url``。
            title: 标题。
            published_at: 源发布时间（UTC）。
            lang: 语言标识。
            meta: 源特有附加字段。
            trace_id: 指定追踪 ID；缺省自动生成（§10.2 不变式 5）。

        Returns:
            统一格式的 ``RawItem``。
        """
        return RawItem(
            trace_id=trace_id or new_trace_id(),
            source=self.source_name,
            source_id=source_id,
            url=url or self.source_url,
            title=title,
            raw_text=raw_text,
            lang=lang,
            published_at=published_at,
            fetched_at=utc_now(),
            sha256=sha256_text(raw_text),
            meta=meta or {},
        )

    @property
    def source_url(self) -> str:
        """源首页地址（``url`` 缺省时的回退值，子类应覆盖）。"""
        return f"https://example.invalid/{self.source_name}"

    @staticmethod
    def to_utc_datetime(value: datetime | date | str | int | float | None) -> datetime | None:
        """把日期 / ISO8601 字符串统一转换为 UTC ``datetime``。

        Note:
            实现委托给 L2 纯函数 :func:`aisec_intel.normalize.datetime_utils.parse_datetime`，
            保证全项目时间口径唯一（``date`` 视为当日 00:00:00Z，naive 视为 UTC，见 §10.2 不变式 3）。

        Args:
            value: ``datetime`` / ``date`` / ISO8601 字符串 / Unix 时间戳 / ``None``。

        Returns:
            UTC ``datetime``；入参为 ``None`` 或无法解析时返回 ``None``。
        """
        parsed = parse_datetime(value)
        if parsed is None and isinstance(value, str) and value.strip():
            logger.warning(f"无法解析时间字符串：{value!r}")
        return parsed

    def raw_text_from_json(self, payload: Any) -> str:
        """把源侧结构化对象序列化为**保真原文**（供 ``RawItem.raw_text`` 存储）。

        Args:
            payload: 任意 JSON 可序列化对象。

        Returns:
            紧凑 JSON 文本（``sort_keys=True`` 保证指纹稳定、``ensure_ascii=False`` 保留原文）。
        """
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _optional_str(value: Any) -> str | None:
    """把可选值安全转为字符串（``None`` 原样返回）。"""
    return None if value is None else str(value)


def _flatten(value: Any) -> str:
    """把任意值扁平化为字符串（``RawItem.meta`` 只接受 ``dict[str, str]``）。"""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
