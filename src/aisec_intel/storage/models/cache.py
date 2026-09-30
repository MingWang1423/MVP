"""``llm_cache`` 的 ORM 映射（表 ``llm_cache``，PROJECT_PLAN.md §3.4 / §5.6）。

用途：**富化重复跑不烧钱**——以 ``sha256(prompt + model + temperature)`` 为幂等键缓存
LLM 结构化输出；命中即直接返回，避免重复扣费（§3.4 额度保护第 1 条）。

设计：
    - ``cache_key`` 为主键（64 位十六进制）；
    - ``response_json`` 存结构化输出的 JSON（便于 ``schema.model_validate`` 二次校验）；
    - ``prompt_tokens`` / ``completion_tokens`` 记录**首次**调用消耗，用于成本评估；
    - ``hits`` 累计命中次数，便于运维页观察真实节省。
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aisec_intel.storage.base import Base


class LLMCacheRow(Base):
    """``llm_cache`` 表：结构化输出缓存（prompt 指纹 → 响应 JSON）。"""

    __tablename__ = "llm_cache"

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True, doc="sha256(prompt + model + temperature)")
    provider: Mapped[str] = mapped_column(String(32), doc="提供方：deepseek / ollama / ...")
    model: Mapped[str] = mapped_column(String(64), index=True, doc="模型名，如 deepseek-chat")
    temperature: Mapped[float] = mapped_column(default=0.0)
    schema_name: Mapped[str] = mapped_column(String(64), doc="结构化输出目标模型名")
    response_json: Mapped[str] = mapped_column(Text, doc="结构化输出 JSON")
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    hits: Mapped[int] = mapped_column(Integer, default=0, doc="命中次数")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
