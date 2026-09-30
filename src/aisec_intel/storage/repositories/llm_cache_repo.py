"""``llm_cache`` 仓储：LLM 结构化输出缓存读写（PROJECT_PLAN.md §3.4 / §5.6）。

只做最朴素的键值读写（键由 :mod:`aisec_intel.llm.cache` 的纯函数生成）：

- :meth:`get`：命中返回缓存条目并**累加命中计数**；
- :meth:`put`：写入或刷新响应（同键重复写入视为覆盖 + 命中累计）。
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from aisec_intel.models.base import utc_now
from aisec_intel.storage.models.cache import LLMCacheRow


@dataclass(frozen=True, slots=True)
class LLMCacheEntry:
    """缓存条目。

    Attributes:
        cache_key: 幂等键。
        response_json: 结构化输出 JSON。
        prompt_tokens: 首次调用的输入 token 数。
        completion_tokens: 首次调用的输出 token 数。
        hits: 命中次数（含本次）。
    """

    cache_key: str
    response_json: str
    prompt_tokens: int
    completion_tokens: int
    hits: int


class LLMCacheRepository:
    """``llm_cache`` 表读写。"""

    def __init__(self, session: AsyncSession) -> None:
        """绑定异步会话。

        Args:
            session: 由 :func:`aisec_intel.storage.database.session_scope` 提供的会话。
        """
        self._session = session

    async def get(self, cache_key: str, *, count_hit: bool = True) -> LLMCacheEntry | None:
        """读取缓存（可选累加命中计数）。

        Args:
            cache_key: 幂等键。
            count_hit: ``True`` 时把 ``hits`` 加一（用于统计真实节省）。

        Returns:
            命中时返回 :class:`LLMCacheEntry`，否则 ``None``。
        """
        row = await self._session.get(LLMCacheRow, cache_key)
        if row is None:
            return None
        if count_hit:
            row.hits = int(row.hits or 0) + 1
            row.updated_at = utc_now()
            await self._session.flush()
        return LLMCacheEntry(
            cache_key=row.cache_key,
            response_json=row.response_json,
            prompt_tokens=int(row.prompt_tokens or 0),
            completion_tokens=int(row.completion_tokens or 0),
            hits=int(row.hits or 0),
        )

    async def put(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        temperature: float,
        schema_name: str,
        response_json: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> LLMCacheEntry:
        """写入（或刷新）缓存条目。

        Args:
            cache_key: 幂等键。
            provider: 提供方名称。
            model: 模型名。
            temperature: 采样温度（参与键计算，落库便于审计）。
            schema_name: 结构化输出目标模型名。
            response_json: 结构化输出 JSON。
            prompt_tokens: 输入 token 数。
            completion_tokens: 输出 token 数。

        Returns:
            写入后的缓存条目。
        """
        now = utc_now()
        row = await self._session.get(LLMCacheRow, cache_key)
        if row is None:
            row = LLMCacheRow(
                cache_key=cache_key,
                provider=provider,
                model=model,
                temperature=temperature,
                schema_name=schema_name,
                response_json=response_json,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                hits=0,
                created_at=now,
                updated_at=now,
            )
            self._session.add(row)
        else:
            row.response_json = response_json
            row.prompt_tokens = prompt_tokens
            row.completion_tokens = completion_tokens
            row.updated_at = now
        await self._session.flush()
        return LLMCacheEntry(
            cache_key=row.cache_key,
            response_json=row.response_json,
            prompt_tokens=int(row.prompt_tokens or 0),
            completion_tokens=int(row.completion_tokens or 0),
            hits=int(row.hits or 0),
        )

    async def count(self) -> int:
        """返回缓存的条目数（运维 / 成本页展示）。

        Returns:
            条目数。
        """
        await self._session.flush()
        from sqlalchemy import func, select

        stmt = select(func.count()).select_from(LLMCacheRow)
        return int((await self._session.execute(stmt)).scalar_one())
