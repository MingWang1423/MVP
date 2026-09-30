"""通用哈希工具（PROJECT_PLAN.md §5.3）。

采集层用内容指纹做幂等与去重（``RawItem.sha256``），因此哈希实现必须是**确定性**的：
同一输入在任何机器上产生同一结果，且不受编码/换行差异干扰。
"""

from __future__ import annotations

import hashlib

SHA256_HEX_LENGTH: int = 64
"""sha256 十六进制摘要长度。"""


def sha256_text(text: str) -> str:
    """计算文本的 sha256 十六进制摘要。

    Args:
        text: 待计算文本；内部统一按 UTF-8 编码。

    Returns:
        64 位小写十六进制摘要。

    Examples:
        >>> sha256_text("ping")[:8]
        'bb8ea4b0'
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(payload: bytes) -> str:
    """计算字节串的 sha256 十六进制摘要。

    Args:
        payload: 待计算字节串。

    Returns:
        64 位小写十六进制摘要。
    """
    return hashlib.sha256(payload).hexdigest()


def is_sha256(value: str) -> bool:
    """判断字符串是否形如 sha256 摘要（64 位十六进制）。

    Args:
        value: 待判断字符串。

    Returns:
        符合格式返回 ``True``，否则 ``False``。
    """
    if len(value) != SHA256_HEX_LENGTH:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())
