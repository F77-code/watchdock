"""Маскирование секретов в строках логов до буфера и ещё раз перед LLM."""

import re

_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]+")
_DB_URI = re.compile(r"(?i)([a-z]+://[^:]+:)[^@]+(@)")
_SECRET = re.compile(
    r"""(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"][^'"]+['"]"""
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----",
    re.DOTALL,
)


def sanitize(text: str) -> str:
    text = _PRIVATE_KEY.sub("[REDACTED_RSA_KEY]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _DB_URI.sub(r"\1[MASKED_PASSWORD]\2", text)
    text = _SECRET.sub(r'\1: "[REDACTED]"', text)
    return text
