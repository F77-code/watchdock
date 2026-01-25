"""Маскирование секретов в строках логов до буфера и ещё раз перед LLM."""

import re

_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]+")
_DB_URI = re.compile(r"(?i)([a-z]+://[^:]+:)[^@]+(@)")
_SECRET = re.compile(
    r"""(?i)\b(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*(?:'(?:[^']*)'|"(?:[^"]*)"|[^\s'"]+)"""
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----",
    re.DOTALL,
)
_SK = re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}\b")
_AKIA = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")


def sanitize(text: str) -> str:
    text = _PRIVATE_KEY.sub("[REDACTED_RSA_KEY]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _DB_URI.sub(r"\1[MASKED_PASSWORD]\2", text)
    text = _SECRET.sub(r'\1: "[REDACTED]"', text)
    text = _SK.sub("[REDACTED]", text)
    text = _AKIA.sub("[REDACTED]", text)
    text = _JWT.sub("[REDACTED]", text)
    return text
