"""Правила, по которым строка лога или событие Docker становится инцидентом."""

import re

LOG_ERROR = "LOG_ERROR"
OOM = "OOM"
CRASH_EXIT = "CRASH_EXIT"
UNHEALTHY = "UNHEALTHY"
STUCK_IN_RESTART_LOOP = "STUCK_IN_RESTART_LOOP"

_PATTERNS = (
    re.compile(r"(?i)\b(FATAL|CRITICAL|PANIC)\b"),
    re.compile(r"(?i)\b(Traceback \(most recent call last\):)"),
    re.compile(r"(?i)\b(NullPointerException|Segmentation fault|SIGSEGV)\b"),
    re.compile(r'(?i)\bHTTP/\d\.\d"\s+5\d{2}\b'),
    re.compile(r"(?i)(connection refused|deadlock detected|out of memory)"),
)


def match_log(line: str) -> bool:
    return any(pattern.search(line) for pattern in _PATTERNS)


def classify_action(action: str, exit_code: int | None = None) -> str | None:
    normalized = action.strip().lower()
    if normalized == "oom":
        return OOM
    if normalized == "die" and exit_code not in (None, 0):
        return CRASH_EXIT
    if normalized.startswith("health_status") and "unhealthy" in normalized:
        return UNHEALTHY
    return None
