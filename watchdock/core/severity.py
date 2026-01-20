"""Порядок критичности для фильтра алертов."""

from schemas.llm import SeverityLevel

_ORDER = {
    SeverityLevel.LOW: 0,
    SeverityLevel.MEDIUM: 1,
    SeverityLevel.HIGH: 2,
    SeverityLevel.CRITICAL: 3,
}


def parse_severity(value: str) -> SeverityLevel:
    try:
        return SeverityLevel(value.strip().upper())
    except ValueError:
        return SeverityLevel.LOW


def below_minimum(level: SeverityLevel, minimum: str) -> bool:
    return _ORDER[level] < _ORDER[parse_severity(minimum)]




def ensure_high(level: SeverityLevel) -> SeverityLevel:
    if _ORDER[level] < _ORDER[SeverityLevel.HIGH]:
        return SeverityLevel.HIGH
    return level
