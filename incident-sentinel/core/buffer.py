"""Кольцевой буфер последних строк лога по каждому контейнеру."""

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone

_TRUNCATED = " [TRUNCATED]"


@dataclass(slots=True)
class LogRecord:
    timestamp: datetime
    line: str


class RingBuffer:
    def __init__(self, max_lines: int, max_bytes: int, max_line_chars: int) -> None:
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self.max_line_chars = max_line_chars
        self._lines: dict[str, deque[LogRecord]] = {}
        self._bytes: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def clip(self, line: str) -> str:
        line = line.replace("\x00", "").rstrip("\r\n")
        if len(line) <= self.max_line_chars:
            return line
        keep = self.max_line_chars - len(_TRUNCATED)
        if keep < 1:
            return line[: self.max_line_chars]
        return line[:keep] + _TRUNCATED

    async def append(
        self,
        container: str,
        line: str,
        timestamp: datetime | None = None,
    ) -> str:
        stored = self.clip(line)
        record = LogRecord(timestamp or datetime.now(timezone.utc), stored)
        size = len(stored.encode("utf-8"))
        async with self._lock:
            bucket = self._lines.setdefault(container, deque())
            bucket.append(record)
            self._bytes[container] = self._bytes.get(container, 0) + size
            self._evict(container)
        return stored

    def _evict(self, container: str) -> None:
        bucket = self._lines[container]
        while len(bucket) > self.max_lines or (
            len(bucket) > 1 and self._bytes[container] > self.max_bytes
        ):
            old = bucket.popleft()
            self._bytes[container] -= len(old.line.encode("utf-8"))

    async def snapshot(self, container: str) -> list[str]:
        async with self._lock:
            bucket = self._lines.get(container)
            if not bucket:
                return []
            return [_format(record) for record in bucket]

    async def snapshot_matching(self, container: str, predicate) -> list[str]:
        async with self._lock:
            bucket = self._lines.get(container)
            if not bucket:
                return []
            return [_format(record) for record in bucket if predicate(record.line)]

    async def containers(self) -> list[str]:
        async with self._lock:
            return list(self._lines)

    async def byte_size(self, container: str) -> int:
        async with self._lock:
            return self._bytes.get(container, 0)


def _format(record: LogRecord) -> str:
    stamp = record.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp} {record.line}"
