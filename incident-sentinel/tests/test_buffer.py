from datetime import datetime, timezone

import pytest

from core.buffer import RingBuffer


@pytest.mark.asyncio
async def test_keeps_only_last_lines() -> None:
    buffer = RingBuffer(max_lines=2, max_bytes=10_000, max_line_chars=100)
    stamp = datetime(2026, 9, 24, 14, 0, tzinfo=timezone.utc)
    await buffer.append("api", "one", stamp)
    await buffer.append("api", "two", stamp)
    await buffer.append("api", "three", stamp)

    lines = await buffer.snapshot("api")
    assert [line.split(" ", 1)[1] for line in lines] == ["two", "three"]
    assert lines[0].startswith("2026-09-24T14:00:00Z")


@pytest.mark.asyncio
async def test_truncates_long_line() -> None:
    buffer = RingBuffer(max_lines=5, max_bytes=10_000, max_line_chars=32)
    stored = await buffer.append("api", "x" * 100)
    assert stored.endswith(" [TRUNCATED]")
    assert len(stored) == 32


@pytest.mark.asyncio
async def test_evicts_by_byte_budget() -> None:
    buffer = RingBuffer(max_lines=50, max_bytes=30, max_line_chars=100)
    await buffer.append("api", "a" * 20)
    await buffer.append("api", "b" * 20)
    await buffer.append("api", "c" * 20)

    lines = await buffer.snapshot("api")
    assert len(lines) < 3
    assert await buffer.byte_size("api") <= 30
    assert lines[-1].endswith("c" * 20)


@pytest.mark.asyncio
async def test_containers_are_isolated() -> None:
    buffer = RingBuffer(max_lines=5, max_bytes=10_000, max_line_chars=100)
    await buffer.append("api", "from-api")
    await buffer.append("db", "from-db")
    assert await buffer.snapshot("api") != await buffer.snapshot("db")
    assert await buffer.snapshot("missing") == []
