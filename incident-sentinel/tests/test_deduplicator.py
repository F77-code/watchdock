import asyncio

import pytest

from config import Settings
from core.deduplicator import Deduplicator, normalize, signature_hash
from core.detector import CRASH_EXIT, STUCK_IN_RESTART_LOOP


def _settings(**overrides: float | int) -> Settings:
    data: dict[str, object] = {
        "openai_api_key": "sk-test",
        "telegram_bot_token": "token",
        "telegram_chat_id": "1",
        "debounce_window_sec": 0.05,
        "cooldown_period_sec": 0.25,
        "restart_loop_threshold": 3,
        "restart_loop_window_sec": 120,
        "restart_loop_cooldown_sec": 10,
    }
    data.update(overrides)
    return Settings(**data)  # type: ignore[arg-type]


def test_signature_ignores_volatile_tokens() -> None:
    left = signature_hash(
        "api",
        "fail 550e8400-e29b-41d4-a716-446655440000 at 10.1.2.3 2026-09-24T14:15:30.123Z",
    )
    right = signature_hash(
        "api",
        "fail 11111111-2222-3333-4444-555555555555 at 192.168.0.8 2026-09-24 14:15:30",
    )
    assert left == right
    assert "<UUID>" in normalize("550e8400-e29b-41d4-a716-446655440000")
    assert signature_hash("db", "fail <UUID>") != left


@pytest.mark.asyncio
async def test_debounce_collapses_burst_and_cooldown_counts_repeats() -> None:
    ready: list = []

    async def on_ready(draft) -> None:
        ready.append(draft)

    dedup = Deduplicator(_settings(), on_ready)
    await dedup.submit("api", "LOG_ERROR", "FATAL: pool exhausted")
    await dedup.submit("api", "LOG_ERROR", "FATAL: pool exhausted")
    await asyncio.sleep(0.12)
    assert len(ready) == 1
    assert ready[0].occurrences == 2
    assert ready[0].repeated is False

    await dedup.submit("api", "LOG_ERROR", "FATAL: pool exhausted")
    await asyncio.sleep(0.12)
    assert len(ready) == 1

    await asyncio.sleep(0.2)
    await dedup.submit("api", "LOG_ERROR", "FATAL: pool exhausted")
    await asyncio.sleep(0.12)
    assert len(ready) == 2
    assert ready[1].repeated is True
    assert ready[1].occurrences >= 2
    await dedup.close()


@pytest.mark.asyncio
async def test_restart_loop_emits_one_alert() -> None:
    ready: list = []

    async def on_ready(draft) -> None:
        ready.append(draft)

    dedup = Deduplicator(_settings(), on_ready)
    for _ in range(3):
        await dedup.note_restart("api")
    await asyncio.sleep(0.12)
    assert ready == []

    await dedup.note_restart("api")
    await asyncio.sleep(0.12)
    assert len(ready) == 1
    assert ready[0].trigger_type == STUCK_IN_RESTART_LOOP

    await dedup.submit("api", CRASH_EXIT, "die exit=1")
    await dedup.note_restart("api")
    await asyncio.sleep(0.12)
    assert len(ready) == 1
    await dedup.close()
