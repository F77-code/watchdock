import asyncio

import pytest

from config import Settings
from core.deduplicator import Deduplicator, normalize, signature_hash
from core.detector import CRASH_EXIT, OOM, STUCK_IN_RESTART_LOOP


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

    async def on_ready(draft) -> bool:
        ready.append(draft)
        return True

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

    async def on_ready(draft) -> bool:
        ready.append(draft)
        return True

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


@pytest.mark.asyncio
async def test_failed_delivery_does_not_start_cooldown() -> None:
    ready: list = []

    async def on_ready(draft) -> bool:
        ready.append(draft)
        return len(ready) > 1

    dedup = Deduplicator(_settings(cooldown_period_sec=30), on_ready)
    await dedup.submit("api", "LOG_ERROR", "FATAL: pool exhausted")
    await asyncio.sleep(0.12)
    assert len(ready) == 1
    state = next(iter(dedup._states.values()))
    assert state.waiting is False
    assert state.cooldown_until == 0.0

    await dedup.submit("api", "LOG_ERROR", "FATAL: pool exhausted")
    await asyncio.sleep(0.12)
    assert len(ready) == 2
    assert next(iter(dedup._states.values())).cooldown_until > 0.0
    await dedup.close()


@pytest.mark.asyncio
async def test_oom_and_die_137_share_one_review() -> None:
    ready: list = []

    async def on_ready(draft) -> bool:
        ready.append(draft)
        return True

    dedup = Deduplicator(_settings(), on_ready)
    await dedup.submit("api", OOM, "oom")
    await dedup.submit("api", CRASH_EXIT, "die exit=137")
    await asyncio.sleep(0.12)
    assert len(ready) == 1
    assert ready[0].trigger_type == OOM

    await dedup.submit("api", CRASH_EXIT, "die exit=1")
    await asyncio.sleep(0.12)
    assert [item.trigger_type for item in ready] == [OOM, CRASH_EXIT]
    await dedup.close()


def test_long_hex_ids_share_one_signature() -> None:
    left = signature_hash("api", "panic req 0123456789abcdef0123456789abcdef")
    right = signature_hash("api", "panic req fedcba9876543210fedcba9876543210")
    assert left == right
    assert "<HEX>" in normalize("0123456789abcdef0123456789abcdef")
