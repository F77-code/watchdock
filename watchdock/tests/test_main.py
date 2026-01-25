from datetime import datetime, timezone

import asyncio
import pytest

from config import Settings
from core.buffer import RingBuffer
from core.deduplicator import Deduplicator, IncidentDraft
from core.snapshotter import Snapshotter
from main import build_context


@pytest.mark.asyncio
async def test_context_includes_neighbor_errors_and_sanitizes_again(tmp_path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("0.1 0.2 0.3 1/1 1\n")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 500 kB\n")
    settings = Settings(
        openai_api_key="sk",
        telegram_bot_token="token",
        telegram_chat_id="1",
        host_proc_path=str(proc),
        compose_project_name="billing",
    )
    buffer = RingBuffer(max_lines=20, max_bytes=10_000, max_line_chars=500)
    stamp = datetime(2026, 9, 24, 14, 0, tzinfo=timezone.utc)
    await buffer.append("backend_api", 'FATAL token="abc"', stamp)
    await buffer.append("postgres", "connection refused", stamp)
    await buffer.append("redis", "INFO ready", stamp)

    context = await build_context(
        buffer,
        Snapshotter(settings),
        IncidentDraft(
            container="backend_api",
            trigger_type="LOG_ERROR",
            signature="abc",
            error_text="FATAL",
            occurrences=2,
            repeated=False,
        ),
    )

    joined = "\n".join(context.raw_logs)
    assert "abc" not in joined
    assert 'token: "[REDACTED]"' in joined
    assert any(line.startswith("[postgres]") and "connection refused" in line for line in context.raw_logs)
    assert not any("redis" in line for line in context.raw_logs)
    assert context.occurrences_count == 2
    assert context.host_metrics.ram_used_pct == 50.0


from core.notifier import Notifier
from schemas.llm import IncidentClassification, LLMIncidentTriage, SeverityLevel


class _QuietLLM:
    def __init__(self, severity: SeverityLevel) -> None:
        self.severity = severity

    async def triage(self, context):
        return LLMIncidentTriage(
            summary="noise",
            severity=self.severity,
            classification=IncidentClassification.UNKNOWN,
            root_cause="nothing urgent",
            blast_radius="one request",
            mitigation_steps=["wait"],
            suggested_commands=["true"],
        )

    async def close(self) -> None:
        return None


class _CountingNotifier:
    def __init__(self) -> None:
        self.sent = 0

    async def send(self, context, triage, repeated: bool = False) -> bool:
        self.sent += 1
        return True

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_dispatch_skips_alerts_below_the_floor(tmp_path) -> None:
    from main import _dispatch

    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("0.1 0.1 0.1 1/1 1\n")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 800 kB\n")
    settings = Settings(
        openai_api_key="sk",
        telegram_bot_token="token",
        telegram_chat_id="1",
        host_proc_path=str(proc),
        min_severity="HIGH",
    )
    buffer = RingBuffer(max_lines=5, max_bytes=1000, max_line_chars=100)
    draft = IncidentDraft(
        container="api",
        trigger_type="LOG_ERROR",
        signature="sig",
        error_text="FATAL",
        occurrences=1,
        repeated=False,
    )
    notifier = _CountingNotifier()
    await _dispatch(draft, buffer, Snapshotter(settings), _QuietLLM(SeverityLevel.LOW), notifier, settings)  # type: ignore[arg-type]
    assert notifier.sent == 0
    await _dispatch(draft, buffer, Snapshotter(settings), _QuietLLM(SeverityLevel.CRITICAL), notifier, settings)  # type: ignore[arg-type]
    assert notifier.sent == 1


@pytest.mark.asyncio
async def test_dispatch_still_sends_when_triage_returns_fallback(tmp_path) -> None:
    from core.llm_client import LLMClient
    from main import _dispatch

    class _Completions:
        async def parse(self, **kwargs):
            raise IndexError("choices")

    class _Chat:
        def __init__(self) -> None:
            self.completions = _Completions()

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

        async def close(self) -> None:
            return None

    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("0.1 0.1 0.1 1/1 1\n")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 800 kB\n")
    settings = Settings(
        openai_api_key="sk",
        telegram_bot_token="token",
        telegram_chat_id="1",
        host_proc_path=str(proc),
    )
    seen: list = []

    class _CaptureNotifier:
        async def send(self, context, triage, repeated: bool = False) -> bool:
            seen.append(triage)
            return True

    delivered = await _dispatch(
        IncidentDraft(
            container="api",
            trigger_type="LOG_ERROR",
            signature="sig",
            error_text="FATAL",
            occurrences=1,
            repeated=False,
        ),
        RingBuffer(max_lines=5, max_bytes=1000, max_line_chars=100),
        Snapshotter(settings),
        LLMClient(settings, client=_Client()),  # type: ignore[arg-type]
        _CaptureNotifier(),  # type: ignore[arg-type]
        settings,
    )
    assert delivered is True
    assert seen[0].summary == "Автоматический триаж недоступен (LLM Timeout/Error)"


@pytest.mark.asyncio
async def test_shutdown_sends_open_debounce_before_closing_clients() -> None:
    from main import shutdown

    order: list[str] = []
    stopped = asyncio.Event()

    class _Watcher:
        async def stop(self) -> None:
            order.append("watcher")
            stopped.set()

    async def watcher_run() -> None:
        await stopped.wait()

    watcher_task = asyncio.create_task(watcher_run())
    ready: list = []

    async def on_ready(draft) -> bool:
        ready.append(draft)
        order.append("ready")
        return True

    settings = Settings(
        openai_api_key="sk",
        telegram_bot_token="token",
        telegram_chat_id="1",
        debounce_window_sec=30,
    )
    dedup = Deduplicator(settings, on_ready)
    await dedup.submit("api", "LOG_ERROR", "FATAL")

    class _Client:
        def __init__(self, name: str) -> None:
            self.name = name

        async def close(self) -> None:
            order.append(self.name)

    await shutdown(
        _Watcher(),  # type: ignore[arg-type]
        watcher_task,
        dedup,
        _Client("telegram"),  # type: ignore[arg-type]
        _Client("llm"),  # type: ignore[arg-type]
        budget=1,
    )
    assert len(ready) == 1
    assert order.index("ready") < order.index("telegram")
    assert order.index("telegram") < order.index("llm")
    assert watcher_task.done()
    state = next(iter(dedup._states.values()))
    assert state.waiting is False


@pytest.mark.asyncio
async def test_third_review_waits_while_logs_still_append() -> None:
    from main import bounded_review

    slots = asyncio.Semaphore(2)
    active = 0
    peak = 0
    release = asyncio.Event()
    both_inside = asyncio.Event()
    buffer = RingBuffer(max_lines=10, max_bytes=5000, max_line_chars=200)

    async def handler(_draft: IncidentDraft) -> bool:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            both_inside.set()
        await release.wait()
        active -= 1
        return True

    async def on_ready(draft: IncidentDraft) -> bool:
        return await bounded_review(slots, handler, draft)

    dedup = Deduplicator(
        Settings(
            openai_api_key="sk",
            telegram_bot_token="token",
            telegram_chat_id="1",
            debounce_window_sec=0.01,
            cooldown_period_sec=30,
        ),
        on_ready,
    )
    for index in range(3):
        await dedup.submit("api", "LOG_ERROR", f"FATAL {index}")
    await both_inside.wait()
    await asyncio.sleep(0.05)
    assert peak == 2
    assert active == 2
    await buffer.append("api", "line while reviews are busy")
    assert await buffer.snapshot("api")
    release.set()
    await dedup.close(timeout=1)
    assert peak == 2


def test_http_client_logs_stay_quiet_when_the_app_is_on_debug() -> None:
    import logging

    from main import silence_http_client_logs

    logging.getLogger("httpx").setLevel(logging.DEBUG)
    silence_http_client_logs()
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING


@pytest.mark.asyncio
async def test_heartbeat_logs_until_stop(caplog) -> None:
    import logging

    from main import heartbeat

    caplog.set_level(logging.INFO, logger="main")
    stop = asyncio.Event()
    task = asyncio.create_task(heartbeat(stop, 0.02))
    await asyncio.sleep(0.07)
    stop.set()
    await task
    assert "sentinel is alive" in caplog.text
