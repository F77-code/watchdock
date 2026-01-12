from datetime import datetime, timezone

import pytest

from config import Settings
from core.buffer import RingBuffer
from core.deduplicator import IncidentDraft
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
