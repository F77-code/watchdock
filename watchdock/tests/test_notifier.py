import re
from datetime import datetime, timezone

import httpx
import pytest

from config import Settings
from core.notifier import TELEGRAM_LIMIT, build_message
from schemas.incident import ContainerStatus, HostSnapshot, IncidentContext
from schemas.llm import IncidentClassification, LLMIncidentTriage, SeverityLevel


def _context(**overrides: object) -> IncidentContext:
    data: dict[str, object] = {
        "incident_id": "inc-1",
        "timestamp": datetime(2026, 9, 24, 14, 15, 30, tzinfo=timezone.utc),
        "failed_container": "backend_api",
        "trigger_type": "LOG_ERROR",
        "raw_logs": ["FATAL pool"],
        "host_metrics": HostSnapshot(
            load_avg=[4.12, 2.5, 1.8],
            ram_used_pct=87.2,
            ram_available_mb=400,
            disk_free_gb=14.2,
        ),
        "neighbor_states": [
            ContainerStatus(
                name="backend_api",
                status="Restarting (1)",
                restart_count=0,
                memory_usage_mb=210,
                memory_limit_mb=256,
            ),
            ContainerStatus(name="postgres", status="Up", health="unhealthy", restart_count=2),
            ContainerStatus(name="redis", status="Up", restart_count=0),
        ],
        "occurrences_count": 1,
    }
    data.update(overrides)
    return IncidentContext(**data)  # type: ignore[arg-type]


def _triage(**overrides: object) -> LLMIncidentTriage:
    data: dict[str, object] = {
        "summary": "Пул соединений PostgreSQL исчерпан",
        "severity": SeverityLevel.CRITICAL,
        "classification": IncidentClassification.DATABASE_CONNECTIVITY,
        "root_cause": "FATAL: remaining connection slots <superuser>",
        "blast_radius": "Бэкенд возвращает HTTP 500",
        "mitigation_steps": ["Проверить блокировки", "Перезапустить backend"],
        "suggested_commands": ["docker compose ps"],
    }
    data.update(overrides)
    return LLMIncidentTriage(**data)  # type: ignore[arg-type]


def test_message_uses_severity_emoji_and_escapes_html() -> None:
    text = build_message(_context(), _triage())
    assert text.startswith("🚨 <b>CRITICAL INCIDENT: [backend_api] · LOG_ERROR</b>")
    assert "2026-09-24 14:15:30 UTC" in text
    assert "<code>DATABASE_CONNECTIVITY</code>" in text
    assert "(Случилось раз: 1)" in text
    assert "remaining connection slots &lt;superuser&gt;" in text
    assert "<superuser>" not in text
    assert "LA <code>[4.12, 2.50, 1.80]</code>" in text
    assert "RAM: <code>87%</code>" in text
    assert "14.2 GB свободно" in text
    assert "210MB / 256MB (82%)" in text
    assert "postgres: Up (unhealthy)" in text
    assert "redis: Up" in text


@pytest.mark.parametrize(
    ("severity", "emoji"),
    [
        (SeverityLevel.LOW, "🟡"),
        (SeverityLevel.MEDIUM, "🟠"),
        (SeverityLevel.HIGH, "🔴"),
        (SeverityLevel.CRITICAL, "🚨"),
    ],
)
def test_emoji_follows_severity(severity: SeverityLevel, emoji: str) -> None:
    text = build_message(_context(), _triage(severity=severity))
    assert text.startswith(emoji)


def test_repeated_incident_preface() -> None:
    text = build_message(_context(occurrences_count=6), _triage(), repeated=True)
    assert text.startswith(
        "Повторение инцидента <code>backend_api</code> (случился 6 раз за последние 5 мин)"
    )


def test_repeated_preface_uses_the_configured_cooldown() -> None:
    text = build_message(
        _context(occurrences_count=4),
        _triage(),
        repeated=True,
        cooldown_sec=120,
    )
    assert "за последние 2 мин" in text
    assert "5 мин" not in text


def test_message_fits_telegram_limit() -> None:
    text = build_message(_context(), _triage(root_cause="A" * 20_000 + "<tag>"))
    assert len(text) <= TELEGRAM_LIMIT
    assert "<tag>" not in text
    assert _html_is_intact(text)


def test_long_message_drops_whole_blocks_without_breaking_tags() -> None:
    neighbors = [
        ContainerStatus(name=f"svc-{index}", status="Up", health="unhealthy", restart_count=index)
        for index in range(30)
    ]
    text = build_message(
        _context(neighbor_states=neighbors),
        _triage(
            root_cause="причина & причина " * 400 + "<>",
            summary="суть " * 400,
            blast_radius="радиус " * 400,
            mitigation_steps=[f"шаг {index} " + "x" * 180 for index in range(20)],
            suggested_commands=[f"docker logs svc-{index} && echo <tag>" for index in range(20)],
        ),
    )
    assert len(text) <= TELEGRAM_LIMIT
    assert "<tag>" not in text
    assert _html_is_intact(text)
    assert not re.search(r"&(?!(?:amp|lt|gt|quot);)", text)


def _html_is_intact(text: str) -> bool:
    if re.search(r"<[^>]*$", text):
        return False
    stack: list[str] = []
    for match in re.finditer(r"<(/?)([a-zA-Z]+)[^>]*>", text):
        closing, name = match.group(1), match.group(2)
        if closing:
            if not stack or stack[-1] != name:
                return False
            stack.pop()
        else:
            stack.append(name)
    return not stack


class _Response:
    def __init__(self) -> None:
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None


class _Http:
    def __init__(self) -> None:
        self.url = ""
        self.payload: dict = {}

    async def post(self, url: str, json: dict) -> _Response:
        self.url = url
        self.payload = json
        return _Response()

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_send_posts_html_to_telegram() -> None:
    from core.notifier import Notifier

    http = _Http()
    notifier = Notifier(
        Settings(openai_api_key="sk", telegram_bot_token="123:abc", telegram_chat_id="-100"),
        client=http,  # type: ignore[arg-type]
    )
    assert await notifier.send(_context(), _triage()) is True
    assert http.url == "https://api.telegram.org/bot123:abc/sendMessage"
    assert http.payload["chat_id"] == "-100"
    assert http.payload["parse_mode"] == "HTML"
    assert "CRITICAL INCIDENT" in http.payload["text"]


class _FlakyHttp:
    def __init__(self) -> None:
        self.calls = 0

    async def post(self, url: str, json: dict) -> _Response:
        self.calls += 1
        if self.calls < 3:
            raise httpx.ConnectError("connection reset")
        return _Response()

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_telegram_send_retries_before_giving_up() -> None:
    from core.notifier import Notifier

    http = _FlakyHttp()
    notifier = Notifier(
        Settings(openai_api_key="sk", telegram_bot_token="123:abc", telegram_chat_id="-100"),
        client=http,  # type: ignore[arg-type]
    )

    async def sleep(_delay: float) -> None:
        return None

    notifier._sleep = sleep
    assert await notifier.send(_context(), _triage()) is True
    assert http.calls == 3


class _DeadHttp:
    def __init__(self) -> None:
        self.calls = 0

    async def post(self, url: str, json: dict) -> _Response:
        self.calls += 1
        raise httpx.ConnectError("connection reset")

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_telegram_send_returns_false_when_retries_are_exhausted() -> None:
    from core.notifier import Notifier

    http = _DeadHttp()
    notifier = Notifier(
        Settings(openai_api_key="sk", telegram_bot_token="123:abc", telegram_chat_id="-100"),
        client=http,  # type: ignore[arg-type]
    )

    async def sleep(_delay: float) -> None:
        return None

    notifier._sleep = sleep
    assert await notifier.send(_context(), _triage()) is False
    assert http.calls == 3


def test_message_ends_with_the_incident_id() -> None:
    text = build_message(_context(), _triage())
    assert text.endswith("<code>inc-1</code>")
