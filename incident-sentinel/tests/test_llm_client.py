import json

import httpx
import pytest
from openai import APITimeoutError, RateLimitError

from config import Settings
from core.llm_client import LLMClient, fallback_triage
from schemas.incident import HostSnapshot, IncidentContext
from schemas.llm import IncidentClassification, LLMIncidentTriage, SeverityLevel


def _settings() -> Settings:
    return Settings(
        openai_api_key="sk-test",
        telegram_bot_token="token",
        telegram_chat_id="1",
        llm_timeout_sec=10,
        llm_max_log_lines=3,
        llm_max_log_chars=500,
    )


def _context() -> IncidentContext:
    return IncidentContext(
        incident_id="inc-1",
        timestamp="2026-09-24T14:15:30Z",
        failed_container="backend_api",
        trigger_type="LOG_ERROR",
        raw_logs=[
            "INFO up",
            'FATAL password="super-secret"',
            "line-3",
            "line-4",
        ],
        host_metrics=HostSnapshot(
            load_avg=[1.0, 0.5, 0.2],
            ram_used_pct=40,
            ram_available_mb=512,
            disk_free_gb=10,
        ),
        neighbor_states=[],
    )


class _Message:
    def __init__(self, parsed: LLMIncidentTriage | None) -> None:
        self.parsed = parsed


class _Choice:
    def __init__(self, parsed: LLMIncidentTriage | None) -> None:
        self.message = _Message(parsed)


class _Completion:
    def __init__(self, parsed: LLMIncidentTriage | None) -> None:
        self.choices = [_Choice(parsed)]


class _Completions:
    def __init__(self, result: _Completion | None = None, error: Exception | None = None) -> None:
        self._result = result
        self._error = error
        self.kwargs: dict | None = None

    async def parse(self, **kwargs):
        self.kwargs = kwargs
        if self._error is not None:
            raise self._error
        return self._result


class _Chat:
    def __init__(self, completions: _Completions) -> None:
        self.completions = completions


class _Client:
    def __init__(self, completions: _Completions) -> None:
        self.chat = _Chat(completions)

    async def close(self) -> None:
        return None


def _triage() -> LLMIncidentTriage:
    return LLMIncidentTriage(
        summary="Пул соединений исчерпан",
        severity=SeverityLevel.CRITICAL,
        classification=IncidentClassification.DATABASE_CONNECTIVITY,
        root_cause="FATAL: remaining connection slots",
        blast_radius="Авторизация недоступна",
        mitigation_steps=["Проверить pg_stat_activity"],
        suggested_commands=["docker compose ps"],
    )


@pytest.mark.asyncio
async def test_parse_returns_structured_triage_and_sanitizes_prompt() -> None:
    completions = _Completions(_Completion(_triage()))
    client = LLMClient(_settings(), client=_Client(completions))  # type: ignore[arg-type]
    result = await client.triage(_context())

    assert result.classification is IncidentClassification.DATABASE_CONNECTIVITY
    assert completions.kwargs is not None
    assert completions.kwargs["response_format"] is LLMIncidentTriage
    assert "Principal SRE" in completions.kwargs["messages"][0]["content"]
    payload = json.loads(completions.kwargs["messages"][1]["content"])
    assert "super-secret" not in json.dumps(payload)
    assert payload["raw_logs"][0].startswith("... пропущено")
    assert 'password: "[REDACTED]"' in payload["raw_logs"][-3]


def _api_errors() -> list[Exception]:
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx.Response(429, request=request)
    return [
        RateLimitError("slow down", response=response, body=None),
        APITimeoutError(request),
        TimeoutError(),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("error", _api_errors())
async def test_fallback_on_llm_errors(error: Exception) -> None:
    completions = _Completions(error=error)
    client = LLMClient(_settings(), client=_Client(completions))  # type: ignore[arg-type]
    result = await client.triage(_context())
    assert result.summary == "Автоматический триаж недоступен (LLM Timeout/Error)"
    assert result.severity is SeverityLevel.HIGH
    assert result.suggested_commands == ["docker logs --tail 100 backend_api"]
    assert result.root_cause.startswith("Сырые логи зафиксировали ошибку: ")


def test_fallback_without_logs() -> None:
    context = _context()
    context.raw_logs = []
    result = fallback_triage(context)
    assert "логов нет" in result.root_cause
