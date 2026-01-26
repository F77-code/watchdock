from pathlib import Path

import pytest
from pydantic import ValidationError

from config import Settings


def test_image_healthcheck_watches_the_heartbeat_file() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    assert "HEALTHCHECK" in dockerfile
    assert "HEARTBEAT_PATH" in dockerfile
    assert "start-period=600s" in dockerfile
    assert "*2" in dockerfile


def test_compose_does_not_give_watchdock_the_daemon_socket() -> None:
    compose = (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text()
    proxy, watchdock = compose.split("\n  watchdock:\n", 1)
    assert "tecnativa/docker-socket-proxy:0.4.2" in proxy
    assert "CONTAINERS: 1" in proxy
    assert "EVENTS: 1" in proxy
    assert "POST: 0" in proxy
    assert "/var/run/docker.sock" not in watchdock
    assert "tcp://docker-proxy:2375" in watchdock
    assert watchdock.count("no-new-privileges:true") == 1
    assert "cap_drop:" in watchdock
    assert "ALL" in watchdock


def test_settings_read_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100")
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "billing")
    monkeypatch.setenv("BUFFER_SIZE_LINES", "40")
    monkeypatch.setenv("DEBOUNCE_WINDOW_SEC", "2")
    monkeypatch.setenv("COOLDOWN_PERIOD_SEC", "60")

    settings = Settings()

    assert settings.compose_project_name == "billing"
    assert settings.buffer_size_lines == 40
    assert settings.debounce_window_sec == 2
    assert settings.cooldown_period_sec == 60
    assert settings.openai_model == "gpt-5-nano"
    assert settings.buffer_max_bytes == 500 * 1024
    assert settings.line_max_chars == 2048


def test_settings_reject_a_huge_buffer_or_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100")
    monkeypatch.setenv("BUFFER_SIZE_LINES", "100000000")
    with pytest.raises(ValidationError):
        Settings()
    monkeypatch.setenv("BUFFER_SIZE_LINES", "200")
    monkeypatch.setenv("LLM_MAX_LOG_CHARS", "100000000")
    with pytest.raises(ValidationError):
        Settings()


def test_settings_reject_blank_secrets_and_unknown_names() -> None:
    with pytest.raises(ValidationError):
        Settings(openai_api_key="", telegram_bot_token="token", telegram_chat_id="1")
    with pytest.raises(ValidationError):
        Settings(openai_api_key="sk", telegram_bot_token="token", telegram_chat_id="1", min_severity="NOPE")
    with pytest.raises(ValidationError):
        Settings(openai_api_key="sk", telegram_bot_token="token", telegram_chat_id="1", log_level="LOUD")


def test_settings_require_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    with pytest.raises(ValidationError):
        Settings()
