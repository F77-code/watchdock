"""Настройки сайдкара. Публичные переменные совпадают с фрагментом compose в ТЗ."""

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    docker_host: str = "unix:///var/run/docker.sock"
    # Пусто: при старте проект читается с лейбла собственного контейнера.
    compose_project_name: str = ""
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-5-nano"
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    log_level: str = "INFO"
    buffer_size_lines: int = Field(default=200, gt=0, le=10_000)
    debounce_window_sec: float = Field(default=5, gt=0)
    cooldown_period_sec: float = Field(default=300, gt=0)

    # Внутренние пределы. В compose их нет: значения зафиксированы ТЗ.
    buffer_max_bytes: int = Field(default=500 * 1024, gt=0, le=8 * 1024 * 1024)
    line_max_chars: int = Field(default=2048, gt=0, le=16_384)
    llm_timeout_sec: float = Field(default=10, gt=0)
    llm_max_log_lines: int = Field(default=80, gt=0, le=500)
    llm_max_log_chars: int = Field(default=24_000, gt=0, le=100_000)
    restart_loop_threshold: int = Field(default=3, gt=0)
    restart_loop_window_sec: float = Field(default=120, gt=0)
    restart_loop_cooldown_sec: float = Field(default=900, gt=0)
    host_proc_path: str = "/host/proc"
    host_sys_path: str = "/host/sys"
    host_disk_path: str = "/"
    self_container_name: str = "watchdock"
    ignored_containers: str = ""
    min_severity: str = "LOW"
    heartbeat_sec: float = Field(default=300, gt=0)
    heartbeat_path: str = "/tmp/watchdock-heartbeat"
    max_signatures: int = Field(default=4096, gt=0, le=100_000)
    review_concurrency: int = Field(default=2, gt=0, le=8)

    @field_validator("openai_api_key", "telegram_bot_token", "telegram_chat_id")
    @classmethod
    def _secret_not_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("секрет не может быть пустым")
        return cleaned

    @field_validator("min_severity")
    @classmethod
    def _known_severity(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned not in _SEVERITIES:
            raise ValueError("неизвестный MIN_SEVERITY")
        return cleaned

    @field_validator("log_level")
    @classmethod
    def _known_log_level(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if cleaned not in _LOG_LEVELS:
            raise ValueError("неизвестный LOG_LEVEL")
        return cleaned
