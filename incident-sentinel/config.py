"""Настройки сайдкара. Публичные переменные совпадают с фрагментом compose в ТЗ."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    docker_host: str = "unix:///var/run/docker.sock"
    compose_project_name: str = "my_app"
    openai_api_key: str
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    telegram_bot_token: str
    telegram_chat_id: str
    log_level: str = "INFO"
    buffer_size_lines: int = Field(default=200, gt=0)
    debounce_window_sec: float = Field(default=5, gt=0)
    cooldown_period_sec: float = Field(default=300, gt=0)

    # Внутренние пределы. В compose их нет: значения зафиксированы ТЗ.
    buffer_max_bytes: int = Field(default=500 * 1024, gt=0)
    line_max_chars: int = Field(default=2048, gt=0)
    llm_timeout_sec: float = Field(default=10, gt=0)
    llm_max_log_lines: int = Field(default=80, gt=0)
    llm_max_log_chars: int = Field(default=24_000, gt=0)
    restart_loop_threshold: int = Field(default=3, gt=0)
    restart_loop_window_sec: float = Field(default=120, gt=0)
    restart_loop_cooldown_sec: float = Field(default=900, gt=0)
    host_proc_path: str = "/host/proc"
    host_sys_path: str = "/host/sys"
    host_disk_path: str = "/"
    self_container_name: str = "incident_sentinel"
    ignored_containers: str = ""
    min_severity: str = "LOW"
