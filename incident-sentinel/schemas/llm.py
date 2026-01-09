from enum import Enum

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentClassification(str, Enum):
    INFRASTRUCTURE_OOM = "INFRASTRUCTURE_OOM"
    DATABASE_CONNECTIVITY = "DATABASE_CONNECTIVITY"
    EXTERNAL_API_TIMEOUT = "EXTERNAL_API_TIMEOUT"
    APPLICATION_BUG = "APPLICATION_BUG"
    CONFIGURATION_SYNTAX = "CONFIGURATION_SYNTAX"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    UNKNOWN = "UNKNOWN"


class LLMIncidentTriage(BaseModel):
    summary: str = Field(description="Краткая суть инцидента в одно емкое предложение")
    severity: SeverityLevel = Field(description="Уровень критичности проблемы")
    classification: IncidentClassification = Field(description="Техническая категория сбоя")
    root_cause: str = Field(description="Анализ первопричины на основе логов и метрик системы")
    blast_radius: str = Field(description="Масштаб влияния: затронут отдельный воркер, функционал или весь сервис")
    mitigation_steps: list[str] = Field(description="Пошаговые действия для быстрого восстановления (quick fix)")
    suggested_commands: list[str] = Field(description="Точные bash/docker команды для проверки и решения проблемы")
