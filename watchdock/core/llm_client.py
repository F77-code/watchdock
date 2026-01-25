"""Триаж инцидента через OpenAI Structured Outputs и аварийный отчёт без модели."""

import asyncio
import json
import logging

from openai import AsyncOpenAI

from config import Settings
from core.sanitizer import sanitize
from core.severity import ensure_high
from schemas.incident import IncidentContext
from schemas.llm import IncidentClassification, LLMIncidentTriage, SeverityLevel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Ты — Principal SRE и инцидент-координатор в распределенных Docker-системах.
Твоя задача — мгновенно локализовать причину падения контейнера или критической ошибки на основе логов и метрик хоста.

Правила:
1. Анализируй метрики хоста (Load Average, Memory, Disk). Если RAM хоста > 95% или у контейнера OOM — приоритет инфраструктурной причине.
2. Проверяй состояние соседних сервисов. Если упал backend, а postgres в статусе restarting/unhealthy — фиксируй первопричину в базе данных.
3. Ответ должен быть предельно конкретным: называй упавший сервис, файл, функцию, SQL-запрос или нехватку ресурса. Никакой воды.
4. В suggested_commands предоставляй реальные команды docker, docker compose, df, free, journalctl.
"""


class LLMClient:
    def __init__(self, settings: Settings, client: AsyncOpenAI | None = None) -> None:
        self._settings = settings
        self._client = client or AsyncOpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            timeout=settings.llm_timeout_sec,
        )

    async def close(self) -> None:
        await self._client.close()

    async def triage(self, context: IncidentContext) -> LLMIncidentTriage:
        try:
            # В актуальном SDK structured outputs живут в chat.completions.parse.
            completion = await asyncio.wait_for(
                self._client.chat.completions.parse(
                    model=self._settings.openai_model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": self._user_payload(context)},
                    ],
                    response_format=LLMIncidentTriage,
                ),
                timeout=self._settings.llm_timeout_sec,
            )
            parsed = completion.choices[0].message.parsed
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("триаж LLM недоступен: %s", exc)
            return apply_context_floor(fallback_triage(context), context)
        if parsed is None:
            logger.warning("модель не вернула структурированный ответ")
            return apply_context_floor(fallback_triage(context), context)
        return apply_context_floor(parsed, context)

    def _user_payload(self, context: IncidentContext) -> str:
        logs = [sanitize(line) for line in context.raw_logs]
        limit = self._settings.llm_max_log_lines
        if len(logs) > limit:
            omitted = len(logs) - limit
            logs = [f"... пропущено {omitted} строк ...", *logs[-limit:]]
        text = "\n".join(logs)
        if len(text) > self._settings.llm_max_log_chars:
            text = text[-self._settings.llm_max_log_chars :]
        payload = context.model_dump(mode="json")
        payload["raw_logs"] = text.splitlines() if text else []
        return json.dumps(payload, ensure_ascii=False)


_EXCERPT_CHARS = 180


def _safe_excerpt(line: str) -> str:
    cleaned = sanitize(line)
    if len(cleaned) <= _EXCERPT_CHARS:
        return cleaned
    return cleaned[:_EXCERPT_CHARS].rstrip() + "…"


def fallback_triage(context: IncidentContext) -> LLMIncidentTriage:
    last = _safe_excerpt(context.raw_logs[-1]) if context.raw_logs else "логов нет"
    container = context.failed_container
    return LLMIncidentTriage(
        summary="Автоматический триаж недоступен (LLM Timeout/Error)",
        severity=SeverityLevel.HIGH,
        classification=IncidentClassification.UNKNOWN,
        root_cause="Сырые логи зафиксировали ошибку: " + last,
        blast_radius="Масштаб не оценён: автоматический триаж недоступен",
        mitigation_steps=[f"Проверить логи вручную: docker logs --tail 100 {container}"],
        suggested_commands=[f"docker logs --tail 100 {container}"],
    )


def _context_is_serious(context: IncidentContext) -> bool:
    if context.trigger_type in {"OOM", "STUCK_IN_RESTART_LOOP"}:
        return True
    if context.host_metrics.ram_used_pct >= 95:
        return True
    for neighbor in context.neighbor_states:
        text = f"{neighbor.status} {neighbor.health or ''}".lower()
        if "unhealthy" in text or "restart" in text:
            return True
    return False


def apply_context_floor(triage: LLMIncidentTriage, context: IncidentContext) -> LLMIncidentTriage:
    if not _context_is_serious(context):
        return triage
    raised = ensure_high(triage.severity)
    if raised is triage.severity:
        return triage
    return triage.model_copy(update={"severity": raised})
