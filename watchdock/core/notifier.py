"""HTML-отчёт в Telegram. Длина сообщения укладывается в лимит Bot API."""

import asyncio
import html
import logging
from datetime import timezone

import httpx

from config import Settings
from schemas.incident import ContainerStatus, IncidentContext
from schemas.llm import LLMIncidentTriage, SeverityLevel

logger = logging.getLogger(__name__)

TELEGRAM_LIMIT = 4096
# Паузы по Retry-After не должны растягивать отправку на минуты.
_RETRY_BUDGET_SEC = 8.0

_EMOJI = {
    SeverityLevel.LOW: "🟡",
    SeverityLevel.MEDIUM: "🟠",
    SeverityLevel.HIGH: "🔴",
    SeverityLevel.CRITICAL: "🚨",
}


class Notifier:
    def __init__(self, settings: Settings, client: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._client = client or httpx.AsyncClient(timeout=10)
        self._owns_client = client is None
        self._attempts = 3
        self._sleep = asyncio.sleep
        self._failed_sends = 0

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def send(
        self,
        context: IncidentContext,
        triage: LLMIncidentTriage,
        *,
        repeated: bool = False,
    ) -> bool:
        text = build_message(
            context,
            triage,
            repeated=repeated,
            cooldown_sec=self._settings.cooldown_period_sec,
        )
        url = f"https://api.telegram.org/bot{self._settings.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self._settings.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        delay = 0.5
        spent = 0.0
        last_error: Exception | None = None
        for attempt in range(self._attempts):
            try:
                response = await self._client.post(url, json=payload)
                response.raise_for_status()
                return True
            except httpx.HTTPStatusError as exc:
                last_error = exc
                wait = delay
                if exc.response.status_code == 429:
                    hinted = _retry_after_seconds(exc.response)
                    if hinted is not None:
                        wait = hinted
                paused = await self._backoff(attempt, wait, spent)
                if paused is None:
                    break
                spent += paused
                delay *= 2
            except httpx.HTTPError as exc:
                last_error = exc
                paused = await self._backoff(attempt, delay, spent)
                if paused is None:
                    break
                spent += paused
                delay *= 2
        self._failed_sends += 1
        logger.error("Telegram не принял отчёт по %s: %s", context.failed_container, last_error)
        return False

    def failed_send_count(self) -> int:
        return self._failed_sends

    async def _backoff(self, attempt: int, wait: float, spent: float) -> float | None:
        if attempt + 1 == self._attempts:
            return None
        remaining = _RETRY_BUDGET_SEC - spent
        if remaining <= 0:
            return None
        pause = min(max(wait, 0.0), remaining)
        if pause > 0:
            await self._sleep(pause)
        return pause


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None or raw.strip() == "":
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


def format_cooldown(seconds: float) -> str:
    whole = max(0, int(seconds))
    if whole > 0 and whole % 3600 == 0:
        hours = whole // 3600
        return f"{hours} ч"
    if whole > 0 and whole % 60 == 0:
        return f"{whole // 60} мин"
    return f"{whole} с"


def _shorten(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rstrip()
    return f"{cut or text[:limit]}…"


def build_message(
    context: IncidentContext,
    triage: LLMIncidentTriage,
    *,
    repeated: bool = False,
    cooldown_sec: float = 300,
) -> str:
    summary = triage.summary
    blast = triage.blast_radius
    root = triage.root_cause
    steps = list(triage.mitigation_steps)
    commands = list(triage.suggested_commands)
    show_neighbors = True

    def render() -> str:
        return _render(
            context,
            triage,
            summary,
            blast,
            root,
            steps,
            commands,
            repeated,
            cooldown_sec,
            show_neighbors,
        )

    text = render()
    for _ in range(80):
        if len(text) <= TELEGRAM_LIMIT:
            return text
        if show_neighbors:
            show_neighbors = False
        elif commands:
            commands.pop()
        elif len(steps) > 1:
            steps.pop()
        elif len(root) > 80:
            root = _shorten(root, max(80, len(root) // 2))
        elif len(blast) > 60:
            blast = _shorten(blast, max(60, len(blast) // 2))
        elif len(summary) > 60:
            summary = _shorten(summary, max(60, len(summary) // 2))
        elif steps:
            steps.pop()
        elif len(root) > 1:
            root = _shorten(root, max(1, len(root) // 2))
        elif len(blast) > 1:
            blast = _shorten(blast, max(1, len(blast) // 2))
        elif len(summary) > 1:
            summary = _shorten(summary, max(1, len(summary) // 2))
        else:
            break
        text = render()
    return text


def _render(
    context: IncidentContext,
    triage: LLMIncidentTriage,
    summary: str,
    blast: str,
    root: str,
    steps: list[str],
    commands: list[str],
    repeated: bool,
    cooldown_sec: float,
    show_neighbors: bool,
) -> str:
    emoji = _EMOJI[triage.severity]
    stamp = context.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    container = html.escape(context.failed_container)
    host = context.host_metrics
    load = ", ".join(f"{value:.2f}" for value in host.load_avg)
    failed = next(
        (item for item in context.neighbor_states if item.name == context.failed_container),
        None,
    )
    memory = _memory_line(failed)
    restarts = failed.restart_count if failed is not None else 0
    if show_neighbors:
        neighbors = ", ".join(
            f"<code>{html.escape(_neighbor_line(item))}</code>" for item in context.neighbor_states
        ) or "<code>нет данных</code>"
        neighbor_line = f"• Статус соседей: {neighbors}\n"
    else:
        neighbor_line = ""
    step_lines = "\n".join(
        f"{index}. {html.escape(step)}" for index, step in enumerate(steps, start=1)
    ) or "1. Проверить логи контейнера."
    command_lines = "\n".join(f"<code>{html.escape(command)}</code>" for command in commands)
    preface = ""
    if repeated:
        preface = (
            f"Повторение инцидента <code>{container}</code> "
            f"(случился {context.occurrences_count} раз за последние {format_cooldown(cooldown_sec)})\n\n"
        )
    return (
        f"{preface}"
        f"{emoji} <b>{triage.severity.value} INCIDENT: [{container}] · {html.escape(context.trigger_type)}</b>\n"
        f"<i>{stamp}</i>\n\n"
        f"📌 <b>Суть:</b> {html.escape(summary)}\n"
        f"🏷 <b>Тип:</b> <code>{html.escape(triage.classification.value)}</code>\n"
        f"⚡️ <b>Критичность:</b> {emoji} <code>{triage.severity.value}</code> "
        f"(Случилось раз: {context.occurrences_count})\n\n"
        f"💥 <b>Влияние:</b> {html.escape(blast)}\n\n"
        f"🔍 <b>Первопричина:</b>\n"
        f"{html.escape(root)}\n\n"
        f"📊 <b>Срез системы:</b>\n"
        f"• Хост: LA <code>[{load}]</code> | RAM: <code>{host.ram_used_pct:.0f}%</code> "
        f"| Диск: <code>{host.disk_free_gb:.1f} GB свободно</code>\n"
        f"• Контейнер: RAM <code>{memory}</code> | Restarts: <code>{restarts}</code>\n"
        f"{neighbor_line}\n"
        f"🛠 <b>Шаги решения:</b>\n"
        f"{step_lines}\n\n"
        f"💻 <b>Команды диагностики:</b>\n"
        f"<i>Это текст модели, он не проверен. Не запускайте команды вслепую.</i>\n"
        f"{command_lines}\n\n"
        f"<code>{html.escape(context.incident_id)}</code>"
    )


def _memory_line(container: ContainerStatus | None) -> str:
    if container is None or container.memory_usage_mb is None:
        return "н/д"
    usage = _fmt_mb(container.memory_usage_mb)
    if container.memory_limit_mb is None or container.memory_limit_mb <= 0:
        return f"{usage}MB"
    percent = container.memory_usage_mb / container.memory_limit_mb * 100
    return f"{usage}MB / {_fmt_mb(container.memory_limit_mb)}MB ({percent:.0f}%)"


def _fmt_mb(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.1f}"


def _neighbor_line(item: ContainerStatus) -> str:
    if item.health:
        return f"{item.name}: {item.status} ({item.health})"
    return f"{item.name}: {item.status}"
