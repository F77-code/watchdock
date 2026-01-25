"""Оркестрация сайдкара: Docker, debounce, снимок, LLM, Telegram."""

import asyncio
import logging
import signal
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from config import Settings
from core.buffer import RingBuffer
from core.deduplicator import Deduplicator, IncidentDraft
from core.detector import match_log
from core.docker_watcher import DockerWatcher
from core.llm_client import LLMClient
from core.notifier import Notifier
from core.sanitizer import sanitize
from core.severity import below_minimum
from core.snapshotter import Snapshotter
from schemas.incident import IncidentContext

logger = logging.getLogger(__name__)

_NEIGHBOR_LOG_LIMIT = 20
SHUTDOWN_BUDGET_SEC = 5.0


async def build_context(
    buffer: RingBuffer,
    snapshotter: Snapshotter,
    draft: IncidentDraft,
) -> IncidentContext:
    logs = [sanitize(line) for line in await buffer.snapshot(draft.container)]
    for name in await buffer.containers():
        if name == draft.container:
            continue
        matched = await buffer.snapshot_matching(name, match_log)
        logs.extend(sanitize(f"[{name}] {line}") for line in matched[-_NEIGHBOR_LOG_LIMIT:])
    host, neighbors = await snapshotter.capture(draft.container)
    return IncidentContext(
        incident_id=uuid.uuid4().hex[:12],
        timestamp=datetime.now(timezone.utc),
        failed_container=draft.container,
        trigger_type=draft.trigger_type,
        raw_logs=logs,
        host_metrics=host,
        neighbor_states=neighbors,
        occurrences_count=draft.occurrences,
    )


async def _dispatch(
    draft: IncidentDraft,
    buffer: RingBuffer,
    snapshotter: Snapshotter,
    llm: LLMClient,
    notifier: Notifier,
    settings: Settings,
) -> bool:
    try:
        context = await build_context(buffer, snapshotter, draft)
        triage = await llm.triage(context)
        if below_minimum(triage.severity, settings.min_severity):
            logger.info(
                "пропускаю %s: %s ниже порога %s",
                draft.container,
                triage.severity.value,
                settings.min_severity,
            )
            return True
        return bool(await notifier.send(context, triage, repeated=draft.repeated))
    except Exception:
        logger.exception("инцидент %s не доставлен", draft.container)
        return False


async def shutdown(
    watcher: DockerWatcher,
    watcher_task: asyncio.Task[None],
    deduplicator: Deduplicator,
    notifier: Notifier,
    llm: LLMClient,
    budget: float = SHUTDOWN_BUDGET_SEC,
) -> None:
    """Остановить приём, дослать открытый debounce и только потом закрыть клиентов."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    await watcher.stop()
    remaining = max(0.0, deadline - loop.time())
    try:
        await asyncio.wait_for(watcher_task, timeout=remaining)
    except TimeoutError:
        watcher_task.cancel()
        await asyncio.gather(watcher_task, return_exceptions=True)
    # Короткий запас, чтобы закрытие клиентов не съело дедлайн Docker.
    remaining = max(0.0, deadline - loop.time() - 0.25)
    await deduplicator.close(timeout=remaining)
    await notifier.close()
    await llm.close()


async def bounded_review(
    slots: asyncio.Semaphore,
    handler: Callable[[IncidentDraft], Awaitable[bool]],
    draft: IncidentDraft,
) -> bool:
    async with slots:
        return await handler(draft)


async def heartbeat(stop: asyncio.Event, interval: float) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            logger.info("sentinel is alive")
        else:
            return


def silence_http_client_logs() -> None:
    # httpx пишет URL запроса на DEBUG, а в нём токен бота.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


async def serve(settings: Settings) -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    silence_http_client_logs()
    buffer = RingBuffer(
        max_lines=settings.buffer_size_lines,
        max_bytes=settings.buffer_max_bytes,
        max_line_chars=settings.line_max_chars,
    )
    snapshotter = Snapshotter(settings)
    llm = LLMClient(settings)
    notifier = Notifier(settings)
    review_slots = asyncio.Semaphore(settings.review_concurrency)

    async def on_ready(draft: IncidentDraft) -> bool:
        return await bounded_review(
            review_slots,
            lambda draft: _dispatch(draft, buffer, snapshotter, llm, notifier, settings),
            draft,
        )

    deduplicator = Deduplicator(settings, on_ready)
    watcher = DockerWatcher(settings, buffer, deduplicator, snapshotter)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    watcher_task = asyncio.create_task(watcher.run(), name="docker-watcher")
    heartbeat_task = asyncio.create_task(heartbeat(stop, settings.heartbeat_sec), name="heartbeat")
    try:
        await stop.wait()
        logger.info("получен сигнал остановки")
    finally:
        heartbeat_task.cancel()
        await shutdown(watcher, watcher_task, deduplicator, notifier, llm)


def main() -> None:
    asyncio.run(serve(Settings()))


if __name__ == "__main__":
    main()
