"""Поток событий Docker и подписка на логи контейнеров текущего compose-проекта."""

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import aiodocker
from aiodocker.utils import clean_filters

from config import Settings
from core.buffer import RingBuffer
from core.deduplicator import Deduplicator
from core.detector import LOG_ERROR, OOM, UNHEALTHY, classify_action, match_log
from core.sanitizer import sanitize
from core.snapshotter import Snapshotter
from schemas.docker import DockerEvent

logger = logging.getLogger(__name__)

_COMPOSE_PROJECT = "com.docker.compose.project"
_LOG_RETRY_SEC = 1.0
_EVENT_NAMES = [
    "die",
    "oom",
    "restart",
    "start",
    "health_status",
    "health_status: unhealthy",
]


@dataclass(slots=True)
class ListedContainer:
    id: str
    name: str
    labels: dict[str, str]
    status: str = ""


class AiodockerSource:
    """Тонкая обёртка над aiodocker: сокет, события и follow-логи."""

    def __init__(self, settings: Settings) -> None:
        self.docker = aiodocker.Docker(url=settings.docker_host)
        self._settings = settings
        self._closed = False

    async def list_containers(self) -> list[ListedContainer]:
        listed = await self.docker.containers.list(
            all=True,
            filters=clean_filters(
                {"label": [f"{_COMPOSE_PROJECT}={self._settings.compose_project_name}"]}
            ),
        )
        found: list[ListedContainer] = []
        for item in listed:
            payload = item._container
            names = payload.get("Names") or []
            name = str(names[0]).lstrip("/") if names else item.id[:12]
            labels = {str(key): str(value) for key, value in (payload.get("Labels") or {}).items()}
            status = str(payload.get("Status") or payload.get("State") or "")
            found.append(ListedContainer(id=item.id, name=name, labels=labels, status=status))
        return found

    async def own_project(self, container_id: str) -> str | None:
        if not container_id:
            return None
        info = await self.docker.containers.container(container_id).show()
        labels = (info.get("Config") or {}).get("Labels") or {}
        project = labels.get(_COMPOSE_PROJECT)
        return str(project) if project else None

    async def events(self) -> AsyncIterator[dict]:
        filters = clean_filters(
            {
                "type": ["container"],
                "event": _EVENT_NAMES,
                "label": [f"{_COMPOSE_PROJECT}={self._settings.compose_project_name}"],
            }
        )
        subscriber = self.docker.events.subscribe(filters=filters)
        while not self._closed:
            raw = await subscriber.get()
            if raw is None:
                return
            if isinstance(raw.get("time"), datetime):
                raw["time"] = int(raw["time"].timestamp())
            yield raw

    async def logs(self, container_id: str) -> AsyncIterator[str]:
        container = self.docker.containers.container(container_id)
        async for chunk in container.log(stdout=True, stderr=True, follow=True, tail=0):
            if isinstance(chunk, bytes):
                yield chunk.decode("utf-8", "replace")
            else:
                yield str(chunk)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self.docker.events.stop()
        finally:
            await self.docker.close()


class DockerWatcher:
    def __init__(
        self,
        settings: Settings,
        buffer: RingBuffer,
        deduplicator: Deduplicator,
        snapshotter: Snapshotter | None = None,
        connect: Callable[[], Awaitable[AiodockerSource]] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._settings = settings
        self._buffer = buffer
        self._deduplicator = deduplicator
        self._snapshotter = snapshotter
        self._connect = connect or self._connect_default
        self._sleep = sleep or asyncio.sleep
        self._stop = asyncio.Event()
        self._source: AiodockerSource | None = None
        self._log_tasks: dict[str, asyncio.Task[None]] = {}
        self._retry_tasks: dict[str, asyncio.Task[None]] = {}
        self._name_of: dict[str, str] = {}
        self._id_of: dict[str, str] = {}
        self._partial: dict[str, str] = {}
        self._own_id = _read_own_id()

    async def run(self) -> None:
        delay = 1.0
        while not self._stop.is_set():
            started = asyncio.get_running_loop().time()
            try:
                source = await self._connect()
                await self._serve(source)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("поток Docker оборвался")
            if self._stop.is_set():
                break
            elapsed = asyncio.get_running_loop().time() - started
            if elapsed >= 30:
                delay = 1.0
            logger.warning("повторное подключение к Docker через %.0f с", delay)
            if await self._pause(delay):
                break
            if elapsed < 30:
                delay = min(delay * 2, 30.0)

    async def stop(self) -> None:
        self._stop.set()
        source = self._source
        if source is not None:
            await source.close()
        await self._cancel_logs()

    async def _pause(self, delay: float) -> bool:
        if self._sleep is asyncio.sleep:
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                return False
            return True
        await self._sleep(delay)
        return self._stop.is_set()

    async def _connect_default(self) -> AiodockerSource:
        return AiodockerSource(self._settings)

    async def _serve(self, source: AiodockerSource) -> None:
        self._source = source
        try:
            project = await self._resolve_project(source)
            if not project:
                logger.error(
                    "compose-проект не задан и не прочитан с контейнера %s",
                    self._own_id or "без id",
                )
                await self._stop.wait()
                return
            self._settings.compose_project_name = project
            docker = getattr(source, "docker", None)
            if self._snapshotter is not None and docker is not None:
                self._snapshotter.bind(docker)
            accepted: list[ListedContainer] = []
            for container in await source.list_containers():
                if not self._accept(container.name, container.id, container.labels):
                    continue
                accepted.append(container)
                logger.info(
                    "контейнер %s: логи и состояние (%s)",
                    container.name,
                    container.status or "статус неизвестен",
                )
                await self._track_logs(source, container.id, container.name)
            await self._forget_absent({item.id for item in accepted})
            logger.info("в проекте %s под наблюдением %s контейнер(ов)", project, len(accepted))
            async for raw in source.events():
                if self._stop.is_set():
                    break
                try:
                    await self._on_event(source, raw)
                except Exception:
                    logger.exception("не удалось обработать событие Docker")
        finally:
            if self._snapshotter is not None:
                self._snapshotter.bind(None)
            self._source = None
            await self._cancel_logs()
            await source.close()

    async def _on_event(self, source: AiodockerSource, raw: dict) -> None:
        event = DockerEvent.model_validate(raw)
        if event.type != "container":
            return
        if not event.belongs_to_project(self._settings.compose_project_name):
            return
        if not self._accept(event.container_name, event.container_id, event.actor.attributes):
            return
        action = event.action.lower()
        if action == "start":
            await self._track_logs(source, event.container_id, event.container_name)
            return
        if action == "restart":
            await self._deduplicator.note_restart(event.container_name)
            await self._track_logs(
                source,
                event.container_id,
                event.container_name,
                replace=True,
            )
            return
        trigger = classify_action(event.action, event.exit_code)
        if trigger is None:
            return
        if trigger == OOM:
            text = "oom"
        elif trigger == UNHEALTHY:
            text = event.action
        else:
            text = f"die exit={event.exit_code}"
        await self._deduplicator.submit(event.container_name, trigger, text)

    async def _track_logs(
        self,
        source: AiodockerSource,
        container_id: str,
        name: str,
        *,
        replace: bool = False,
    ) -> None:
        self._reap_finished()
        previous = self._id_of.get(name)
        if previous and previous != container_id:
            await self._cancel_log(previous)
        current = self._log_tasks.get(container_id)
        if current is not None and not current.done():
            if not replace:
                return
            await self._cancel_log(container_id)
        if self._stop.is_set():
            return
        self._drop_retry(container_id)
        task = asyncio.create_task(
            self._follow_logs(source, container_id, name),
            name=f"logs-{name}",
        )
        self._log_tasks[container_id] = task
        self._name_of[container_id] = name
        self._id_of[name] = container_id

    async def _follow_logs(self, source: AiodockerSource, container_id: str, name: str) -> None:
        try:
            async for chunk in source.logs(container_id):
                if self._stop.is_set():
                    return
                await self._consume_chunk(name, chunk)
            await self._flush_partial(name)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("поток логов %s оборвался, повторяю подписку", name, exc_info=True)
            await self._flush_partial(name)
            self._schedule_retry(source, container_id, name)

    def _schedule_retry(self, source: AiodockerSource, container_id: str, name: str) -> None:
        if self._stop.is_set():
            return
        current = self._retry_tasks.get(container_id)
        if current is not None and not current.done():
            return

        async def _again() -> None:
            try:
                await self._sleep(_LOG_RETRY_SEC)
                if self._stop.is_set():
                    return
                if not await self._still_listed(source, container_id):
                    return
                await self._track_logs(source, container_id, name, replace=True)
            except asyncio.CancelledError:
                raise

        self._retry_tasks[container_id] = asyncio.create_task(
            _again(),
            name=f"logs-retry-{name}",
        )

    async def _still_listed(self, source: AiodockerSource, container_id: str) -> bool:
        try:
            listed = await source.list_containers()
        except Exception:
            logger.warning("не удалось сверить %s со списком проекта", container_id, exc_info=True)
            return False
        return any(
            item.id == container_id and self._accept(item.name, item.id, item.labels)
            for item in listed
        )

    def _reap_finished(self) -> None:
        finished = [container_id for container_id, task in self._log_tasks.items() if task.done()]
        for container_id in finished:
            self._log_tasks.pop(container_id, None)
            name = self._name_of.pop(container_id, None)
            if name and self._id_of.get(name) == container_id:
                self._id_of.pop(name, None)

    async def _forget_absent(self, live_ids: set[str]) -> None:
        self._reap_finished()
        stale = [container_id for container_id in self._log_tasks if container_id not in live_ids]
        for container_id in stale:
            await self._cancel_log(container_id)

    async def _cancel_log(self, container_id: str) -> None:
        self._drop_retry(container_id)
        task = self._log_tasks.pop(container_id, None)
        name = self._name_of.pop(container_id, None)
        if name and self._id_of.get(name) == container_id:
            self._id_of.pop(name, None)
        if task is None or task.done():
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    def _drop_retry(self, container_id: str) -> None:
        retry = self._retry_tasks.get(container_id)
        if retry is None or retry is asyncio.current_task():
            return
        self._retry_tasks.pop(container_id, None)
        if not retry.done():
            retry.cancel()

    async def _flush_partial(self, name: str) -> None:
        pending = self._partial.pop(name, "")
        if pending.strip():
            await self._consume_line(name, pending)

    async def _consume_chunk(self, name: str, chunk: str) -> None:
        pending = self._partial.get(name, "") + chunk
        while "\n" in pending:
            line, pending = pending.split("\n", 1)
            await self._consume_line(name, line)
        self._partial[name] = pending[-8192:]

    async def _consume_line(self, name: str, line: str) -> None:
        cleaned = sanitize(line)
        if not cleaned:
            return
        await self._buffer.append(name, cleaned)
        if match_log(cleaned):
            await self._deduplicator.submit(name, LOG_ERROR, cleaned)

    async def _resolve_project(self, source: AiodockerSource) -> str:
        configured = self._settings.compose_project_name.strip()
        if configured:
            return configured
        discover = getattr(source, "own_project", None)
        if discover is None or not self._own_id:
            return ""
        try:
            found = await discover(self._own_id)
        except Exception:
            logger.exception("не удалось прочитать лейбл своего контейнера")
            return ""
        return str(found or "").strip()

    def _ignored_names(self) -> set[str]:
        names = {self._settings.self_container_name}
        for part in self._settings.ignored_containers.split(","):
            cleaned = part.strip()
            if cleaned:
                names.add(cleaned)
        return names

    def _accept(self, name: str, container_id: str, labels: dict[str, str]) -> bool:
        project = labels.get(_COMPOSE_PROJECT)
        if project != self._settings.compose_project_name:
            return False
        if name in self._ignored_names():
            return False
        if self._own_id and container_id.startswith(self._own_id):
            return False
        return True

    async def _cancel_logs(self) -> None:
        retries = list(self._retry_tasks.values())
        tasks = list(self._log_tasks.values())
        self._retry_tasks.clear()
        self._log_tasks.clear()
        self._name_of.clear()
        self._id_of.clear()
        for task in (*retries, *tasks):
            task.cancel()
        pending = [*retries, *tasks]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


def _read_own_id() -> str:
    try:
        return Path("/etc/hostname").read_text().strip()
    except OSError:
        return ""
