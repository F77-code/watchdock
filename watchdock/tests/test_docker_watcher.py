import asyncio
from collections.abc import AsyncIterator

import pytest

from config import Settings
from core.buffer import RingBuffer
from core.detector import CRASH_EXIT, LOG_ERROR, OOM
from core.docker_watcher import DockerWatcher, ListedContainer


def _settings() -> Settings:
    return Settings(
        openai_api_key="sk-test",
        telegram_bot_token="token",
        telegram_chat_id="1",
        compose_project_name="billing",
    )


class _Recorder:
    def __init__(self) -> None:
        self.submitted: list[tuple[str, str, str]] = []
        self.restarts: list[str] = []

    async def submit(self, container: str, trigger_type: str, error_text: str) -> None:
        self.submitted.append((container, trigger_type, error_text))

    async def note_restart(self, container: str) -> None:
        self.restarts.append(container)


class _Source:
    def __init__(self, logs: dict[str, list[str]], events: list[dict]) -> None:
        self._logs = logs
        self._events = events
        self._closed = False

    async def list_containers(self) -> list[ListedContainer]:
        return [
            ListedContainer(
                id="cid-api",
                name="backend_api",
                labels={"com.docker.compose.project": "billing"},
            ),
            ListedContainer(
                id="cid-other",
                name="foreign",
                labels={"com.docker.compose.project": "other"},
            ),
            ListedContainer(
                id="cid-self",
                name="watchdock",
                labels={"com.docker.compose.project": "billing"},
            ),
        ]

    async def events(self) -> AsyncIterator[dict]:
        await asyncio.sleep(0)
        for raw in self._events:
            yield raw
            await asyncio.sleep(0)
        while not self._closed:
            await asyncio.sleep(0.01)

    async def logs(self, container_id: str) -> AsyncIterator[str]:
        for line in self._logs.get(container_id, []):
            yield line
        while not self._closed:
            await asyncio.sleep(0.01)

    async def close(self) -> None:
        self._closed = True


def _event(name: str, action: str, container_id: str, **attributes: str) -> dict:
    attrs = {
        "name": name,
        "com.docker.compose.project": "billing",
        "com.docker.compose.service": name,
    }
    attrs.update(attributes)
    return {
        "Type": "container",
        "Action": action,
        "Actor": {"ID": container_id, "Attributes": attrs},
        "time": 1700000000,
    }


@pytest.mark.asyncio
async def test_follows_logs_and_container_events() -> None:
    source = _Source(
        logs={"cid-api": ['FATAL password="super-secret"\n']},
        events=[
            _event("backend_api", "oom", "cid-api"),
            _event("backend_api", "die", "cid-api", exitCode="0"),
            _event("backend_api", "die", "cid-api", exitCode="137"),
            _event("foreign", "die", "cid-foreign", exitCode="1", **{
                "com.docker.compose.project": "other",
            }),
            _event("backend_api", "restart", "cid-api"),
            _event("watchdock", "die", "cid-self", exitCode="1"),
        ],
    )

    async def connect() -> _Source:
        return source

    recorder = _Recorder()
    buffer = RingBuffer(max_lines=20, max_bytes=10_000, max_line_chars=200)
    watcher = DockerWatcher(
        _settings(),
        buffer,
        recorder,  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
    )
    task = asyncio.create_task(watcher.run())
    await asyncio.sleep(0.05)

    stored = await buffer.snapshot("backend_api")
    assert stored
    assert "super-secret" not in stored[0]
    assert "FATAL" in stored[0]
    assert await buffer.snapshot("watchdock") == []

    kinds = [(item[0], item[1]) for item in recorder.submitted]
    assert ("backend_api", LOG_ERROR) in kinds
    assert ("backend_api", OOM) in kinds
    assert ("backend_api", CRASH_EXIT) in kinds
    assert not any(item[0] == "foreign" for item in recorder.submitted)
    assert not any(item[0] == "watchdock" for item in recorder.submitted)
    assert recorder.submitted.count(("backend_api", CRASH_EXIT, "die exit=137")) == 1
    assert recorder.restarts == ["backend_api"]

    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_socket_backoff_doubles_until_stop() -> None:
    attempts = 0

    async def connect() -> _Source:
        nonlocal attempts
        attempts += 1
        raise ConnectionError("docker socket down")

    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)
        if len(sleeps) == 3:
            watcher._stop.set()

    watcher = DockerWatcher(
        _settings(),
        RingBuffer(max_lines=10, max_bytes=1000, max_line_chars=100),
        _Recorder(),  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
        sleep=sleep,
    )
    await watcher.run()
    assert attempts == 3
    assert sleeps == [1.0, 2.0, 4.0]


class _FiniteLogs:
    def __init__(self) -> None:
        self._closed = False

    async def list_containers(self) -> list[ListedContainer]:
        return [
            ListedContainer(
                id="cid-api",
                name="backend_api",
                labels={"com.docker.compose.project": "billing"},
            )
        ]

    async def events(self):
        while not self._closed:
            await asyncio.sleep(0.01)
        if False:
            yield {}

    async def logs(self, container_id: str):
        yield "FATAL unterminated"

    async def close(self) -> None:
        self._closed = True


@pytest.mark.asyncio
async def test_unterminated_log_line_still_opens_an_incident() -> None:
    source = _FiniteLogs()

    async def connect():
        return source

    recorder = _Recorder()
    buffer = RingBuffer(max_lines=10, max_bytes=5000, max_line_chars=200)
    watcher = DockerWatcher(
        _settings(),
        buffer,
        recorder,  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
    )
    task = asyncio.create_task(watcher.run())
    await asyncio.sleep(0.08)
    stored = await buffer.snapshot("backend_api")
    assert stored and "FATAL unterminated" in stored[0]
    assert ("backend_api", LOG_ERROR) in [(item[0], item[1]) for item in recorder.submitted]
    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_ignored_container_names_are_not_followed() -> None:
    source = _Source(logs={"cid-helper": ["FATAL from helper\n"]}, events=[])

    async def connect():
        return source

    settings = _settings()
    settings.ignored_containers = "metrics-helper"
    source_containers = await source.list_containers()
    source_containers.append(
        ListedContainer(
            id="cid-helper",
            name="metrics-helper",
            labels={"com.docker.compose.project": "billing"},
        )
    )

    class _Listing(_Source):
        async def list_containers(self) -> list[ListedContainer]:
            return source_containers

    listing = _Listing(logs={"cid-helper": ["FATAL from helper\n"]}, events=[])

    async def connect_listing():
        return listing

    recorder = _Recorder()
    buffer = RingBuffer(max_lines=10, max_bytes=5000, max_line_chars=200)
    watcher = DockerWatcher(
        settings,
        buffer,
        recorder,  # type: ignore[arg-type]
        connect=connect_listing,  # type: ignore[arg-type]
    )
    task = asyncio.create_task(watcher.run())
    await asyncio.sleep(0.05)
    assert await buffer.snapshot("metrics-helper") == []
    assert recorder.submitted == []
    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


class _ThisCompose(_Source):
    def __init__(self) -> None:
        super().__init__(
            logs={
                "cid-api": ["FATAL api\n"],
                "cid-db": ["FATAL db\n"],
                "cid-other": ["FATAL foreign\n"],
            },
            events=[],
        )
        self.asked: list[str] = []

    async def own_project(self, container_id: str) -> str:
        self.asked.append(container_id)
        return "watchdock"

    async def list_containers(self) -> list[ListedContainer]:
        return [
            ListedContainer(
                id="cid-api",
                name="api",
                labels={"com.docker.compose.project": "watchdock"},
                status="Up 2 hours",
            ),
            ListedContainer(
                id="cid-db",
                name="db",
                labels={"com.docker.compose.project": "watchdock"},
                status="Up 2 hours (healthy)",
            ),
            ListedContainer(
                id="cid-self",
                name="watchdock",
                labels={"com.docker.compose.project": "watchdock"},
                status="Up",
            ),
            ListedContainer(
                id="cid-other",
                name="foreign",
                labels={"com.docker.compose.project": "other"},
                status="Up",
            ),
        ]


@pytest.mark.asyncio
async def test_empty_project_follows_every_container_of_this_compose() -> None:
    source = _ThisCompose()

    async def connect() -> _ThisCompose:
        return source

    settings = _settings()
    settings.compose_project_name = ""
    recorder = _Recorder()
    buffer = RingBuffer(max_lines=20, max_bytes=10_000, max_line_chars=200)
    watcher = DockerWatcher(
        settings,
        buffer,
        recorder,  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
    )
    watcher._own_id = "selfcid"
    task = asyncio.create_task(watcher.run())
    await asyncio.sleep(0.05)

    assert source.asked == ["selfcid"]
    assert settings.compose_project_name == "watchdock"
    assert await buffer.snapshot("api")
    assert await buffer.snapshot("db")
    assert await buffer.snapshot("foreign") == []
    assert await buffer.snapshot("watchdock") == []
    names = {item[0] for item in recorder.submitted}
    assert names == {"api", "db"}

    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


async def _wait_for(predicate, timeout: float = 1.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("условие не выполнилось")


class _ReplacingLogs:
    """Первый follow висит, пока его не отменят. Второй отдаёт новую строку."""

    def __init__(self, events: list[dict]) -> None:
        self._events = events
        self._closed = False
        self.generations: list[int] = []
        self.old_cancelled = asyncio.Event()
        self.first_entered = asyncio.Event()
        self._generation = 0

    async def list_containers(self) -> list[ListedContainer]:
        return [
            ListedContainer(
                id="cid-api",
                name="backend_api",
                labels={"com.docker.compose.project": "billing"},
            )
        ]

    async def events(self):
        await self.first_entered.wait()
        for raw in self._events:
            yield raw
            await asyncio.sleep(0)
        while not self._closed:
            await asyncio.sleep(0.01)

    async def logs(self, container_id: str):
        generation = self._generation
        self._generation += 1
        self.generations.append(generation)
        if generation == 0:
            self.first_entered.set()
            try:
                while not self._closed:
                    await asyncio.sleep(0.01)
                    yield ""
            except asyncio.CancelledError:
                self.old_cancelled.set()
                raise
        if not self.old_cancelled.is_set():
            raise AssertionError("новый follow стартовал до отмены старого")
        yield "FATAL after switch\n"
        while not self._closed:
            await asyncio.sleep(0.01)

    async def close(self) -> None:
        self._closed = True
        self.first_entered.set()


@pytest.mark.asyncio
async def test_restart_replaces_a_live_follow() -> None:
    source = _ReplacingLogs([_event("backend_api", "restart", "cid-api")])

    async def connect():
        return source

    recorder = _Recorder()
    buffer = RingBuffer(max_lines=20, max_bytes=10_000, max_line_chars=200)
    watcher = DockerWatcher(
        _settings(),
        buffer,
        recorder,  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
    )
    task = asyncio.create_task(watcher.run())
    await _wait_for(lambda: _has_line(buffer, "FATAL after switch"))
    assert source.generations == [0, 1]
    assert source.old_cancelled.is_set()
    assert recorder.restarts == ["backend_api"]
    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_new_container_id_replaces_the_old_follow() -> None:
    source = _ReplacingLogs([_event("backend_api", "start", "cid-api-2")])

    async def connect():
        return source

    async def logs(self, container_id: str):
        generation = self._generation
        self._generation += 1
        self.generations.append((generation, container_id))
        if generation == 0:
            self.first_entered.set()
            try:
                while not self._closed:
                    await asyncio.sleep(0.01)
                    yield ""
            except asyncio.CancelledError:
                self.old_cancelled.set()
                raise
        if not self.old_cancelled.is_set():
            raise AssertionError("новый follow стартовал до отмены старого")
        yield "FATAL recreated\n"
        while not self._closed:
            await asyncio.sleep(0.01)

    source.logs = logs.__get__(source, _ReplacingLogs)  # type: ignore[method-assign]
    buffer = RingBuffer(max_lines=20, max_bytes=10_000, max_line_chars=200)
    watcher = DockerWatcher(
        _settings(),
        buffer,
        _Recorder(),  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
    )
    task = asyncio.create_task(watcher.run())
    await _wait_for(lambda: _has_line(buffer, "FATAL recreated"))
    assert source.generations == [(0, "cid-api"), (1, "cid-api-2")]
    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


class _BreakingLogs:
    def __init__(self) -> None:
        self._closed = False
        self.calls = 0

    async def list_containers(self) -> list[ListedContainer]:
        return [
            ListedContainer(
                id="cid-api",
                name="backend_api",
                labels={"com.docker.compose.project": "billing"},
            )
        ]

    async def events(self):
        while not self._closed:
            await asyncio.sleep(0.01)
        if False:
            yield {}

    async def logs(self, container_id: str):
        self.calls += 1
        if self.calls == 1:
            yield "FATAL first\n"
            raise ConnectionError("stream died")
        yield "FATAL second\n"
        while not self._closed:
            await asyncio.sleep(0.01)

    async def close(self) -> None:
        self._closed = True


@pytest.mark.asyncio
async def test_broken_follow_resubscribes_without_a_start_event() -> None:
    source = _BreakingLogs()

    async def connect():
        return source

    async def sleep(_delay: float) -> None:
        return None

    buffer = RingBuffer(max_lines=20, max_bytes=10_000, max_line_chars=200)
    watcher = DockerWatcher(
        _settings(),
        buffer,
        _Recorder(),  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
        sleep=sleep,
    )
    task = asyncio.create_task(watcher.run())
    await _wait_for(lambda: _has_line(buffer, "FATAL second"))
    assert source.calls >= 2
    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_listing_drops_a_buffer_for_a_container_that_left() -> None:
    source = _Source(logs={"cid-api": []}, events=[])

    async def connect():
        return source

    buffer = RingBuffer(max_lines=10, max_bytes=5000, max_line_chars=200)
    await buffer.append("ghost", "old line")
    watcher = DockerWatcher(
        _settings(),
        buffer,
        _Recorder(),  # type: ignore[arg-type]
        connect=connect,  # type: ignore[arg-type]
    )
    task = asyncio.create_task(watcher.run())

    async def ghost_gone() -> bool:
        return "ghost" not in await buffer.containers()

    await _wait_for(ghost_gone)
    assert await buffer.snapshot("backend_api") == []
    await watcher.stop()
    await asyncio.wait_for(task, timeout=1)


async def _has_line(buffer: RingBuffer, needle: str) -> bool:
    stored = await buffer.snapshot("backend_api")
    return any(needle in line for line in stored)
