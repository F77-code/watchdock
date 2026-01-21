"""Сигнатура ошибки, окно debounce и кулдаун повторных алертов."""

import asyncio
import hashlib
import logging
import re
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from config import Settings
from core.detector import CRASH_EXIT, OOM, STUCK_IN_RESTART_LOOP

logger = logging.getLogger(__name__)

# Демон почти сразу после oom шлёт die 137. Вторая карточка в этом окне не нужна.
_OOM_PAIR_WINDOW_SEC = 15.0

_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?Z?")
_HEX = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)


def normalize(text: str) -> str:
    text = _UUID.sub("<UUID>", text)
    text = _IP.sub("<IP>", text)
    text = _TIMESTAMP.sub("<TIMESTAMP>", text)
    text = _HEX.sub("<HEX>", text)
    return text


def signature_hash(container_name: str, error_trace: str) -> str:
    payload = container_name + normalize(error_trace)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class IncidentDraft:
    container: str
    trigger_type: str
    signature: str
    error_text: str
    occurrences: int
    repeated: bool


@dataclass(slots=True)
class _SignatureState:
    occurrences: int = 0
    cooldown_until: float = 0.0
    waiting: bool = False
    container: str = ""
    trigger_type: str = ""
    error_text: str = ""


class Deduplicator:
    def __init__(
        self,
        settings: Settings,
        on_ready: Callable[[IncidentDraft], Awaitable[bool]],
    ) -> None:
        self._settings = settings
        self._on_ready = on_ready
        self._states: dict[str, _SignatureState] = {}
        self._restarts: dict[str, deque[float]] = {}
        self._restart_cooldown_until: dict[str, float] = {}
        self._oom_until: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()

    async def submit(self, container: str, trigger_type: str, error_text: str) -> None:
        now = time.monotonic()
        digest = signature_hash(container, error_text or trigger_type)
        async with self._lock:
            if trigger_type == OOM:
                self._oom_until[container] = now + _OOM_PAIR_WINDOW_SEC
            if (
                trigger_type == CRASH_EXIT
                and now < self._restart_cooldown_until.get(container, 0.0)
            ):
                return
            if (
                trigger_type == CRASH_EXIT
                and _is_oom_kill(error_text)
                and now < self._oom_until.get(container, 0.0)
            ):
                return
            state = self._states.get(digest)
            if state is None:
                state = _SignatureState()
                self._states[digest] = state
            if state.waiting or now < state.cooldown_until:
                state.occurrences += 1
                return
            carried = state.occurrences
            state.occurrences = 0
            state.waiting = True
            state.container = container
            state.trigger_type = trigger_type
            state.error_text = error_text
            task = asyncio.create_task(self._flush_later(digest, carried))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def note_restart(self, container: str) -> None:
        now = time.monotonic()
        triggered = False
        async with self._lock:
            if now < self._restart_cooldown_until.get(container, 0.0):
                return
            times = self._restarts.setdefault(container, deque())
            times.append(now)
            window = self._settings.restart_loop_window_sec
            while times and now - times[0] > window:
                times.popleft()
            if len(times) > self._settings.restart_loop_threshold:
                self._restart_cooldown_until[container] = (
                    now + self._settings.restart_loop_cooldown_sec
                )
                times.clear()
                triggered = True
        if triggered:
            await self.submit(container, STUCK_IN_RESTART_LOOP, STUCK_IN_RESTART_LOOP)

    async def close(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _flush_later(self, digest: str, carried: int) -> None:
        await asyncio.sleep(self._settings.debounce_window_sec)
        async with self._lock:
            state = self._states[digest]
            extra = state.occurrences
            state.occurrences = 0
            draft = IncidentDraft(
                container=state.container,
                trigger_type=state.trigger_type,
                signature=digest,
                error_text=state.error_text,
                occurrences=carried + extra + 1,
                repeated=carried > 0,
            )
        delivered = False
        try:
            delivered = bool(await self._on_ready(draft))
        except asyncio.CancelledError:
            await self._release(digest, delivered=False)
            raise
        except Exception:
            logger.exception("разбор %s не завершился", draft.container)
        await self._release(digest, delivered=delivered)

    async def _release(self, digest: str, *, delivered: bool) -> None:
        async with self._lock:
            state = self._states.get(digest)
            if state is None:
                return
            state.waiting = False
            if delivered:
                state.cooldown_until = time.monotonic() + self._settings.cooldown_period_sec


def _is_oom_kill(error_text: str) -> bool:
    return "137" in error_text
