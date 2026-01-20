"""Снимок хоста и контейнеров проекта в момент, когда debounce уже собрал логи."""

import asyncio
import logging
import os
from pathlib import Path

import aiodocker
from aiodocker.utils import clean_filters

from config import Settings
from schemas.incident import ContainerStatus, HostSnapshot

logger = logging.getLogger(__name__)

_COMPOSE_PROJECT = "com.docker.compose.project"
_NO_LIMIT = 10**15


def parse_loadavg(text: str) -> list[float]:
    parts = text.split()
    if len(parts) < 3:
        return [0.0, 0.0, 0.0]
    try:
        return [float(parts[0]), float(parts[1]), float(parts[2])]
    except ValueError:
        return [0.0, 0.0, 0.0]


def parse_meminfo(text: str) -> tuple[float, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        token = raw.strip().split()
        if not token:
            continue
        try:
            values[key] = int(token[0])
        except ValueError:
            continue
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    if total <= 0:
        return 0.0, 0
    used_pct = (total - available) / total * 100
    return round(used_pct, 2), available // 1024


def disk_free_gb(path: str = "/") -> float:
    try:
        stats = os.statvfs(path)
    except OSError:
        return 0.0
    return round(stats.f_bavail * stats.f_frsize / (1024**3), 2)


def read_host_metrics(proc_path: Path, disk_path: str = "/") -> HostSnapshot:
    load = [0.0, 0.0, 0.0]
    ram_used_pct = 0.0
    ram_available_mb = 0
    try:
        load = parse_loadavg((proc_path / "loadavg").read_text())
    except OSError:
        logger.warning("не удалось прочитать %s/loadavg", proc_path)
    try:
        ram_used_pct, ram_available_mb = parse_meminfo((proc_path / "meminfo").read_text())
    except OSError:
        logger.warning("не удалось прочитать %s/meminfo", proc_path)
    return HostSnapshot(
        load_avg=load,
        ram_used_pct=ram_used_pct,
        ram_available_mb=ram_available_mb,
        disk_free_gb=disk_free_gb(disk_path),
    )


def cgroup_memory_files(sys_path: Path, cgroup_text: str) -> tuple[Path, Path] | None:
    for line in cgroup_text.splitlines():
        parts = line.strip().split(":")
        if len(parts) < 3:
            continue
        controllers, relative = parts[1], parts[2].lstrip("/")
        if not relative:
            continue
        if controllers == "":
            base = sys_path / "fs" / "cgroup" / relative
            return base / "memory.current", base / "memory.max"
        if "memory" in controllers.split(","):
            base = sys_path / "fs" / "cgroup" / "memory" / relative
            return base / "memory.usage_in_bytes", base / "memory.limit_in_bytes"
    return None


def read_cgroup_memory(sys_path: Path, cgroup_text: str) -> tuple[float | None, float | None]:
    files = cgroup_memory_files(sys_path, cgroup_text)
    if files is None:
        return None, None
    usage_path, limit_path = files
    try:
        usage = int(usage_path.read_text().strip())
    except (OSError, ValueError):
        return None, None
    limit: int | None
    try:
        raw_limit = limit_path.read_text().strip()
        parsed = None if raw_limit == "max" else int(raw_limit)
        limit = parsed if parsed is not None and 0 < parsed < _NO_LIMIT else None
    except (OSError, ValueError):
        limit = None
    return _to_mb(usage), None if limit is None else _to_mb(limit)


def _to_mb(value: int | float) -> float:
    return round(value / (1024 * 1024), 1)


def _anomaly_rank(item: ContainerStatus) -> tuple[int, str]:
    text = f"{item.status} {item.health or ''}".lower()
    if "unhealthy" in text:
        return (0, item.name)
    if any(token in text for token in ("restart", "dead", "exited")):
        return (1, item.name)
    return (2, item.name)


class Snapshotter:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._docker: aiodocker.Docker | None = None

    def bind(self, docker: aiodocker.Docker | None) -> None:
        self._docker = docker

    async def capture(self, failed_container: str) -> tuple[HostSnapshot, list[ContainerStatus]]:
        host = await asyncio.to_thread(
            read_host_metrics,
            Path(self._settings.host_proc_path),
            self._settings.host_disk_path,
        )
        neighbors = await self._containers(failed_container)
        neighbors.sort(key=_anomaly_rank)
        return host, neighbors

    async def _containers(self, failed_container: str) -> list[ContainerStatus]:
        docker = self._docker
        if docker is None:
            return []
        try:
            listed = await docker.containers.list(
                all=True,
                filters=clean_filters(
                    {
                        "label": [
                            f"{_COMPOSE_PROJECT}={self._settings.compose_project_name}"
                        ]
                    }
                ),
            )
        except Exception:
            logger.exception("не удалось получить список контейнеров")
            return []

        results = await asyncio.gather(
            *(self._describe(container, failed_container) for container in listed)
        )
        return [item for item in results if item is not None]

    async def _describe(self, container, failed_container: str) -> ContainerStatus | None:
        payload = container._container
        names = payload.get("Names") or []
        name = str(names[0]).lstrip("/") if names else str(payload.get("Name", "")).lstrip("/")
        if not name or name == self._settings.self_container_name:
            return None
        list_status = str(payload.get("Status") or payload.get("State") or "unknown")
        try:
            inspected = await container.show()
        except Exception:
            logger.warning("inspect не удался для %s", name, exc_info=True)
            return ContainerStatus(name=name, status=list_status, restart_count=0)

        state = inspected.get("State") or {}
        health = (state.get("Health") or {}).get("Status")
        usage_mb = None
        limit_mb = None
        if name == failed_container:
            usage_mb, limit_mb = await self._memory(container, inspected)
        return ContainerStatus(
            name=name,
            status=list_status,
            health=health,
            restart_count=int(inspected.get("RestartCount") or 0),
            memory_usage_mb=usage_mb,
            memory_limit_mb=limit_mb,
        )

    async def _memory(self, container, inspected: dict) -> tuple[float | None, float | None]:
        try:
            samples = await container.stats(stream=False)
        except Exception:
            logger.warning("docker stats недоступен для %s", container.id, exc_info=True)
            samples = []
        if samples:
            memory = (samples[-1] or {}).get("memory_stats") or {}
            usage = memory.get("usage")
            limit = memory.get("limit")
            if isinstance(usage, (int, float)):
                limit_mb = None
                if isinstance(limit, (int, float)) and 0 < limit < _NO_LIMIT:
                    limit_mb = _to_mb(limit)
                return _to_mb(usage), limit_mb
        return self._memory_from_cgroup(inspected)

    def _memory_from_cgroup(self, inspected: dict) -> tuple[float | None, float | None]:
        pid = (inspected.get("State") or {}).get("Pid")
        if not pid:
            return None, None
        cgroup_path = Path(self._settings.host_proc_path) / str(pid) / "cgroup"
        try:
            text = cgroup_path.read_text()
        except OSError:
            return None, None
        return read_cgroup_memory(Path(self._settings.host_sys_path), text)
