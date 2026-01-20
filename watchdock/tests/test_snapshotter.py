from pathlib import Path

import pytest

from config import Settings
from core.snapshotter import (
    Snapshotter,
    cgroup_memory_files,
    parse_loadavg,
    parse_meminfo,
    read_cgroup_memory,
    read_host_metrics,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        openai_api_key="sk-test",
        telegram_bot_token="token",
        telegram_chat_id="1",
        compose_project_name="billing",
        host_proc_path=str(tmp_path / "proc"),
        host_sys_path=str(tmp_path / "sys"),
    )


def test_parse_host_files(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("4.12 2.50 1.80 1/200 10\n")
    (proc / "meminfo").write_text("MemTotal:       2048000 kB\nMemAvailable:    512000 kB\n")

    assert parse_loadavg((proc / "loadavg").read_text()) == [4.12, 2.50, 1.80]
    assert parse_meminfo((proc / "meminfo").read_text()) == (75.0, 500)

    host = read_host_metrics(proc)
    assert host.load_avg == [4.12, 2.50, 1.80]
    assert host.ram_used_pct == 75.0
    assert host.ram_available_mb == 500
    assert host.disk_free_gb > 0


def test_cgroup_v2_memory(tmp_path: Path) -> None:
    base = tmp_path / "sys" / "fs" / "cgroup" / "docker" / "abc"
    base.mkdir(parents=True)
    (base / "memory.current").write_text("104857600\n")
    (base / "memory.max").write_text("max\n")

    files = cgroup_memory_files(tmp_path / "sys", "0::/docker/abc\n")
    assert files is not None
    assert files[0].name == "memory.current"
    usage, limit = read_cgroup_memory(tmp_path / "sys", "0::/docker/abc\n")
    assert usage == 100.0
    assert limit is None


class _Container:
    def __init__(self, name: str, status: str, inspect: dict, stats: list[dict]) -> None:
        self.id = f"id-{name}"
        self._container = {"Names": [f"/{name}"], "Status": status, "State": "running"}
        self._inspect = inspect
        self._stats = stats

    async def show(self) -> dict:
        return self._inspect

    async def stats(self, stream: bool = False) -> list[dict]:
        assert stream is False
        return self._stats


class _Docker:
    def __init__(self, containers: list[_Container]) -> None:
        self.containers = self
        self._containers = containers

    async def list(self, **kwargs) -> list[_Container]:
        assert "filters" in kwargs
        return self._containers


@pytest.mark.asyncio
async def test_capture_sorts_unhealthy_neighbors_and_reads_stats(tmp_path: Path) -> None:
    api = _Container(
        "backend_api",
        "Restarting (1) 2 seconds ago",
        {
            "RestartCount": 4,
            "State": {"Status": "restarting", "Pid": 0},
        },
        [{"memory_stats": {"usage": 220200960, "limit": 268435456}}],
    )
    postgres = _Container(
        "postgres",
        "Up 2 hours",
        {"RestartCount": 0, "State": {"Status": "running", "Health": {"Status": "unhealthy"}}},
        [],
    )
    redis = _Container(
        "redis",
        "Up 3 hours",
        {"RestartCount": 1, "State": {"Status": "running", "Health": {"Status": "healthy"}}},
        [],
    )
    sentinel = _Container(
        "watchdock",
        "Up",
        {"RestartCount": 0, "State": {"Status": "running"}},
        [],
    )
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("0.10 0.20 0.30 1/1 1\n")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")

    snapshotter = Snapshotter(_settings(tmp_path))
    snapshotter.bind(_Docker([redis, api, postgres, sentinel]))  # type: ignore[arg-type]
    host, neighbors = await snapshotter.capture("backend_api")

    assert host.ram_used_pct == 75.0
    assert [item.name for item in neighbors] == ["postgres", "backend_api", "redis"]
    failed = next(item for item in neighbors if item.name == "backend_api")
    assert failed.restart_count == 4
    assert failed.memory_usage_mb == 210.0
    assert failed.memory_limit_mb == 256.0
    assert neighbors[0].health == "unhealthy"
    assert neighbors[2].memory_usage_mb is None


@pytest.mark.asyncio
async def test_capture_uses_configured_disk_path(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "loadavg").write_text("0.1 0.1 0.1 1/1 1\n")
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 500 kB\n")
    settings = _settings(tmp_path)
    settings.host_disk_path = str(tmp_path / "missing-mount")
    snapshotter = Snapshotter(settings)
    host, _neighbors = await snapshotter.capture("backend_api")
    assert host.disk_free_gb == 0.0
