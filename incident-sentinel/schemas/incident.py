from datetime import datetime

from pydantic import BaseModel


class HostSnapshot(BaseModel):
    load_avg: list[float]
    ram_used_pct: float
    ram_available_mb: int
    disk_free_gb: float


class ContainerStatus(BaseModel):
    name: str
    status: str
    health: str | None = None
    restart_count: int
    memory_usage_mb: float | None = None
    memory_limit_mb: float | None = None


class IncidentContext(BaseModel):
    incident_id: str
    timestamp: datetime
    failed_container: str
    trigger_type: str  # LOG_ERROR, OOM, CRASH_EXIT, UNHEALTHY, STUCK_IN_RESTART_LOOP
    raw_logs: list[str]
    host_metrics: HostSnapshot
    neighbor_states: list[ContainerStatus]
    occurrences_count: int = 1
