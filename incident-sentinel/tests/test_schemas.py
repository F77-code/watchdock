from datetime import datetime, timezone

from schemas.docker import DockerEvent
from schemas.incident import ContainerStatus, HostSnapshot, IncidentContext
from schemas.llm import IncidentClassification, LLMIncidentTriage, SeverityLevel


def test_docker_event_reads_compose_attributes() -> None:
    event = DockerEvent.model_validate(
        {
            "Type": "container",
            "Action": "die",
            "Actor": {
                "ID": "abc123",
                "Attributes": {
                    "name": "backend_api",
                    "exitCode": "1",
                    "com.docker.compose.project": "billing",
                    "com.docker.compose.service": "backend",
                },
            },
            "time": 1700000000,
        }
    )

    assert event.container_name == "backend_api"
    assert event.exit_code == 1
    assert event.belongs_to_project("billing")
    assert event.compose_service == "backend"


def test_incident_context_defaults() -> None:
    context = IncidentContext(
        incident_id="inc-1",
        timestamp=datetime(2026, 9, 24, 14, 15, 30, tzinfo=timezone.utc),
        failed_container="backend_api",
        trigger_type="LOG_ERROR",
        raw_logs=["boom"],
        host_metrics=HostSnapshot(
            load_avg=[1.0, 0.5, 0.2],
            ram_used_pct=40.0,
            ram_available_mb=512,
            disk_free_gb=20.0,
        ),
        neighbor_states=[
            ContainerStatus(name="postgres", status="running", restart_count=0, health="unhealthy")
        ],
    )
    assert context.occurrences_count == 1
    assert context.neighbor_states[0].health == "unhealthy"


def test_llm_triage_enums() -> None:
    triage = LLMIncidentTriage(
        summary="Пул соединений исчерпан",
        severity=SeverityLevel.CRITICAL,
        classification=IncidentClassification.DATABASE_CONNECTIVITY,
        root_cause="FATAL: remaining connection slots",
        blast_radius="Авторизация недоступна",
        mitigation_steps=["Проверить pg_stat_activity"],
        suggested_commands=["docker compose restart backend_api"],
    )
    assert triage.severity is SeverityLevel.CRITICAL
    assert triage.classification.value == "DATABASE_CONNECTIVITY"
