"""События Docker Engine API, которые приходят из потока /events."""

from pydantic import BaseModel, ConfigDict, Field


class DockerActor(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str = Field(default="", alias="ID")
    attributes: dict[str, str] = Field(default_factory=dict, alias="Attributes")


class DockerEvent(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: str = Field(alias="Type")
    action: str = Field(alias="Action")
    actor: DockerActor = Field(alias="Actor")
    time: int = 0

    @property
    def container_id(self) -> str:
        return self.actor.id

    @property
    def container_name(self) -> str:
        attrs = self.actor.attributes
        return attrs.get("name") or attrs.get("com.docker.compose.service") or self.actor.id[:12]

    @property
    def compose_project(self) -> str | None:
        return self.actor.attributes.get("com.docker.compose.project")

    @property
    def compose_service(self) -> str | None:
        return self.actor.attributes.get("com.docker.compose.service")

    @property
    def exit_code(self) -> int | None:
        raw = self.actor.attributes.get("exitCode")
        if raw is None or raw == "":
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    def belongs_to_project(self, project: str) -> bool:
        return self.compose_project == project
