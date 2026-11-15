"""ICS-side typed model of a container unit (what the deployment engine puts in `podman.deploy_unit` params). It mirrors the node agent's
closed schema (`ou_agent/guestspec.py`) so plans are rejected at plan time; the agent validates again independently (tests keep the two
in step). There is deliberately no field for arbitrary arguments, host paths, privileged mode, devices or sockets."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Port(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bind: str = Field(pattern=r"^\d{1,3}(\.\d{1,3}){3}$")
    host: int = Field(ge=1024, le=65535)
    container: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"


class Volume(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}[a-z0-9]$")   # a named volume of this component, never a host path
    path: str
    read_only: bool = False


class SecretRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,40}$")
    env: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")


class UnitSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = Field(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{1,30}[a-z0-9]$")
    type: Literal["container", "container-hostnet"] = "container"
    image: str                                   # registry/repo@sha256:<digest>
    env: dict[str, str] = {}
    ports: list[Port] = []
    volumes: list[Volume] = []
    secrets: list[SecretRef] = []
    user: str | None = None
    read_only: bool = True
    memory_mib: int = Field(512, ge=16, le=65536)

    def params(self) -> dict:
        d = self.model_dump(mode="json", exclude_none=True)
        return d


def pull_params(image: str) -> dict:
    return {"image": image}
