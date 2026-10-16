from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

EventType = Literal["process", "file", "registry", "network", "powershell", "auth", "sysmon"]


class EventIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    event_type: EventType
    timestamp: datetime | None = None
    ip_address: str | None = None
    os_version: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    command_line: str | None = None
    parent_process: str | None = None
    file_path: str | None = None
    registry_key: str | None = None
    remote_address: str | None = None
    remote_port: int | None = None
    raw_username: str | None = None
    raw_sid: str | None = None
    raw_payload: dict[str, Any] | None = None


class CommandResult(BaseModel):
    status: Literal["done", "failed"]
    result: str | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=60)
    password: str = Field(min_length=8)
    role: Literal["administrator", "analyst"] = "analyst"
    email: str = ""


class EnrollIn(BaseModel):
    template: str = Field(min_length=4)


class TxCreate(BaseModel):
    purpose: Literal["response_action", "rule_change", "terminal", "backup_create", "backup_restore", "release_endpoint"]


class TxVerify(BaseModel):
    credential: str


class TicketTransition(BaseModel):
    status: Literal["under_investigation", "false_positive", "resolved", "closed"]


class AssignIn(BaseModel):
    user_id: str | None = None


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3)
    summary: str | None = None
    endpoint_id: str | None = None


class IncidentUpdate(BaseModel):
    status: Literal["investigating", "resolved", "closed"] | None = None
    notes: str | None = None
    assigned_to: str | None = None


class ResponseIn(BaseModel):
    action: str
    params: dict[str, Any] = {}


class RuleIn(BaseModel):
    name: str
    description: str | None = None
    event_type: EventType
    severity: Literal["low", "medium", "high", "critical"]
    mitre_technique: str | None = None
    confidence: float = Field(default=0.8, ge=0, le=1)
    logic: dict[str, Any]
    threshold_count: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=0, ge=0)


class RuleToggle(BaseModel):
    enabled: bool


class ToolRun(BaseModel):
    tool: str
    target: str
