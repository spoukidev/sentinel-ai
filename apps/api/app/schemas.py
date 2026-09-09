import json
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, IPvAnyAddress, field_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]
Role = Literal["administrator", "analyst", "viewer"]
Source = Literal["windows", "linux", "web", "firewall", "dns", "cloud"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Login(Strict):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class Register(Login):
    name: str = Field(min_length=2, max_length=120)
    organization: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)


class AssetInput(Strict):
    hostname: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9._-]+$")
    ip_address: IPvAnyAddress
    operating_system: str = Field(default="Unknown", max_length=80)
    asset_type: Literal["workstation", "server", "network", "cloud", "application"] = "workstation"
    owner: str = Field(default="Unassigned", max_length=120)
    department: str = Field(default="Security", max_length=80)
    criticality: Severity = "medium"
    status: Literal["active", "inactive"] = "active"
    tags: list[str] = Field(default_factory=list, max_length=20)


class EventInput(Strict):
    timestamp: datetime
    source: Source
    category: str = Field(max_length=40)
    event_type: str = Field(max_length=80)
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    username: str = Field(default="", max_length=120)
    hostname: str = Field(min_length=1, max_length=120)
    action: str = Field(max_length=80)
    outcome: str = Field(max_length=30)
    raw_event: str = Field(default="", max_length=8192)
    parsed_metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def utc_timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        if value > datetime.now(timezone.utc):
            raise ValueError("future events are not accepted")
        return value.astimezone(timezone.utc)

    @field_validator("parsed_metadata")
    @classmethod
    def bounded_metadata(cls, value):
        if len(json.dumps(value)) > 8192:
            raise ValueError("metadata exceeds 8192 characters")
        return value


class Batch(Strict):
    events: list[EventInput] = Field(min_length=1, max_length=100)


class Condition(Strict):
    field: Literal[
        "action",
        "outcome",
        "event_type",
        "username",
        "raw_event",
        "meta.bytes",
        "meta.new_country",
        "meta.travel_signal",
        "meta.domain",
    ]
    op: Literal["eq", "contains", "gte"]
    value: str | int | float | bool


class RuleInput(Strict):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(max_length=2000)
    enabled: bool = True
    severity: Severity
    source: Source
    conditions: list[Condition] = Field(min_length=1, max_length=10)
    threshold: int = Field(ge=1, le=100)
    window_seconds: int = Field(ge=1, le=86400)
    tactic: str = Field(max_length=80)
    technique: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    tags: list[str] = Field(default_factory=list, max_length=20)
    recommended_response: str = Field(max_length=2000)


class AlertUpdate(Strict):
    status: Literal["new", "investigating", "resolved", "false_positive"]
    false_positive_reason: str = Field(default="", max_length=2000)
    assignee: str | None = None


class NoteInput(Strict):
    body: str = Field(min_length=1, max_length=4000)


class RoleInput(Strict):
    role: Role


class CsvInput(Strict):
    content: str = Field(max_length=100000)
