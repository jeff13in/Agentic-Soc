"""Pydantic models shared by the agent, API, evals and training code."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class VerdictLabel(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_ESCALATION = "needs_escalation"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class Alert(BaseModel):
    """A normalized alert produced by a detection rule firing on one event."""

    alert_id: str
    rule_id: str
    rule_name: str
    rule_severity: Severity
    rule_tags: list[str] = Field(default_factory=list)
    timestamp: datetime
    host: str
    user: str | None = None
    event_id: int
    event_uid: str
    process_guid: str | None = None
    image: str | None = None
    parent_image: str | None = None
    command_line: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)

    def agent_view(self) -> dict[str, Any]:
        """The alert as shown to the model. Never includes labels."""
        return self.model_dump(mode="json")


class LabelledAlert(BaseModel):
    alert: Alert
    label: VerdictLabel
    techniques: list[str] = Field(default_factory=list)
    scenario: str | None = None
    split: str = "dev"


class Evidence(BaseModel):
    tool: str
    finding: str = Field(min_length=3)
    event_ref: str | None = None


class Verdict(BaseModel):
    alert_id: str
    verdict: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    attack_techniques: list[str] = Field(default_factory=list)
    summary: str = Field(min_length=10)
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

    @field_validator("attack_techniques")
    @classmethod
    def _technique_ids(cls, v: list[str]) -> list[str]:
        import re

        bad = [t for t in v if not re.fullmatch(r"T\d{4}(\.\d{3})?", t)]
        if bad:
            raise ValueError(f"invalid ATT&CK technique id(s): {bad}")
        return v

    @field_validator("evidence")
    @classmethod
    def _needs_evidence(cls, v: list[Evidence], info) -> list[Evidence]:
        verdict = info.data.get("verdict")
        if verdict in (VerdictLabel.TRUE_POSITIVE, VerdictLabel.FALSE_POSITIVE) and not v:
            raise ValueError("a true_positive/false_positive verdict must cite at least one evidence entry")
        return v


class ToolCallRecord(BaseModel):
    step: int
    call_id: str
    name: str
    arguments: dict[str, Any]
    result: Any = None
    is_error: bool = False
    error: str | None = None
    latency_ms: float = 0.0


class ModelTurnRecord(BaseModel):
    step: int
    text: str = ""
    tool_calls: list[str] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    latency_ms: float = 0.0
    stop_reason: str | None = None
    model: str | None = None


class Trace(BaseModel):
    trace_id: str
    alert_id: str
    run_id: str | None = None
    backend: str
    model: str
    prompt_version: str
    prompt_hash: str
    defenses: list[str] = Field(default_factory=list)
    started_at: datetime
    latency_s: float = 0.0
    status: str = "ok"  # ok | repaired | invalid_verdict | budget_exhausted | refusal | error
    verdict: Verdict | None = None
    verifier: dict[str, Any] | None = None
    turns: list[ModelTurnRecord] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    error: str | None = None
    final_note_step: int | None = None  # turn after which the loop appended its "budget used up" note

    @property
    def final_label(self) -> VerdictLabel:
        return self.verdict.verdict if self.verdict else VerdictLabel.NEEDS_ESCALATION
