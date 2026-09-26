from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class LocationCreate(BaseModel):
    code: str = Field(min_length=2, max_length=64)
    building: str = Field(min_length=1, max_length=100)
    room: str = Field(min_length=1, max_length=100)
    cabinet: str = Field(min_length=1, max_length=100)
    shelf: str = Field(min_length=1, max_length=100)
    sensitivity: Literal["normal", "restricted", "critical"] = "normal"
    capacity_units: int = Field(gt=0, le=1_000_000)


class BatchCreate(BaseModel):
    intake_code: str = Field(min_length=3, max_length=64)
    project_code: str = Field(min_length=2, max_length=64)
    expected_count: int = Field(gt=0, le=100_000)


class DossierCreate(BaseModel):
    dossier_code: str = Field(min_length=3, max_length=100)
    intake_id: int = Field(gt=0)
    disclosure_event_id: int | None = Field(default=None, gt=0)
    asset_type: str = Field(min_length=1, max_length=100)
    quantity: float = Field(gt=0)
    unit: str = Field(min_length=1, max_length=20)
    vault_id: int | None = Field(default=None, gt=0)


class CopyIssueChild(BaseModel):
    dossier_code: str = Field(min_length=3, max_length=100)
    quantity: float = Field(gt=0)
    vault_id: int | None = Field(default=None, gt=0)


class CopyIssueRequest(BaseModel):
    operation_code: str | None = Field(default=None, max_length=64)
    requested_quantity: float = Field(gt=0)
    loss_quantity: float = Field(default=0, ge=0)
    children: list[CopyIssueChild] = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=500)


class DisclosureUseCreate(BaseModel):
    recipient_code: str = Field(min_length=2, max_length=100)
    quantity: float = Field(gt=0)
    idempotency_key: str = Field(min_length=4, max_length=100)
    note: str = Field(default="", max_length=500)


class LoanCreate(BaseModel):
    access_code: str | None = Field(default=None, max_length=64)
    dossier_id: int = Field(gt=0)
    requester_user_id: int = Field(gt=0)
    quantity: float = Field(gt=0)
    due_at: str = Field(min_length=10, max_length=40)


class LoanReturn(BaseModel):
    quantity: float = Field(gt=0)
    note: str = Field(default="", max_length=500)


class ApprovalCreate(BaseModel):
    request_code: str | None = Field(default=None, max_length=64)
    action_type: Literal["access_loan", "disposal", "vault_reveal", "inventory_review_adjustment"]
    resource_type: str = Field(min_length=2, max_length=50)
    resource_id: int = Field(gt=0)
    payload: dict[str, Any] = Field(default_factory=dict)
    expires_at: str | None = None


class ApprovalDecision(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=500)


class IncidentReportCreate(BaseModel):
    case_code: str | None = Field(default=None, max_length=64)
    clue_key: str | None = Field(default=None, max_length=200)
    dossier_id: int | None = Field(default=None, gt=0)
    intake_id: int | None = Field(default=None, gt=0)
    dossier_ids: list[int] = Field(default_factory=list, max_length=200)
    session_ids: list[int] = Field(default_factory=list, max_length=200)
    copy_ids: list[int] = Field(default_factory=list, max_length=200)
    incident_type: str = Field(min_length=2, max_length=100)
    severity: Literal["low", "medium", "high", "critical"]
    description: str = Field(min_length=4, max_length=2000)

    @model_validator(mode="after")
    def ensure_target(self):
        if not (self.dossier_id or self.intake_id or self.dossier_ids or self.session_ids or self.copy_ids):
            raise ValueError("至少关联一个档案、移交批次、会话或副本")
        return self


class IncidentLinksAdd(BaseModel):
    dossier_ids: list[int] = Field(default_factory=list, max_length=200)
    session_ids: list[int] = Field(default_factory=list, max_length=200)
    copy_ids: list[int] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def ensure_any(self):
        if not (self.dossier_ids or self.session_ids or self.copy_ids):
            raise ValueError("至少关联一个档案、会话或副本")
        return self


class InvestigatorAssign(BaseModel):
    user_id: int = Field(gt=0)


class EvidenceAdd(BaseModel):
    evidence_kind: str = Field(min_length=2, max_length=50)
    label: str = Field(min_length=2, max_length=200)
    uri: str | None = Field(default=None, max_length=500)
    note: str = Field(default="", max_length=2000)


class TimelineEntryCreate(BaseModel):
    event_type: str = Field(min_length=2, max_length=100)
    note: str = Field(default="", max_length=2000)
    occurred_at: str | None = Field(default=None, min_length=10, max_length=40)


class IncidentDismiss(BaseModel):
    reason: str = Field(min_length=4, max_length=2000)


class IncidentResolve(BaseModel):
    resolution: str = Field(min_length=4, max_length=2000)
