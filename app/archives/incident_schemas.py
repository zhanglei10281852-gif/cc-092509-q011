from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class IncidentLinkInput(BaseModel):
    """一条线索关联：原始档案、受控副本或登录会话。"""

    link_type: Literal["dossier", "copy", "session"]
    dossier_id: int | None = Field(default=None, gt=0)
    session_id: int | None = Field(default=None, gt=0)
    note: str = Field(default="", max_length=500)

    @model_validator(mode="after")
    def ensure_target(self):
        if self.link_type == "session":
            if not self.session_id or self.dossier_id:
                raise ValueError("会话关联必须且只能填写 session_id")
        elif not self.dossier_id or self.session_id:
            raise ValueError("档案或副本关联必须且只能填写 dossier_id")
        return self


class LeakReportCreate(BaseModel):
    """泄密线索上报：一封线索可同时冻结多个档案、会话与副本。"""

    case_code: str | None = Field(default=None, max_length=64)
    clue_key: str | None = Field(default=None, min_length=4, max_length=200)
    incident_type: str = Field(min_length=2, max_length=100)
    severity: Literal["low", "medium", "high", "critical"]
    description: str = Field(min_length=4, max_length=2000)
    links: list[IncidentLinkInput] = Field(default_factory=list, max_length=100)


class IncidentLinksAppend(BaseModel):
    links: list[IncidentLinkInput] = Field(min_length=1, max_length=100)


class AssignmentCreate(BaseModel):
    investigator_user_id: int = Field(gt=0)


class EvidenceCreate(BaseModel):
    evidence_code: str | None = Field(default=None, max_length=64)
    kind: str = Field(min_length=2, max_length=50)
    summary: str = Field(min_length=4, max_length=500)
    detail: str = Field(default="", max_length=4000)


class TimelineNoteCreate(BaseModel):
    body: str = Field(min_length=2, max_length=2000)


class ResolveRequest(BaseModel):
    resolution: str = Field(min_length=4, max_length=2000)


class DismissRequest(BaseModel):
    reason: str = Field(min_length=4, max_length=2000)


class ContainRequest(BaseModel):
    note: str = Field(default="", max_length=1000)
