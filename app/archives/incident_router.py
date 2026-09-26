from __future__ import annotations

from fastapi import APIRouter, Depends, Response, status

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.archives.incident_response import IncidentResponseService
from app.archives.incident_schemas import (
    AssignmentCreate,
    ContainRequest,
    DismissRequest,
    EvidenceCreate,
    IncidentLinksAppend,
    LeakReportCreate,
    ResolveRequest,
    TimelineNoteCreate,
)

router = APIRouter(prefix="/api/incidents", tags=["泄密事件处置"])


@router.post("", status_code=status.HTTP_201_CREATED)
def report_leak(
    payload: LeakReportCreate,
    response: Response,
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        result = IncidentResponseService(connection).report(principal, payload.model_dump())
    if result["merged"]:
        response.status_code = status.HTTP_200_OK
    return result


@router.get("")
def list_incidents(state: str | None = None, principal: Principal = Depends(current_principal)):
    return IncidentResponseService(get_connection()).list(principal, state)


@router.post("/rebuild")
def rebuild_restrictions(principal: Principal = Depends(current_principal)):
    principal.require("incidents.manage")
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).rebuild_restrictions(principal)


@router.get("/{case_id}")
def incident_detail(case_id: int, principal: Principal = Depends(current_principal)):
    return IncidentResponseService(get_connection()).detail(principal, case_id)


@router.post("/{case_id}/links")
def append_links(case_id: int, payload: IncidentLinksAppend, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).append_links(principal, case_id, payload.model_dump()["links"])


@router.post("/{case_id}/assignments", status_code=status.HTTP_201_CREATED)
def assign_investigator(case_id: int, payload: AssignmentCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).assign(principal, case_id, payload.investigator_user_id)


@router.delete("/{case_id}/assignments/{investigator_user_id}")
def revoke_investigator(case_id: int, investigator_user_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).revoke_assignment(principal, case_id, investigator_user_id)


@router.post("/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
def append_evidence(case_id: int, payload: EvidenceCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).add_evidence(principal, case_id, payload.model_dump())


@router.delete("/{case_id}/evidence/{evidence_id}")
def purge_evidence(case_id: int, evidence_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).delete_evidence(principal, case_id, evidence_id)


@router.post("/{case_id}/timeline", status_code=status.HTTP_201_CREATED)
def append_timeline_note(case_id: int, payload: TimelineNoteCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).add_timeline_note(principal, case_id, payload.body)


@router.post("/{case_id}/contain")
def contain_incident(case_id: int, payload: ContainRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).contain(principal, case_id, payload.note)


@router.post("/{case_id}/resolve")
def resolve_incident(case_id: int, payload: ResolveRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).resolve(principal, case_id, payload.resolution)


@router.post("/{case_id}/dismiss")
def dismiss_incident(case_id: int, payload: DismissRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).dismiss(principal, case_id, payload.reason)


@router.post("/{case_id}/links/{link_id}/release")
def release_link(case_id: int, link_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).release_link(principal, case_id, link_id)
