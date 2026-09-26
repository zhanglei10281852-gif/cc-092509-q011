from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.core.security import Principal
from app.archives.schemas import (
    CopyIssueRequest,
    EvidenceAdd,
    IncidentDismiss,
    IncidentLinksAdd,
    IncidentReportCreate,
    IncidentResolve,
    InvestigatorAssign,
    TimelineEntryCreate,
    ApprovalCreate,
    ApprovalDecision,
    BatchCreate,
    DisclosureUseCreate,
    LoanCreate,
    LoanReturn,
    LocationCreate,
    DossierCreate,
)
from app.archives.incident_response import IncidentResponseService
from app.archives.service import ApprovalService, AccessLoanService, VaultService, DossierLifecycleService

router = APIRouter(prefix="/api/dossiers", tags=["知识产权档案"])


@router.post("/vaults", status_code=status.HTTP_201_CREATED)
def create_vault(payload: LocationCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return VaultService(connection).create(principal, payload.model_dump())


@router.get("/vaults")
def list_vaults(principal: Principal = Depends(current_principal)):
    return VaultService(get_connection()).list(principal)


@router.post("/batches", status_code=status.HTTP_201_CREATED)
def create_batch(payload: BatchCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).create_batch(principal, payload.model_dump())


@router.post("", status_code=status.HTTP_201_CREATED)
def create_dossier(payload: DossierCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).register_dossier(principal, payload.model_dump())


@router.get("")
def list_dossiers(
    lifecycle_state: str | None = Query(default=None),
    intake_id: int | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return DossierLifecycleService(get_connection()).list_dossiers(principal, lifecycle_state, intake_id)


@router.get("/{dossier_id}")
def get_dossier(dossier_id: int, principal: Principal = Depends(current_principal)):
    return DossierLifecycleService(get_connection()).detail(principal, dossier_id)


@router.post("/{dossier_id}/issue_copys", status_code=status.HTTP_201_CREATED)
def issue_copy(dossier_id: int, payload: CopyIssueRequest, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).issue_copy(principal, dossier_id, payload.model_dump())


@router.post("/{dossier_id}/disclosures", status_code=status.HTTP_201_CREATED)
def disclose(dossier_id: int, payload: DisclosureUseCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DossierLifecycleService(connection).disclose(principal, dossier_id, payload.model_dump())


@router.post("/access_loans", status_code=status.HTTP_201_CREATED)
def create_access_loan(payload: LoanCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessLoanService(connection).create(principal, payload.model_dump())


@router.post("/access_loans/{access_loan_id}/returns")
def return_access_loan(access_loan_id: int, payload: LoanReturn, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return AccessLoanService(connection).return_access_loan(principal, access_loan_id, payload.model_dump())


@router.post("/approvals", status_code=status.HTTP_201_CREATED)
def create_approval(payload: ApprovalCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ApprovalService(connection).create(principal, payload.model_dump())


@router.post("/approvals/{request_id}/decisions")
def decide_approval(request_id: int, payload: ApprovalDecision, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return ApprovalService(connection).decide(principal, request_id, payload.model_dump())


@router.post("/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(payload: IncidentReportCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).report(principal, payload.model_dump())


@router.get("/incidents/list")
def list_incidents(state: str | None = None, principal: Principal = Depends(current_principal)):
    return IncidentResponseService(get_connection()).list(principal, state)


@router.get("/incidents/{case_id}")
def incident_detail(case_id: int, principal: Principal = Depends(current_principal)):
    return IncidentResponseService(get_connection()).detail(principal, case_id)


@router.post("/incidents/{case_id}/links", status_code=status.HTTP_201_CREATED)
def add_incident_links(case_id: int, payload: IncidentLinksAdd, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).add_links(principal, case_id, payload.model_dump())


@router.post("/incidents/{case_id}/investigators", status_code=status.HTTP_201_CREATED)
def assign_investigator(case_id: int, payload: InvestigatorAssign, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).assign_investigator(principal, case_id, payload.user_id)


@router.post("/incidents/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
def add_incident_evidence(case_id: int, payload: EvidenceAdd, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).add_evidence(principal, case_id, payload.model_dump())


@router.post("/incidents/{case_id}/timeline", status_code=status.HTTP_201_CREATED)
def add_incident_timeline(case_id: int, payload: TimelineEntryCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).add_timeline_entry(principal, case_id, payload.model_dump())


@router.post("/incidents/{case_id}/investigate")
def investigate_incident(case_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).investigate(principal, case_id)


@router.post("/incidents/{case_id}/contain")
def contain_incident(case_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).contain(principal, case_id)


@router.post("/incidents/{case_id}/dismiss")
def dismiss_incident(case_id: int, payload: IncidentDismiss, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).dismiss(principal, case_id, payload.reason)


@router.post("/incidents/{case_id}/resolve")
def resolve_incident(case_id: int, payload: IncidentResolve, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return IncidentResponseService(connection).resolve(principal, case_id, payload.resolution)
