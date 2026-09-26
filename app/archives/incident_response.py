from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository, IncidentRepository
from app.services.audit import AuditContext, AuditService

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ACTIVE_STATES = ("open", "investigating", "contained")
SESSION_FREEZE_REASON_PREFIX = "incident_freeze:"
TARGET_TYPE_LABEL = {"dossier": "档案", "session": "会话", "copy": "副本"}


class IncidentResponseService:
    """泄密事件处置：线索上报合并、隔离冻结、调查协作、解除限制与恢复重建。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.incidents = IncidentRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ---- 上报与合并 ----

    def report(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("incidents.manage")
        now = to_storage(self.clock.now())
        clue_key = (data.get("clue_key") or "").strip() or None
        data = {**data, "clue_key": clue_key}
        if clue_key:
            existing = self.incidents.active_by_clue(clue_key)
            if existing:
                return self._merge_report(principal, existing, data, now)
        case_code = data.get("case_code") or f"ANM-{uuid.uuid4().hex[:12]}"
        case = self.incidents.create(data, principal.user_id, case_code, now)
        self.incidents.add_timeline(case["id"], "reported", f"线索上报：{data['description']}", principal.user_id, now)
        links = self._attach_links(principal, case, data, now)
        self.audit.record(principal, "incident.report", "incident_case", str(case["id"]), after=case, metadata={"clue_key": clue_key})
        return {"case": self.incidents.get(case["id"]), "links": links, "merged": False}

    def _merge_report(self, principal: Principal, case: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
        severity = data["severity"] if SEVERITY_ORDER[data["severity"]] > SEVERITY_ORDER[case["severity"]] else case["severity"]
        updated = self.incidents.bump_report(case["id"], severity, now)
        self.incidents.add_timeline(case["id"], "duplicate_report", f"重复上报合并：{data['description']}", principal.user_id, now)
        links = self._attach_links(principal, updated, data, now)
        self.audit.record(principal, "incident.merge", "incident_case", str(case["id"]), before=case, after=updated)
        return {"case": updated, "links": links, "merged": True}

    # ---- 关联与冻结 ----

    def add_links(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get(case_id)
        self._require_active(case)
        now = to_storage(self.clock.now())
        links = self._attach_links(principal, case, data, now)
        self.audit.record(principal, "incident.link", "incident_case", str(case_id), metadata={"link_ids": [link["id"] for link in links]})
        return {"case": self.incidents.get(case_id), "links": links}

    def _attach_links(self, principal: Principal, case: dict[str, Any], data: dict[str, Any], now: str) -> list[dict[str, Any]]:
        links = []
        dossier_ids = list(dict.fromkeys([*([data["dossier_id"]] if data.get("dossier_id") else []), *data.get("dossier_ids", [])]))
        for dossier_id in dossier_ids:
            links.append(self._link_target(principal, case, "dossier", dossier_id, now))
        for copy_id in data.get("copy_ids", []):
            links.append(self._link_target(principal, case, "copy", copy_id, now))
        for session_id in data.get("session_ids", []):
            links.append(self._link_target(principal, case, "session", session_id, now))
        return links

    def _link_target(self, principal: Principal, case: dict[str, Any], target_type: str, target_id: int, now: str) -> dict[str, Any]:
        existing = self.incidents.find_link(case["id"], target_type, target_id)
        if existing:
            return existing
        if target_type in {"dossier", "copy"}:
            dossier = self.dossiers.get(target_id)
            if target_type == "copy" and not dossier["source_dossier_id"]:
                raise ValidationError("副本对象必须是已签发的受控副本")
            snapshot: dict[str, Any] = dict(dossier)
        else:
            session = self.connection.execute("SELECT * FROM sessions WHERE id=?", (target_id,)).fetchone()
            if session is None:
                raise NotFoundError("会话不存在")
            snapshot = {"revoked_at": session["revoked_at"], "revoke_reason": session["revoke_reason"]}
        link = self.incidents.add_link(case["id"], target_type, target_id, principal.user_id, now)
        self.incidents.add_snapshot(link["id"], case["id"], target_type, target_id, snapshot, now)
        self._freeze_target(case, link, snapshot, principal.user_id, now)
        self.incidents.add_timeline(case["id"], "link_frozen", f"冻结{TARGET_TYPE_LABEL[target_type]} #{target_id}", principal.user_id, now)
        return link

    def _freeze_target(self, case: dict[str, Any], link: dict[str, Any], snapshot: dict[str, Any], actor_user_id: int | None, now: str) -> None:
        if link["target_type"] in {"dossier", "copy"}:
            dossier_id = link["target_id"]
            if snapshot["lifecycle_state"] in {"quarantined", "disposed"}:
                return
            self.dossiers.set_state(dossier_id, "quarantined", snapshot["version"], now)
            self.dossiers.append_event(
                dossier_id,
                "incident.frozen",
                actor_user_id,
                now,
                from_state=snapshot["lifecycle_state"],
                to_state="quarantined",
                details={"case_code": case["case_code"], "link_id": link["id"]},
            )
        else:
            self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason=? WHERE id=? AND revoked_at IS NULL",
                (now, f"{SESSION_FREEZE_REASON_PREFIX}{case['case_code']}", link["target_id"]),
            )

    # ---- 调查协作 ----

    def assign_investigator(self, principal: Principal, case_id: int, user_id: int) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get(case_id)
        self._require_active(case)
        user = self.connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None:
            raise NotFoundError("调查人用户不存在")
        if user["status"] != "active":
            raise ValidationError("调查人账号必须处于可用状态")
        existing = self.incidents.find_investigator(case_id, user_id)
        if existing:
            return existing
        now = to_storage(self.clock.now())
        assignment = self.incidents.assign_investigator(case_id, user_id, principal.user_id, now)
        self.incidents.add_timeline(case_id, "investigator_assigned", f"分派调查人：{user['display_name']}", principal.user_id, now)
        self.audit.record(principal, "incident.assign", "incident_case", str(case_id), metadata={"user_id": user_id})
        return assignment

    def add_evidence(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        case = self.incidents.get(case_id)
        self._require_case_access(principal, case_id)
        self._require_active(case)
        now = to_storage(self.clock.now())
        digest = hashlib.sha256(
            json.dumps(
                {
                    "case_id": case_id,
                    "evidence_kind": data["evidence_kind"],
                    "label": data["label"],
                    "uri": data.get("uri"),
                    "note": data.get("note", ""),
                    "added_by": principal.user_id,
                    "created_at": now,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        evidence = self.incidents.add_evidence(case_id, data, digest, principal.user_id, now)
        self.incidents.add_timeline(case_id, "evidence_added", f"追加证据：{data['label']}", principal.user_id, now)
        self.audit.record(principal, "incident.evidence", "incident_case", str(case_id), after=evidence)
        return evidence

    def add_timeline_entry(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        case = self.incidents.get(case_id)
        self._require_case_access(principal, case_id)
        self._require_active(case)
        occurred_at = data.get("occurred_at") or to_storage(self.clock.now())
        entry = self.incidents.add_timeline(case_id, data["event_type"], data.get("note", ""), principal.user_id, occurred_at)
        self.audit.record(principal, "incident.timeline", "incident_case", str(case_id), after=entry)
        return entry

    # ---- 状态流转与解除 ----

    def investigate(self, principal: Principal, case_id: int) -> dict[str, Any]:
        return self._transition(principal, case_id, {"open"}, "investigating", "案件进入调查")

    def contain(self, principal: Principal, case_id: int) -> dict[str, Any]:
        return self._transition(principal, case_id, {"open", "investigating"}, "contained", "泄露面已遏制")

    def _transition(self, principal: Principal, case_id: int, allowed: set[str], target: str, note: str) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get(case_id)
        if case["state"] not in allowed:
            raise ConflictError("当前事件状态不允许该流转")
        now = to_storage(self.clock.now())
        updated = self.incidents.set_state(case_id, target, now)
        self.incidents.add_timeline(case_id, f"state_{target}", note, principal.user_id, now)
        self.audit.record(principal, f"incident.{target}", "incident_case", str(case_id), before=case, after=updated)
        return updated

    def dismiss(self, principal: Principal, case_id: int, reason: str) -> dict[str, Any]:
        return self._close(principal, case_id, "dismissed", reason, "误报确认，解除隔离")

    def resolve(self, principal: Principal, case_id: int, resolution: str) -> dict[str, Any]:
        return self._close(principal, case_id, "resolved", resolution, "整改完成，解除隔离")

    def _close(self, principal: Principal, case_id: int, target_state: str, text: str, release_reason: str) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get(case_id)
        self._require_active(case)
        now = to_storage(self.clock.now())
        updated = self.incidents.set_state(case_id, target_state, now, resolution=text)
        released = self._release_case_links(case, release_reason, now, actor_user_id=principal.user_id)
        self.incidents.add_timeline(case_id, f"state_{target_state}", text, principal.user_id, now)
        self.audit.record(
            principal,
            f"incident.{target_state}",
            "incident_case",
            str(case_id),
            before=case,
            after=updated,
            metadata={"released_links": len(released)},
        )
        return {"case": self.incidents.get(case_id), "released_links": released}

    def _release_case_links(self, case: dict[str, Any], reason: str, now: str, actor_user_id: int | None) -> list[int]:
        released = []
        for link in self.incidents.frozen_links(case["id"]):
            self._release_link(case, link, reason, now, actor_user_id)
            released.append(link["id"])
        return released

    def _release_link(self, case: dict[str, Any], link: dict[str, Any], reason: str, now: str, actor_user_id: int | None) -> None:
        snapshot_row = self.incidents.snapshot_for(link["id"])
        snapshot = snapshot_row["snapshot"] if snapshot_row else {}
        self.incidents.release_link(link["id"], reason, now)
        if link["target_type"] in {"dossier", "copy"}:
            dossier_id = link["target_id"]
            if self.incidents.active_frozen_dossier_case(dossier_id, exclude_case_id=case["id"]):
                return
            current = self.connection.execute("SELECT * FROM dossiers WHERE id=?", (dossier_id,)).fetchone()
            if current is None or current["lifecycle_state"] != "quarantined":
                return
            restored = snapshot.get("lifecycle_state") or "available"
            if restored == "access_loaned" and current["reserved_quantity"] == 0:
                restored = "disclosed" if current["quantity"] == 0 else "available"
            self.connection.execute(
                "UPDATE dossiers SET lifecycle_state=?,version=version+1,updated_at=? WHERE id=?",
                (restored, now, dossier_id),
            )
            self.dossiers.append_event(
                dossier_id,
                "incident.released",
                actor_user_id,
                now,
                from_state="quarantined",
                to_state=restored,
                details={"case_code": case["case_code"], "reason": reason},
            )
        else:
            reason_code = f"{SESSION_FREEZE_REASON_PREFIX}{case['case_code']}"
            other = self.incidents.active_frozen_session_case(link["target_id"], exclude_case_id=case["id"])
            if other:
                self.connection.execute(
                    "UPDATE sessions SET revoke_reason=? WHERE id=? AND revoke_reason=?",
                    (f"{SESSION_FREEZE_REASON_PREFIX}{other['case_code']}", link["target_id"], reason_code),
                )
            else:
                self.connection.execute(
                    "UPDATE sessions SET revoked_at=NULL,revoke_reason=NULL WHERE id=? AND revoke_reason=?",
                    (link["target_id"], reason_code),
                )

    # ---- 查询 ----

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return self.incidents.list(state)

    def detail(self, principal: Principal, case_id: int) -> dict[str, Any]:
        case = self.incidents.get(case_id)
        self._require_case_access(principal, case_id)
        return {
            "case": case,
            "links": self.incidents.links(case_id),
            "snapshots": self.incidents.snapshots(case_id),
            "investigators": self.incidents.investigators(case_id),
            "evidence": self.incidents.evidence(case_id),
            "timeline": self.incidents.timeline(case_id),
        }

    def _require_case_access(self, principal: Principal, case_id: int) -> None:
        if principal.can("incidents.manage"):
            return
        if self.incidents.is_investigator(case_id, principal.user_id):
            return
        raise PermissionDeniedError("仅泄密事件调查组成员或事件管理员可以查看")

    @staticmethod
    def _require_active(case: dict[str, Any]) -> None:
        if case["state"] not in ACTIVE_STATES:
            raise ConflictError("泄密事件已经结案，不能再修改")

    # ---- 服务恢复后按事件状态重建限制 ----

    def rebuild_restrictions(self) -> dict[str, int]:
        now = to_storage(self.clock.now())
        refrozen = 0
        released = 0
        active_rows = self.connection.execute(
            """SELECT l.*,c.case_code FROM incident_links l
               JOIN incident_cases c ON c.id=l.case_id
               WHERE l.freeze_state='frozen' AND c.state IN ('open','investigating','contained')
               ORDER BY l.id"""
        ).fetchall()
        for row in active_rows:
            link = dict(row)
            case = {"id": link["case_id"], "case_code": link["case_code"]}
            if link["target_type"] in {"dossier", "copy"}:
                dossier = self.connection.execute("SELECT * FROM dossiers WHERE id=?", (link["target_id"],)).fetchone()
                if dossier and dossier["lifecycle_state"] not in {"quarantined", "disposed"}:
                    self.connection.execute(
                        "UPDATE dossiers SET lifecycle_state='quarantined',version=version+1,updated_at=? WHERE id=?",
                        (now, link["target_id"]),
                    )
                    self.dossiers.append_event(
                        link["target_id"],
                        "incident.refrozen",
                        None,
                        now,
                        from_state=dossier["lifecycle_state"],
                        to_state="quarantined",
                        details={"case_code": link["case_code"], "reason": "服务恢复重建限制"},
                    )
                    refrozen += 1
            else:
                session = self.connection.execute("SELECT * FROM sessions WHERE id=?", (link["target_id"],)).fetchone()
                if session and session["revoked_at"] is None:
                    self.connection.execute(
                        "UPDATE sessions SET revoked_at=?,revoke_reason=? WHERE id=?",
                        (now, f"{SESSION_FREEZE_REASON_PREFIX}{link['case_code']}", link["target_id"]),
                    )
                    refrozen += 1
        closed_rows = self.connection.execute(
            """SELECT l.*,c.case_code FROM incident_links l
               JOIN incident_cases c ON c.id=l.case_id
               WHERE l.freeze_state='frozen' AND c.state IN ('resolved','dismissed')
               ORDER BY l.id"""
        ).fetchall()
        for row in closed_rows:
            link = dict(row)
            case = {"id": link["case_id"], "case_code": link["case_code"]}
            self._release_link(case, link, "系统恢复按结案状态解除", now, None)
            released += 1
        if refrozen or released:
            self.audit.record(
                AuditContext(None, "系统"),
                "incident.rebuild",
                "incident_case",
                None,
                metadata={"refrozen": refrozen, "released": released},
            )
        return {"refrozen": refrozen, "released": released}
