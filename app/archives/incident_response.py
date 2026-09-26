"""泄密事件处置流程。

保密办公室收到线索（如邮件误发）后：
1. 上报线索并关联涉事档案、登录会话与受控副本，系统立即冻结（隔离）相关载体；
2. 分派调查人，调查组在事件工作区内查看与追加证据、时间线，无需解除隔离；
3. 确认误报（dismiss）或完成整改（resolve）后分别解除对应限制，恢复档案原状态；
4. 服务重启后按事件状态重建限制，避免恢复期间出现管控空窗。

调查证据与时间线只追加不删除；同一线索重复上报会合并进既有事件。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository, row_dict
from app.services.audit import AuditContext, AuditService

ACTIVE_CASE_STATES = ("open", "investigating", "contained")
TERMINAL_CASE_STATES = ("resolved", "dismissed")
CIRCULATING_STATES = ("received", "available", "access_loaned", "partially_disclosed", "quarantined", "pending_disposal")
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def ensure_dossier_not_restricted(
    connection: sqlite3.Connection, dossier_id: int, operation: str
) -> None:
    """档案被泄密事件隔离时，以明确原因拒绝借阅、披露与处置等请求。"""
    row = connection.execute(
        """SELECT c.id AS case_id, c.case_code, c.description
           FROM incident_snapshots s JOIN incident_cases c ON c.id = s.case_id
           WHERE s.dossier_id=? AND s.released_at IS NULL
             AND c.state IN ('open','investigating','contained')
           ORDER BY s.id LIMIT 1""",
        (dossier_id,),
    ).fetchone()
    if row:
        raise ConflictError(
            f"档案因泄密事件 {row['case_code']} 处于隔离状态，{operation}已被拒绝；事件说明：{row['description']}",
            context={"case_id": row["case_id"], "case_code": row["case_code"], "operation": operation},
        )


class IncidentResponseRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create_case(self, data: dict[str, Any], detected_by: int, case_code: str, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO incident_cases(case_code,dossier_id,intake_id,clue_key,incident_type,severity,state,
                   detected_by,description,created_at,updated_at)
               VALUES(?,?,?,?,?,?,'open',?,?,?,?)""",
            (
                case_code, data.get("dossier_id"), data.get("intake_id"), data.get("clue_key"),
                data["incident_type"], data["severity"], detected_by, data["description"], now, now,
            ),
        )
        return self.get_case(cursor.lastrowid)

    def get_case(self, case_id: int) -> dict[str, Any]:
        return row_dict(
            self.connection.execute("SELECT * FROM incident_cases WHERE id=?", (case_id,)).fetchone()
        )

    def get_case_by_code(self, case_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM incident_cases WHERE case_code=?", (case_code,)
        ).fetchone()
        return dict(row) if row else None

    def latest_case_for_clue(self, clue_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM incident_cases WHERE clue_key=? ORDER BY id DESC LIMIT 1", (clue_key,)
        ).fetchone()
        return dict(row) if row else None

    def list_cases(self, state: str | None) -> list[dict[str, Any]]:
        sql = """SELECT c.*,
                        (SELECT COUNT(*) FROM incident_links l WHERE l.case_id=c.id) AS link_count,
                        (SELECT COUNT(*) FROM incident_snapshots s WHERE s.case_id=c.id AND s.released_at IS NULL)
                            AS active_restriction_count,
                        (SELECT COUNT(*) FROM incident_evidence e WHERE e.case_id=c.id) AS evidence_count
                 FROM incident_cases c"""
        params: tuple[Any, ...] = ()
        if state:
            sql += " WHERE c.state=?"
            params = (state,)
        sql += " ORDER BY c.id DESC"
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    def update_case(
        self,
        case_id: int,
        now: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        resolution: str | None = None,
    ) -> dict[str, Any]:
        assignments: list[str] = []
        params: list[Any] = []
        if state is not None:
            assignments.append("state=?")
            params.append(state)
        if severity is not None:
            assignments.append("severity=?")
            params.append(severity)
        if resolution is not None:
            assignments.append("resolution=?")
            params.append(resolution)
        if not assignments:
            return self.get_case(case_id)
        params.extend([now, case_id])
        self.connection.execute(
            f"UPDATE incident_cases SET {','.join(assignments)},version=version+1,updated_at=? WHERE id=?",
            tuple(params),
        )
        return self.get_case(case_id)

    def add_link(
        self,
        case_id: int,
        link: dict[str, Any],
        actor_user_id: int,
        now: str,
        *,
        auto_linked: bool = False,
    ) -> tuple[dict[str, Any], bool]:
        cursor = self.connection.execute(
            """INSERT OR IGNORE INTO incident_links(case_id,link_type,dossier_id,session_id,auto_linked,note,linked_by,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                case_id, link["link_type"], link.get("dossier_id"), link.get("session_id"),
                int(auto_linked), link.get("note", ""), actor_user_id, now,
            ),
        )
        if link["link_type"] == "session":
            row = self.connection.execute(
                "SELECT * FROM incident_links WHERE case_id=? AND session_id=?",
                (case_id, link["session_id"]),
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT * FROM incident_links WHERE case_id=? AND link_type=? AND dossier_id=?",
                (case_id, link["link_type"], link["dossier_id"]),
            ).fetchone()
        return dict(row), cursor.rowcount == 1

    def get_link(self, link_id: int) -> dict[str, Any]:
        return row_dict(
            self.connection.execute("SELECT * FROM incident_links WHERE id=?", (link_id,)).fetchone()
        )

    def links_for_case(self, case_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                """SELECT l.*,d.dossier_code
                   FROM incident_links l LEFT JOIN dossiers d ON d.id=l.dossier_id
                   WHERE l.case_id=? ORDER BY l.id""",
                (case_id,),
            ).fetchall()
        ]

    def create_snapshot(
        self, case_id: int, dossier: dict[str, Any], state_before: str, digest: str, now: str
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO incident_snapshots(case_id,dossier_id,state_before,quantity,reserved_quantity,
                   vault_id,custody_user_id,dossier_version,snapshot_digest,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                case_id, dossier["id"], state_before, dossier["quantity"], dossier["reserved_quantity"],
                dossier.get("vault_id"), dossier.get("custody_user_id"), dossier["version"], digest, now,
            ),
        )
        return dict(
            self.connection.execute(
                "SELECT * FROM incident_snapshots WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )

    def snapshot_for(self, case_id: int, dossier_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM incident_snapshots WHERE case_id=? AND dossier_id=?",
            (case_id, dossier_id),
        ).fetchone()
        return dict(row) if row else None

    def active_snapshots_for_dossier(self, dossier_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM incident_snapshots WHERE dossier_id=? AND released_at IS NULL ORDER BY id",
                (dossier_id,),
            ).fetchall()
        ]

    def snapshots_for_case(self, case_id: int, *, active_only: bool = False) -> list[dict[str, Any]]:
        sql = """SELECT s.*,d.dossier_code FROM incident_snapshots s
                 JOIN dossiers d ON d.id=s.dossier_id WHERE s.case_id=?"""
        if active_only:
            sql += " AND s.released_at IS NULL"
        sql += " ORDER BY s.id"
        return [dict(row) for row in self.connection.execute(sql, (case_id,)).fetchall()]

    def release_snapshot(self, snapshot_id: int, released_by: int | None, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE incident_snapshots SET released_at=?,released_by=? WHERE id=?",
            (now, released_by, snapshot_id),
        )
        return dict(
            self.connection.execute(
                "SELECT * FROM incident_snapshots WHERE id=?", (snapshot_id,)
            ).fetchone()
        )

    def circulating_descendants(self, dossier_id: int) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in CIRCULATING_STATES)
        rows = self.connection.execute(
            f"""WITH RECURSIVE descendants(id) AS (
                    SELECT id FROM dossiers WHERE source_dossier_id=?
                    UNION
                    SELECT d.id FROM dossiers d JOIN descendants x ON d.source_dossier_id=x.id
                )
                SELECT d.* FROM dossiers d JOIN descendants x ON x.id=d.id
                WHERE d.lifecycle_state IN ({placeholders}) ORDER BY d.id""",
            (dossier_id, *CIRCULATING_STATES),
        ).fetchall()
        return [dict(row) for row in rows]

    def assignments_for_case(self, case_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                """SELECT a.*,u.display_name AS investigator_name
                   FROM incident_assignments a JOIN users u ON u.id=a.investigator_user_id
                   WHERE a.case_id=? ORDER BY a.id""",
                (case_id,),
            ).fetchall()
        ]

    def assignment_for(self, case_id: int, investigator_user_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM incident_assignments WHERE case_id=? AND investigator_user_id=?",
            (case_id, investigator_user_id),
        ).fetchone()
        return dict(row) if row else None

    def evidence_for_case(self, case_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                """SELECT e.*,u.display_name AS submitted_by_name
                   FROM incident_evidence e JOIN users u ON u.id=e.submitted_by
                   WHERE e.case_id=? ORDER BY e.id""",
                (case_id,),
            ).fetchall()
        ]

    def evidence_by_code(self, evidence_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM incident_evidence WHERE evidence_code=?", (evidence_code,)
        ).fetchone()
        return dict(row) if row else None

    def timeline_for_case(self, case_id: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM incident_timeline WHERE case_id=? ORDER BY id", (case_id,)
            ).fetchall()
        ]

    def append_timeline(
        self, case_id: int, entry_type: str, body: str, actor_user_id: int | None, now: str
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO incident_timeline(case_id,entry_type,body,actor_user_id,created_at)
               VALUES(?,?,?,?,?)""",
            (case_id, entry_type, body, actor_user_id, now),
        )
        return dict(
            self.connection.execute(
                "SELECT * FROM incident_timeline WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )


class IncidentResponseService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.incidents = IncidentResponseRepository(connection)
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ---------- 上报与合并 ----------

    def report(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("incidents.manage")
        clue_key = data.get("clue_key")
        if clue_key:
            existing = self.incidents.latest_case_for_clue(clue_key)
            if existing and existing["state"] in ACTIVE_CASE_STATES:
                return self._merge_report(principal, existing, data)
        case_code = data.get("case_code") or f"LEAK-{uuid.uuid4().hex[:12]}"
        if self.incidents.get_case_by_code(case_code):
            raise ConflictError("事件编号已经存在")
        now = to_storage(self.clock.now())
        case = self.incidents.create_case(data, principal.user_id, case_code, now)
        self._timeline(case["id"], "case.created", f"线索登记：{data['description']}", principal.user_id, now)
        added = self._add_links(principal, case, data.get("links", []), now)
        self.audit.record(
            principal, "incident.report", "incident_case", str(case["id"]),
            after=case, metadata={"clue_key": clue_key, "link_count": len(added)},
        )
        return {
            **self.detail(principal, case["id"]),
            "merged": False,
            "added_link_ids": [link["id"] for link in added],
        }

    def _merge_report(self, principal: Principal, case: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        if SEVERITY_ORDER[data["severity"]] > SEVERITY_ORDER[case["severity"]]:
            self.incidents.update_case(case["id"], now, severity=data["severity"])
            self._timeline(
                case["id"], "severity.escalated",
                f"重复上报提升严重度：{case['severity']} → {data['severity']}", principal.user_id, now,
            )
        added = self._add_links(principal, case, data.get("links", []), now)
        self._timeline(
            case["id"], "report.merged",
            f"重复上报已合并：{data['description']}（新增关联 {len(added)} 项）", principal.user_id, now,
        )
        self.audit.record(
            principal, "incident.merge", "incident_case", str(case["id"]),
            metadata={"clue_key": data.get("clue_key"), "added_links": len(added)},
        )
        return {
            **self.detail(principal, case["id"]),
            "merged": True,
            "added_link_ids": [link["id"] for link in added],
        }

    # ---------- 关联与冻结 ----------

    def append_links(self, principal: Principal, case_id: int, links: list[dict[str, Any]]) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get_case(case_id)
        self._require_active(case, "追加关联")
        now = to_storage(self.clock.now())
        added = self._add_links(principal, case, links, now)
        self.audit.record(
            principal, "incident.link", "incident_case", str(case_id),
            metadata={"added_links": len(added)},
        )
        return {**self.detail(principal, case_id), "added_link_ids": [link["id"] for link in added]}

    def _add_links(
        self, principal: Principal, case: dict[str, Any], links: list[dict[str, Any]], now: str
    ) -> list[dict[str, Any]]:
        added: list[dict[str, Any]] = []
        for link in links:
            if link["link_type"] == "session":
                self._require_session(link["session_id"])
            else:
                self.dossiers.get(link["dossier_id"])
            row, created = self.incidents.add_link(case["id"], link, principal.user_id, now)
            if not created:
                continue
            added.append(row)
            self._timeline(
                case["id"], "link.added",
                f"关联{self._link_label(row)}（{link.get('note') or '无备注'}）", principal.user_id, now,
            )
            if case["state"] in ACTIVE_CASE_STATES:
                self._apply_link_restriction(case, row, principal.user_id, now)
        return added

    def _apply_link_restriction(
        self, case: dict[str, Any], link: dict[str, Any], actor_user_id: int | None, now: str
    ) -> None:
        if link["link_type"] == "session":
            self._revoke_session(case, link["session_id"], actor_user_id, now)
            return
        self._quarantine_dossier(case, link["dossier_id"], actor_user_id, now)
        for descendant in self.incidents.circulating_descendants(link["dossier_id"]):
            row, created = self.incidents.add_link(
                case["id"],
                {"link_type": "copy", "dossier_id": descendant["id"], "note": "仍在流转的受控副本"},
                actor_user_id or link["linked_by"],
                now,
                auto_linked=True,
            )
            if created:
                self._timeline(
                    case["id"], "link.added",
                    f"自动关联在途副本 {descendant['dossier_code']}", actor_user_id, now,
                )
            self._quarantine_dossier(case, descendant["id"], actor_user_id, now)

    def _quarantine_dossier(
        self, case: dict[str, Any], dossier_id: int, actor_user_id: int | None, now: str
    ) -> None:
        dossier = self.dossiers.get(dossier_id)
        if self.incidents.snapshot_for(case["id"], dossier_id) is None:
            state_before = dossier["lifecycle_state"]
            if state_before == "quarantined":
                # 已被其他事件隔离：沿用最早已有快照的原始状态，结案时才能正确恢复
                others = self.incidents.active_snapshots_for_dossier(dossier_id)
                state_before = others[0]["state_before"] if others else "quarantined"
            digest = self._snapshot_digest(case["id"], dossier, state_before, now)
            self.incidents.create_snapshot(case["id"], dossier, state_before, digest, now)
        if dossier["lifecycle_state"] != "quarantined":
            self.connection.execute(
                "UPDATE dossiers SET lifecycle_state='quarantined',version=version+1,updated_at=? WHERE id=?",
                (now, dossier_id),
            )
            self.dossiers.append_event(
                dossier_id, "incident.quarantined", actor_user_id, now,
                from_state=dossier["lifecycle_state"], to_state="quarantined",
                details={"case_code": case["case_code"]},
            )
            self._timeline(
                case["id"], "dossier.quarantined",
                f"档案 {dossier['dossier_code']} 已隔离冻结", actor_user_id, now,
            )

    def _revoke_session(
        self, case: dict[str, Any], session_id: int, actor_user_id: int | None, now: str
    ) -> None:
        cursor = self.connection.execute(
            "UPDATE sessions SET revoked_at=?,revoke_reason=? WHERE id=? AND revoked_at IS NULL",
            (now, f"incident:{case['case_code']}", session_id),
        )
        if cursor.rowcount == 1:
            self._timeline(
                case["id"], "session.revoked",
                f"登录会话 #{session_id} 已吊销，防止泄露面扩大", actor_user_id, now,
            )

    # ---------- 调查工作区 ----------

    def detail(self, principal: Principal, case_id: int) -> dict[str, Any]:
        case = self.incidents.get_case(case_id)
        self._require_workspace_access(principal, case_id)
        return self._workspace(case)

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        return self.incidents.list_cases(state)

    def assign(self, principal: Principal, case_id: int, investigator_user_id: int) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get_case(case_id)
        self._require_active(case, "分派调查人")
        self._require_user(investigator_user_id)
        now = to_storage(self.clock.now())
        existing = self.incidents.assignment_for(case_id, investigator_user_id)
        replayed = False
        if existing and existing["revoked_at"] is None:
            replayed = True
        elif existing:
            self.connection.execute(
                """UPDATE incident_assignments SET revoked_at=NULL,revoked_by=NULL,
                       assigned_by=?,assigned_at=? WHERE id=?""",
                (principal.user_id, now, existing["id"]),
            )
        else:
            self.connection.execute(
                """INSERT INTO incident_assignments(case_id,investigator_user_id,assigned_by,assigned_at)
                   VALUES(?,?,?,?)""",
                (case_id, investigator_user_id, principal.user_id, now),
            )
        if not replayed:
            self._timeline(
                case_id, "investigator.assigned", f"分派调查人 #{investigator_user_id}", principal.user_id, now
            )
        if case["state"] == "open":
            self.incidents.update_case(case_id, now, state="investigating")
            self._timeline(case_id, "state.changed", "事件进入调查阶段", principal.user_id, now)
        self.audit.record(
            principal, "incident.assign", "incident_case", str(case_id),
            metadata={"investigator_user_id": investigator_user_id, "replayed": replayed},
        )
        return {"assignment": self.incidents.assignment_for(case_id, investigator_user_id), "replayed": replayed}

    def revoke_assignment(self, principal: Principal, case_id: int, investigator_user_id: int) -> dict[str, Any]:
        principal.require("incidents.manage")
        self.incidents.get_case(case_id)
        existing = self.incidents.assignment_for(case_id, investigator_user_id)
        if not existing or existing["revoked_at"] is not None:
            raise NotFoundError("调查人分派不存在或已解除")
        now = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE incident_assignments SET revoked_at=?,revoked_by=? WHERE id=?",
            (now, principal.user_id, existing["id"]),
        )
        self._timeline(case_id, "investigator.revoked", f"解除调查人 #{investigator_user_id}", principal.user_id, now)
        self.audit.record(
            principal, "incident.assign_revoke", "incident_case", str(case_id),
            metadata={"investigator_user_id": investigator_user_id},
        )
        return self.incidents.assignment_for(case_id, investigator_user_id)

    def add_evidence(self, principal: Principal, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
        case = self.incidents.get_case(case_id)
        self._require_workspace_access(principal, case_id)
        self._require_active(case, "追加证据")
        evidence_code = data.get("evidence_code") or f"EVD-{uuid.uuid4().hex[:12]}"
        existing = self.incidents.evidence_by_code(evidence_code)
        if existing:
            if existing["case_id"] != case_id:
                raise ConflictError("证据编号已被其他事件占用")
            same = (
                existing["kind"] == data["kind"]
                and existing["summary"] == data["summary"]
                and existing["detail"] == data.get("detail", "")
            )
            if not same:
                raise ConflictError("证据编号已被不同内容占用")
            return {"evidence": existing, "replayed": True}
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            """INSERT INTO incident_evidence(case_id,evidence_code,kind,summary,detail,submitted_by,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (case_id, evidence_code, data["kind"], data["summary"], data.get("detail", ""), principal.user_id, now),
        )
        evidence = dict(
            self.connection.execute("SELECT * FROM incident_evidence WHERE id=?", (cursor.lastrowid,)).fetchone()
        )
        self._timeline(case_id, "evidence.added", f"追加证据 {evidence_code}：{data['summary']}", principal.user_id, now)
        self.audit.record(
            principal, "incident.evidence", "incident_case", str(case_id),
            after=evidence, metadata={"evidence_code": evidence_code},
        )
        return {"evidence": evidence, "replayed": False}

    def delete_evidence(self, principal: Principal, case_id: int, evidence_id: int) -> dict[str, Any]:
        # 调查证据只允许追加：incidents.evidence.purge 刻意不授予任何内置角色，
        # 普通管理员（包括 administrator）调用此接口一律 403。
        principal.require("incidents.evidence.purge")
        case = self.incidents.get_case(case_id)
        row = self.connection.execute(
            "SELECT * FROM incident_evidence WHERE id=? AND case_id=?", (evidence_id, case_id)
        ).fetchone()
        if row is None:
            raise NotFoundError("证据不存在")
        self.connection.execute("DELETE FROM incident_evidence WHERE id=?", (evidence_id,))
        self.audit.record(
            principal, "incident.evidence_purge", "incident_case", str(case_id),
            before=dict(row), metadata={"evidence_code": row["evidence_code"]},
        )
        return {"deleted": True, "evidence_code": row["evidence_code"]}

    def add_timeline_note(self, principal: Principal, case_id: int, body: str) -> dict[str, Any]:
        case = self.incidents.get_case(case_id)
        self._require_workspace_access(principal, case_id)
        self._require_active(case, "追加时间线")
        entry = self._timeline(case_id, "note", body, principal.user_id, to_storage(self.clock.now()))
        self.audit.record(
            principal, "incident.timeline", "incident_case", str(case_id), metadata={"entry_id": entry["id"]}
        )
        return entry

    # ---------- 状态推进与解除限制 ----------

    def contain(self, principal: Principal, case_id: int, note: str = "") -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get_case(case_id)
        self._require_active(case, "确认遏制")
        now = to_storage(self.clock.now())
        for link in self.incidents.links_for_case(case_id):
            self._apply_link_restriction(case, link, principal.user_id, now)
        replayed = case["state"] == "contained"
        if not replayed:
            self.incidents.update_case(case_id, now, state="contained")
            self._timeline(case_id, "state.changed", "事件已遏制，泄露范围确认受控", principal.user_id, now)
        if note:
            self._timeline(case_id, "note", note, principal.user_id, now)
        self.audit.record(
            principal, "incident.contain", "incident_case", str(case_id), metadata={"replayed": replayed}
        )
        return {**self.detail(principal, case_id), "replayed": replayed}

    def resolve(self, principal: Principal, case_id: int, resolution: str) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get_case(case_id)
        self._require_active(case, "完成整改")
        now = to_storage(self.clock.now())
        released = self._lift_case_restrictions(case, principal.user_id, now)
        updated = self.incidents.update_case(case_id, now, state="resolved", resolution=resolution)
        self._timeline(case_id, "case.resolved", f"整改完成：{resolution}", principal.user_id, now)
        self.audit.record(
            principal, "incident.resolve", "incident_case", str(case_id),
            before=case, after=updated, metadata={"released": released},
        )
        return {**self.detail(principal, case_id), "released": released}

    def dismiss(self, principal: Principal, case_id: int, reason: str) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get_case(case_id)
        self._require_active(case, "确认误报")
        now = to_storage(self.clock.now())
        released = self._lift_case_restrictions(case, principal.user_id, now)
        updated = self.incidents.update_case(case_id, now, state="dismissed", resolution=reason)
        self._timeline(case_id, "case.dismissed", f"确认误报：{reason}", principal.user_id, now)
        self.audit.record(
            principal, "incident.dismiss", "incident_case", str(case_id),
            before=case, after=updated, metadata={"released": released},
        )
        return {**self.detail(principal, case_id), "released": released}

    def release_link(self, principal: Principal, case_id: int, link_id: int) -> dict[str, Any]:
        principal.require("incidents.manage")
        case = self.incidents.get_case(case_id)
        self._require_active(case, "解除单项限制")
        link = self.incidents.get_link(link_id)
        if link["case_id"] != case_id:
            raise NotFoundError("关联不属于该事件")
        if link["link_type"] == "session":
            raise ValidationError("会话一经吊销不可恢复，涉事人员需重新登录")
        snapshot = self.incidents.snapshot_for(case_id, link["dossier_id"])
        if snapshot is None or snapshot["released_at"] is not None:
            raise ConflictError("该关联没有生效中的隔离限制")
        now = to_storage(self.clock.now())
        restored = self._release_snapshot(snapshot, principal.user_id, now)
        self._timeline(
            case_id, "restriction.released",
            f"提前解除档案 #{link['dossier_id']} 的隔离限制", principal.user_id, now,
        )
        self.audit.record(
            principal, "incident.release", "incident_case", str(case_id),
            metadata={"link_id": link_id, "dossier_id": link["dossier_id"], "restored": restored},
        )
        return {"snapshot": self.incidents.snapshot_for(case_id, link["dossier_id"]), "restored": restored}

    # ---------- 服务恢复后重建限制 ----------

    def rebuild_restrictions(self, principal: Principal | None = None) -> dict[str, Any]:
        actor_user_id = principal.user_id if principal else None
        now = to_storage(self.clock.now())
        summary: dict[str, list[int]] = {"requarantined": [], "sessions_revoked": [], "released": []}
        active_cases = self.incidents.list_cases(None)
        for case in active_cases:
            if case["state"] in ACTIVE_CASE_STATES:
                for link in self.incidents.links_for_case(case["id"]):
                    if link["link_type"] == "session":
                        session = self._require_session(link["session_id"])
                        if session["revoked_at"] is None:
                            self._revoke_session(case, link["session_id"], actor_user_id, now)
                            summary["sessions_revoked"].append(link["session_id"])
                    else:
                        dossier = self.dossiers.get(link["dossier_id"])
                        missing_snapshot = self.incidents.snapshot_for(case["id"], dossier["id"]) is None
                        if missing_snapshot or dossier["lifecycle_state"] != "quarantined":
                            self._quarantine_dossier(case, dossier["id"], actor_user_id, now)
                            summary["requarantined"].append(dossier["id"])
            else:
                for snapshot in self.incidents.snapshots_for_case(case["id"], active_only=True):
                    self._release_snapshot(snapshot, actor_user_id, now)
                    summary["released"].append(snapshot["dossier_id"])
                    self._timeline(
                        case["id"], "rebuild.released",
                        f"服务恢复时解除档案 #{snapshot['dossier_id']} 的遗留隔离", actor_user_id, now,
                    )
        context = AuditContext(actor_user_id, principal.display_name if principal else "系统")
        self.audit.record(
            context, "incident.rebuild", "incident_case", None,
            metadata={key: len(value) for key, value in summary.items()},
        )
        return summary

    # ---------- 内部工具 ----------

    def _lift_case_restrictions(
        self, case: dict[str, Any], actor_user_id: int | None, now: str
    ) -> list[int]:
        released: list[int] = []
        for snapshot in self.incidents.snapshots_for_case(case["id"], active_only=True):
            self._release_snapshot(snapshot, actor_user_id, now)
            released.append(snapshot["dossier_id"])
        session_links = [link for link in self.incidents.links_for_case(case["id"]) if link["link_type"] == "session"]
        if session_links:
            self._timeline(
                case["id"], "session.notice",
                "已吊销的登录会话不可恢复，涉事人员需重新登录", actor_user_id, now,
            )
        return released

    def _release_snapshot(
        self, snapshot: dict[str, Any], actor_user_id: int | None, now: str
    ) -> bool:
        """解除一条隔离快照；仅当档案没有其他生效中的隔离时才恢复原状态。"""
        self.incidents.release_snapshot(snapshot["id"], actor_user_id, now)
        dossier_id = snapshot["dossier_id"]
        remaining = self.incidents.active_snapshots_for_dossier(dossier_id)
        dossier = self.dossiers.get(dossier_id)
        if remaining or dossier["lifecycle_state"] != "quarantined":
            return False
        self.connection.execute(
            "UPDATE dossiers SET lifecycle_state=?,version=version+1,updated_at=? WHERE id=?",
            (snapshot["state_before"], now, dossier_id),
        )
        self.dossiers.append_event(
            dossier_id, "incident.released", actor_user_id, now,
            from_state="quarantined", to_state=snapshot["state_before"],
            details={"snapshot_id": snapshot["id"]},
        )
        return True

    def _workspace(self, case: dict[str, Any]) -> dict[str, Any]:
        return {
            "case": case,
            "links": self.incidents.links_for_case(case["id"]),
            "snapshots": self.incidents.snapshots_for_case(case["id"]),
            "assignments": self.incidents.assignments_for_case(case["id"]),
            "evidence": self.incidents.evidence_for_case(case["id"]),
            "timeline": self.incidents.timeline_for_case(case["id"]),
        }

    def _require_workspace_access(self, principal: Principal, case_id: int) -> None:
        if principal.can("incidents.manage"):
            return
        assignment = self.incidents.assignment_for(case_id, principal.user_id)
        if assignment and assignment["revoked_at"] is None:
            return
        raise PermissionDeniedError("仅事件管理人员或受派调查人可访问事件工作区")

    def _require_active(self, case: dict[str, Any], operation: str) -> None:
        if case["state"] in TERMINAL_CASE_STATES:
            raise ConflictError(f"事件已结案（{case['state']}），不能{operation}")

    def _require_session(self, session_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if row is None:
            raise NotFoundError("登录会话不存在")
        return dict(row)

    def _require_user(self, user_id: int) -> None:
        if not self.connection.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise NotFoundError("调查人用户不存在")

    def _timeline(
        self, case_id: int, entry_type: str, body: str, actor_user_id: int | None, now: str
    ) -> dict[str, Any]:
        return self.incidents.append_timeline(case_id, entry_type, body, actor_user_id, now)

    @staticmethod
    def _link_label(link: dict[str, Any]) -> str:
        if link["link_type"] == "session":
            return f"登录会话 #{link['session_id']}"
        kind = "档案" if link["link_type"] == "dossier" else "受控副本"
        return f"{kind} #{link['dossier_id']}"

    @staticmethod
    def _snapshot_digest(case_id: int, dossier: dict[str, Any], state_before: str, now: str) -> str:
        canonical = json.dumps(
            {
                "case_id": case_id,
                "dossier_id": dossier["id"],
                "state_before": state_before,
                "quantity": dossier["quantity"],
                "reserved_quantity": dossier["reserved_quantity"],
                "vault_id": dossier.get("vault_id"),
                "custody_user_id": dossier.get("custody_user_id"),
                "dossier_version": dossier["version"],
                "created_at": now,
            },
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
