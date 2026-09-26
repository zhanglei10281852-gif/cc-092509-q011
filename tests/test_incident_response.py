from __future__ import annotations


def _create_user(client, admin, username, role_codes):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": username, "password": "Research!23456", "display_name": username, "role_codes": role_codes},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, username, password="Research!23456"):
    response = client.post("/api/auth/login", json={"username": username, "password": password, "client_label": "tests"})
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    return token, me.json()["session_id"]


def _bootstrap_dossier(client, admin, code="LEAK-001"):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={"code": f"V-{code}", "building": "档案楼", "room": "常温库", "cabinet": "一号柜", "shelf": "一层", "sensitivity": "normal", "capacity_units": 100},
    ).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"B-{code}", "project_code": "P-LEAK", "expected_count": 5},
    ).json()
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={"dossier_code": code, "intake_id": batch["id"], "asset_type": "技术秘密载体", "quantity": 50, "unit": "份", "vault_id": vault["id"]},
    ).json()
    return vault, batch, dossier


def _report(client, admin, **overrides):
    payload = {
        "clue_key": "clue-default",
        "incident_type": "邮件误发",
        "severity": "high",
        "description": "含技术秘密附件的邮件误发外部邮箱",
    }
    payload.update(overrides)
    response = client.post("/api/dossiers/incidents", headers=admin["headers"], json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_report_freezes_dossiers_copies_and_sessions(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    issued = client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={"requested_quantity": 10, "children": [{"dossier_code": "LEAK-001-A", "quantity": 10}]},
    )
    assert issued.status_code == 201, issued.text
    copy_id = issued.json()["children"][0]["id"]
    _create_user(client, admin, "leak.suspect", ["researcher"])
    suspect_token, suspect_session = _login(client, "leak.suspect")

    body = _report(
        client,
        admin,
        clue_key="mail-misdirect-001",
        dossier_ids=[dossier["id"]],
        copy_ids=[copy_id],
        session_ids=[suspect_session],
    )
    assert body["merged"] is False
    case_id = body["case"]["id"]
    assert body["case"]["report_count"] == 1
    assert {link["target_type"] for link in body["links"]} == {"dossier", "copy", "session"}

    for target in (dossier["id"], copy_id):
        detail = client.get(f"/api/dossiers/{target}", headers=admin["headers"])
        assert detail.json()["lifecycle_state"] == "quarantined"
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {suspect_token}"}).status_code == 401

    detail = client.get(f"/api/dossiers/incidents/{case_id}", headers=admin["headers"])
    assert detail.status_code == 200
    payload = detail.json()
    assert len(payload["links"]) == 3
    assert len(payload["snapshots"]) == 3
    dossier_snapshot = next(item for item in payload["snapshots"] if item["target_type"] == "dossier")
    assert dossier_snapshot["snapshot"]["lifecycle_state"] == "available"
    assert payload["timeline"][0]["event_type"] == "reported"


def test_quarantine_blocks_loan_disclosure_disposal_and_copy_issue_with_reason(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    case = _report(client, admin, clue_key="clue-guard", dossier_ids=[dossier["id"]])["case"]
    case_code = case["case_code"]

    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "requester_user_id": admin["body"]["user"]["id"], "quantity": 1, "due_at": "2026-10-01T00:00:00+00:00"},
    )
    assert loan.status_code == 409
    assert case_code in loan.json()["error"]["message"]

    disclosure = client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={"recipient_code": "EXT-01", "quantity": 1, "idempotency_key": "leak-guard-1"},
    )
    assert disclosure.status_code == 409
    assert case_code in disclosure.json()["error"]["message"]

    approval = client.post(
        "/api/dossiers/approvals",
        headers=admin["headers"],
        json={"action_type": "disposal", "resource_type": "dossier", "resource_id": dossier["id"], "payload": {"quantity": 1}},
    )
    assert approval.status_code == 409
    assert case_code in approval.json()["error"]["message"]

    issue = client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={"requested_quantity": 1, "children": [{"dossier_code": "LEAK-GUARD-C", "quantity": 1}]},
    )
    assert issue.status_code == 409
    assert case_code in issue.json()["error"]["message"]


def test_duplicate_clue_merges_instead_of_creating_second_case(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _, _, other = _bootstrap_dossier(client, admin, code="LEAK-002")
    first = _report(client, admin, clue_key="clue-merge", dossier_ids=[dossier["id"]])

    second = client.post(
        "/api/dossiers/incidents",
        headers=admin["headers"],
        json={
            "clue_key": "clue-merge",
            "incident_type": "邮件误发",
            "severity": "critical",
            "description": "同一邮件误发线索的再次上报",
            "dossier_ids": [other["id"]],
        },
    )
    assert second.status_code == 201, second.text
    merged = second.json()
    assert merged["merged"] is True
    assert merged["case"]["id"] == first["case"]["id"]
    assert merged["case"]["report_count"] == 2
    assert merged["case"]["severity"] == "critical"
    assert client.get(f"/api/dossiers/{other['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"

    listing = client.get("/api/dossiers/incidents/list", headers=admin["headers"]).json()
    assert len([case for case in listing if case["clue_key"] == "clue-merge"]) == 1

    detail = client.get(f"/api/dossiers/incidents/{first['case']['id']}", headers=admin["headers"]).json()
    assert any(entry["event_type"] == "duplicate_report" for entry in detail["timeline"])


def test_investigator_views_and_appends_evidence_while_outsider_is_denied(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    investigator = _create_user(client, admin, "leak.investigator", ["auditor"])
    investigator_token, _ = _login(client, "leak.investigator")
    _create_user(client, admin, "leak.outsider", ["auditor"])
    outsider_token, _ = _login(client, "leak.outsider")
    case_id = _report(client, admin, clue_key="clue-investigate", dossier_ids=[dossier["id"]])["case"]["id"]

    denied = client.get(f"/api/dossiers/incidents/{case_id}", headers={"Authorization": f"Bearer {outsider_token}"})
    assert denied.status_code == 403

    assigned = client.post(
        f"/api/dossiers/incidents/{case_id}/investigators",
        headers=admin["headers"],
        json={"user_id": investigator["id"]},
    )
    assert assigned.status_code == 201, assigned.text

    headers = {"Authorization": f"Bearer {investigator_token}"}
    detail = client.get(f"/api/dossiers/incidents/{case_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["investigators"][0]["user_id"] == investigator["id"]

    evidence = client.post(
        f"/api/dossiers/incidents/{case_id}/evidence",
        headers=headers,
        json={"evidence_kind": "邮件头", "label": "误发邮件原始头", "uri": "milter://archive/001", "note": "收件人拼写错误"},
    )
    assert evidence.status_code == 201, evidence.text
    assert evidence.json()["digest"]

    # 调查证据为只追加：普通管理员也没有删除入口
    deleted = client.delete(f"/api/dossiers/incidents/{case_id}/evidence", headers=admin["headers"])
    assert deleted.status_code == 405

    entry = client.post(
        f"/api/dossiers/incidents/{case_id}/timeline",
        headers=headers,
        json={"event_type": "访谈", "note": "与当事人确认误发经过"},
    )
    assert entry.status_code == 201, entry.text
    timeline = client.get(f"/api/dossiers/incidents/{case_id}", headers=headers).json()["timeline"]
    assert any(item["event_type"] == "访谈" for item in timeline)


def test_dismiss_releases_dossier_and_session_restrictions(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _create_user(client, admin, "leak.user2", ["researcher"])
    token, session_id = _login(client, "leak.user2")
    case_id = _report(client, admin, clue_key="clue-dismiss", dossier_ids=[dossier["id"]], session_ids=[session_id])["case"]["id"]
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    dismissed = client.post(
        f"/api/dossiers/incidents/{case_id}/dismiss",
        headers=admin["headers"],
        json={"reason": "确认为内部测试邮件，未造成外泄"},
    )
    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["case"]["state"] == "dismissed"
    assert len(dismissed.json()["released_links"]) == 2

    restored = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert restored["lifecycle_state"] == "available"
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # 结案后不能再追加关联或证据
    blocked = client.post(f"/api/dossiers/incidents/{case_id}/links", headers=admin["headers"], json={"dossier_ids": [dossier["id"]]})
    assert blocked.status_code == 409


def test_investigate_contain_resolve_flow_restores_dossier(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    case_id = _report(client, admin, clue_key="clue-resolve", dossier_ids=[dossier["id"]])["case"]["id"]

    investigating = client.post(f"/api/dossiers/incidents/{case_id}/investigate", headers=admin["headers"])
    assert investigating.json()["state"] == "investigating"
    contained = client.post(f"/api/dossiers/incidents/{case_id}/contain", headers=admin["headers"])
    assert contained.json()["state"] == "contained"
    resolved = client.post(
        f"/api/dossiers/incidents/{case_id}/resolve",
        headers=admin["headers"],
        json={"resolution": "已召回误发邮件，完成全员保密整改"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["case"]["state"] == "resolved"
    assert "整改" in resolved.json()["case"]["resolution"]
    assert client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "available"

    again = client.post(f"/api/dossiers/incidents/{case_id}/resolve", headers=admin["headers"], json={"resolution": "重复结案"})
    assert again.status_code == 409


def test_loan_return_does_not_break_quarantine(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "requester_user_id": admin["body"]["user"]["id"], "quantity": 5, "due_at": "2026-10-01T00:00:00+00:00"},
    )
    assert loan.status_code == 201, loan.text
    case_id = _report(client, admin, clue_key="clue-loan", dossier_ids=[dossier["id"]])["case"]["id"]
    assert client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"

    returned = client.post(f"/api/dossiers/access_loans/{loan.json()['id']}/returns", headers=admin["headers"], json={"quantity": 5})
    assert returned.status_code == 200, returned.text
    # 归还不能解除事件隔离
    assert client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"

    client.post(f"/api/dossiers/incidents/{case_id}/resolve", headers=admin["headers"], json={"resolution": "整改完成，解除隔离"})
    restored = client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()
    assert restored["lifecycle_state"] == "available"


def test_rebuild_restrictions_recovers_freeze_and_release(client, admin):
    from app.archives.incident_response import IncidentResponseService
    from app.database import transaction

    _, _, dossier = _bootstrap_dossier(client, admin)
    case_id = _report(client, admin, clue_key="clue-rebuild", dossier_ids=[dossier["id"]])["case"]["id"]

    # 运行期间限制被绕过：服务恢复后按未结案状态重新冻结
    with transaction(immediate=True) as connection:
        connection.execute("UPDATE dossiers SET lifecycle_state='available' WHERE id=?", (dossier["id"],))
    with transaction(immediate=True) as connection:
        result = IncidentResponseService(connection).rebuild_restrictions()
    assert result["refrozen"] == 1
    assert client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "quarantined"

    # 已结案事件的残留冻结在恢复时被解除
    client.post(f"/api/dossiers/incidents/{case_id}/resolve", headers=admin["headers"], json={"resolution": "整改完成"})
    with transaction(immediate=True) as connection:
        connection.execute("UPDATE dossiers SET lifecycle_state='quarantined' WHERE id=?", (dossier["id"],))
        connection.execute("UPDATE incident_links SET freeze_state='frozen',released_at=NULL,release_reason=NULL")
    with transaction(immediate=True) as connection:
        result = IncidentResponseService(connection).rebuild_restrictions()
    assert result["released"] == 1
    assert client.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"]).json()["lifecycle_state"] == "available"


def test_copy_link_requires_issued_copy(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    response = client.post(
        "/api/dossiers/incidents",
        headers=admin["headers"],
        json={
            "clue_key": "clue-bad-copy",
            "incident_type": "邮件误发",
            "severity": "low",
            "description": "尝试把原始档案登记为副本",
            "copy_ids": [dossier["id"]],
        },
    )
    assert response.status_code == 422
