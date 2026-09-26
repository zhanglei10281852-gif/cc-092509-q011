from __future__ import annotations


def create_vault(client, admin, code="SEC-V-01"):
    response = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": code, "building": "科研楼", "room": "保密间", "cabinet": "柜一",
            "shelf": "一层", "sensitivity": "normal", "capacity_units": 100,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_dossier(client, admin, code="SEC-D-001", quantity=100):
    vault = create_vault(client, admin, code=f"{code}-V")
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"{code}-B", "project_code": "P-SEC", "expected_count": 3},
    )
    assert batch.status_code == 201, batch.text
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": code, "intake_id": batch.json()["id"], "asset_type": "专利交底",
            "quantity": quantity, "unit": "份", "vault_id": vault["id"],
        },
    )
    assert dossier.status_code == 201, dossier.text
    return dossier.json()


def issue_copy(client, admin, dossier, child_code, quantity):
    response = client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={"requested_quantity": quantity, "children": [{"dossier_code": child_code, "quantity": quantity}]},
    )
    assert response.status_code == 201, response.text
    return response.json()["children"][0]


def create_user(client, admin, username, role_codes):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username, "password": "Invest!23456",
            "display_name": f"用户{username}", "role_codes": role_codes,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def login(client, username):
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Invest!23456", "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def report_leak(client, admin, links, clue_key="MSG-2026-0001", severity="high", description="涉密附件误发外部邮箱"):
    return client.post(
        "/api/incidents",
        headers=admin["headers"],
        json={
            "clue_key": clue_key, "incident_type": "邮件误发", "severity": severity,
            "description": description, "links": links,
        },
    )


def dossier_state(client, admin, dossier_id):
    return client.get(f"/api/dossiers/{dossier_id}", headers=admin["headers"]).json()["lifecycle_state"]


def test_report_freezes_dossier_and_circulating_copies(client, admin):
    parent = create_dossier(client, admin)
    child_one = issue_copy(client, admin, parent, "SEC-D-001-A", 10)
    child_two = issue_copy(client, admin, parent, "SEC-D-001-B", 5)

    response = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": parent["id"]}])
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["merged"] is False
    assert body["case"]["state"] == "open"

    # 涉事档案与仍在流转的副本被立刻冻结
    assert dossier_state(client, admin, parent["id"]) == "quarantined"
    assert dossier_state(client, admin, child_one["id"]) == "quarantined"
    assert dossier_state(client, admin, child_two["id"]) == "quarantined"

    # 隔离快照记录冻结前状态，副本以 copy 关联自动登记
    snapshots = {item["dossier_id"]: item for item in body["snapshots"]}
    assert set(snapshots) == {parent["id"], child_one["id"], child_two["id"]}
    assert all(item["state_before"] == "available" for item in snapshots.values())
    assert all(item["released_at"] is None for item in snapshots.values())
    assert all(item["snapshot_digest"] for item in snapshots.values())
    copy_links = [link for link in body["links"] if link["link_type"] == "copy"]
    assert {link["dossier_id"] for link in copy_links} == {child_one["id"], child_two["id"]}
    assert all(link["auto_linked"] == 1 for link in copy_links)
    assert any(entry["entry_type"] == "case.created" for entry in body["timeline"])


def test_duplicate_clue_merges_instead_of_creating_second_case(client, admin):
    first_dossier = create_dossier(client, admin, code="SEC-D-101")
    second_dossier = create_dossier(client, admin, code="SEC-D-102")

    first = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": first_dossier["id"]}], severity="medium")
    assert first.status_code == 201
    case_id = first.json()["case"]["id"]

    second = report_leak(
        client, admin,
        [{"link_type": "dossier", "dossier_id": first_dossier["id"]},
         {"link_type": "dossier", "dossier_id": second_dossier["id"]}],
        severity="critical", description="同一封邮件再次被发现转发",
    )
    assert second.status_code == 200, second.text
    assert second.json()["merged"] is True
    assert second.json()["case"]["id"] == case_id
    # 重复关联被去重，仅新增一个关联；严重度升级到更高值
    assert len(second.json()["added_link_ids"]) == 1
    assert second.json()["case"]["severity"] == "critical"
    assert dossier_state(client, admin, second_dossier["id"]) == "quarantined"
    assert any(entry["entry_type"] == "report.merged" for entry in second.json()["timeline"])

    listing = client.get("/api/incidents", headers=admin["headers"])
    assert len([case for case in listing.json() if case["clue_key"] == "MSG-2026-0001"]) == 1


def test_quarantine_blocks_loan_disclosure_and_disposal_with_reason(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-201")
    approver_one = create_user(client, admin, "approver-one", ["approver"])
    approver_two = create_user(client, admin, "approver-two", ["approver"])

    # 隔离前完成双人审批，确保处置单本身有效
    approval = client.post(
        "/api/dossiers/approvals",
        headers=admin["headers"],
        json={"action_type": "disposal", "resource_type": "dossier", "resource_id": dossier["id"], "payload": {"quantity": 10}},
    )
    assert approval.status_code == 201, approval.text
    request_id = approval.json()["id"]
    for username in ("approver-one", "approver-two"):
        decided = client.post(
            f"/api/dossiers/approvals/{request_id}/decisions",
            headers=login(client, username),
            json={"decision": "approve"},
        )
        assert decided.status_code == 200, decided.text

    case_id = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}]).json()["case"]["id"]
    detail = client.get(f"/api/incidents/{case_id}", headers=admin["headers"]).json()
    case_code = detail["case"]["case_code"]

    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "requester_user_id": admin["body"]["user"]["id"], "quantity": 5, "due_at": "2026-10-01T00:00:00+00:00"},
    )
    assert loan.status_code == 409
    assert case_code in loan.json()["error"]["message"]
    assert "查阅借阅" in loan.json()["error"]["message"]

    disclosure = client.post(
        f"/api/dossiers/{dossier['id']}/disclosures",
        headers=admin["headers"],
        json={"recipient_code": "EXT-01", "quantity": 5, "idempotency_key": "leak-block-1"},
    )
    assert disclosure.status_code == 409
    assert case_code in disclosure.json()["error"]["message"]
    assert "对外披露" in disclosure.json()["error"]["message"]

    copy_issue = client.post(
        f"/api/dossiers/{dossier['id']}/issue_copys",
        headers=admin["headers"],
        json={"requested_quantity": 5, "children": [{"dossier_code": "SEC-D-201-X", "quantity": 5}]},
    )
    assert copy_issue.status_code == 409
    assert case_code in copy_issue.json()["error"]["message"]
    assert "受控副本签发" in copy_issue.json()["error"]["message"]

    new_approval = client.post(
        "/api/dossiers/approvals",
        headers=admin["headers"],
        json={"action_type": "disposal", "resource_type": "dossier", "resource_id": dossier["id"], "payload": {"quantity": 5}},
    )
    assert new_approval.status_code == 409
    assert case_code in new_approval.json()["error"]["message"]

    executed = client.post(
        f"/api/dossier-operations/disposals/{request_id}",
        headers=admin["headers"],
        json={"method": "碎纸机粉碎", "witness_one": approver_one["id"], "witness_two": approver_two["id"]},
    )
    assert executed.status_code == 409
    assert case_code in executed.json()["error"]["message"]
    assert "合规处置" in executed.json()["error"]["message"]


def test_investigator_views_and_appends_without_lifting_quarantine(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-301")
    investigator = create_user(client, admin, "investigator", ["researcher"])
    outsider = create_user(client, admin, "outsider", ["researcher"])
    case_id = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}]).json()["case"]["id"]

    investigator_headers = login(client, "investigator")
    # 分派前调查组无权进入工作区
    assert client.get(f"/api/incidents/{case_id}", headers=investigator_headers).status_code == 403

    assigned = client.post(
        f"/api/incidents/{case_id}/assignments",
        headers=admin["headers"],
        json={"investigator_user_id": investigator["id"]},
    )
    assert assigned.status_code == 201, assigned.text
    # 分派调查人后事件进入调查阶段
    detail = client.get(f"/api/incidents/{case_id}", headers=investigator_headers)
    assert detail.status_code == 200
    assert detail.json()["case"]["state"] == "investigating"

    # 调查组追加证据与时间线，隔离保持不动
    evidence = client.post(
        f"/api/incidents/{case_id}/evidence",
        headers=investigator_headers,
        json={"evidence_code": "EVD-MAIL-1", "kind": "邮件原件", "summary": "误发邮件头与收件人列表"},
    )
    assert evidence.status_code == 201, evidence.text
    replayed = client.post(
        f"/api/incidents/{case_id}/evidence",
        headers=investigator_headers,
        json={"evidence_code": "EVD-MAIL-1", "kind": "邮件原件", "summary": "误发邮件头与收件人列表"},
    )
    assert replayed.status_code == 201
    assert replayed.json()["replayed"] is True
    note = client.post(
        f"/api/incidents/{case_id}/timeline",
        headers=investigator_headers,
        json={"body": "已联系收件方确认未二次转发"},
    )
    assert note.status_code == 201
    assert dossier_state(client, admin, dossier["id"]) == "quarantined"

    # 未受派人员始终无权查看证据
    assert client.get(f"/api/incidents/{case_id}", headers=login(client, "outsider")).status_code == 403


def test_evidence_cannot_be_deleted_by_admin(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-401")
    case_id = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}]).json()["case"]["id"]
    evidence = client.post(
        f"/api/incidents/{case_id}/evidence",
        headers=admin["headers"],
        json={"evidence_code": "EVD-LOG-1", "kind": "系统日志", "summary": "外发网关日志"},
    )
    assert evidence.status_code == 201
    deleted = client.delete(f"/api/incidents/{case_id}/evidence/{evidence.json()['evidence']['id']}", headers=admin["headers"])
    assert deleted.status_code == 403
    detail = client.get(f"/api/incidents/{case_id}", headers=admin["headers"]).json()
    assert len(detail["evidence"]) == 1


def test_resolve_restores_states_and_allows_loan(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-501")
    child = issue_copy(client, admin, dossier, "SEC-D-501-A", 10)
    case_id = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}]).json()["case"]["id"]

    resolved = client.post(
        f"/api/incidents/{case_id}/resolve",
        headers=admin["headers"],
        json={"resolution": "已召回误发邮件并完成全员保密整改"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["case"]["state"] == "resolved"
    assert set(resolved.json()["released"]) == {dossier["id"], child["id"]}
    assert all(item["released_at"] for item in resolved.json()["snapshots"])
    assert dossier_state(client, admin, dossier["id"]) == "available"
    assert dossier_state(client, admin, child["id"]) == "available"

    loan = client.post(
        "/api/dossiers/access_loans",
        headers=admin["headers"],
        json={"dossier_id": dossier["id"], "requester_user_id": admin["body"]["user"]["id"], "quantity": 5, "due_at": "2026-10-01T00:00:00+00:00"},
    )
    assert loan.status_code == 201, loan.text

    # 结案后不能再追加证据
    late = client.post(
        f"/api/incidents/{case_id}/evidence",
        headers=admin["headers"],
        json={"kind": "补充", "summary": "结案后补充材料"},
    )
    assert late.status_code == 409


def test_dismiss_releases_restrictions_for_false_positive(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-601")
    case_id = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}]).json()["case"]["id"]
    dismissed = client.post(
        f"/api/incidents/{case_id}/dismiss",
        headers=admin["headers"],
        json={"reason": "经核实收件地址为授权合作方，确认误报"},
    )
    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["case"]["state"] == "dismissed"
    assert dismissed.json()["case"]["resolution"] == "经核实收件地址为授权合作方，确认误报"
    assert dossier_state(client, admin, dossier["id"]) == "available"
    assert any(entry["entry_type"] == "case.dismissed" for entry in dismissed.json()["timeline"])


def test_session_link_revokes_session_permanently(client, admin):
    leaker = create_user(client, admin, "leaker", ["researcher"])
    leaker_headers = login(client, "leaker")
    from app.database import get_connection

    session_id = get_connection().execute(
        "SELECT id FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1", (leaker["id"],)
    ).fetchone()[0]

    response = report_leak(client, admin, [{"link_type": "session", "session_id": session_id}], clue_key="MSG-2026-0002")
    assert response.status_code == 201, response.text

    # 会话被立即吊销，令牌失效
    denied = client.get("/api/dossiers", headers=leaker_headers)
    assert denied.status_code == 401

    # 确认误报后会话也不恢复，需重新登录
    case_id = response.json()["case"]["id"]
    client.post(f"/api/incidents/{case_id}/dismiss", headers=admin["headers"], json={"reason": "确认为内部测试邮件"})
    assert client.get("/api/dossiers", headers=leaker_headers).status_code == 401
    assert client.get("/api/dossiers", headers=login(client, "leaker")).status_code == 200


def test_release_single_link_early(client, admin):
    first = create_dossier(client, admin, code="SEC-D-701")
    second = create_dossier(client, admin, code="SEC-D-702")
    reported = report_leak(
        client, admin,
        [{"link_type": "dossier", "dossier_id": first["id"]}, {"link_type": "dossier", "dossier_id": second["id"]}],
    )
    case_id = reported.json()["case"]["id"]
    first_link = next(link for link in reported.json()["links"] if link["dossier_id"] == first["id"])

    released = client.post(f"/api/incidents/{case_id}/links/{first_link['id']}/release", headers=admin["headers"])
    assert released.status_code == 200, released.text
    assert released.json()["restored"] is True
    assert dossier_state(client, admin, first["id"]) == "available"
    assert dossier_state(client, admin, second["id"]) == "quarantined"

    resolved = client.post(
        f"/api/incidents/{case_id}/resolve", headers=admin["headers"], json={"resolution": "整改完成"}
    )
    assert resolved.status_code == 200
    assert dossier_state(client, admin, second["id"]) == "available"


def test_overlapping_cases_restore_only_after_last_release(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-801")
    case_a = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}], clue_key="MSG-A").json()["case"]["id"]
    case_b = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}], clue_key="MSG-B").json()["case"]["id"]

    client.post(f"/api/incidents/{case_a}/resolve", headers=admin["headers"], json={"resolution": "事件 A 整改完成"})
    assert dossier_state(client, admin, dossier["id"]) == "quarantined"

    client.post(f"/api/incidents/{case_b}/resolve", headers=admin["headers"], json={"resolution": "事件 B 整改完成"})
    assert dossier_state(client, admin, dossier["id"]) == "available"


def test_rebuild_restores_restrictions_after_service_drift(client, admin):
    from app.database import get_connection

    dossier = create_dossier(client, admin, code="SEC-D-901")
    leaker = create_user(client, admin, "drift-leaker", ["researcher"])
    login(client, "drift-leaker")
    session_id = get_connection().execute(
        "SELECT id FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1", (leaker["id"],)
    ).fetchone()[0]
    case_id = report_leak(
        client, admin,
        [{"link_type": "dossier", "dossier_id": dossier["id"]}, {"link_type": "session", "session_id": session_id}],
        clue_key="MSG-DRIFT",
    ).json()["case"]["id"]

    # 模拟服务中断期间状态被绕过：档案脱离隔离、会话被恢复
    connection = get_connection()
    connection.execute("UPDATE dossiers SET lifecycle_state='available' WHERE id=?", (dossier["id"],))
    connection.execute("UPDATE sessions SET revoked_at=NULL,revoke_reason=NULL WHERE id=?", (session_id,))

    rebuilt = client.post("/api/incidents/rebuild", headers=admin["headers"])
    assert rebuilt.status_code == 200, rebuilt.text
    assert dossier["id"] in rebuilt.json()["requarantined"]
    assert session_id in rebuilt.json()["sessions_revoked"]
    assert dossier_state(client, admin, dossier["id"]) == "quarantined"
    revoked = connection.execute("SELECT revoked_at FROM sessions WHERE id=?", (session_id,)).fetchone()[0]
    assert revoked is not None

    # 结案后重建会解除遗留隔离而不是重新冻结
    client.post(f"/api/incidents/{case_id}/resolve", headers=admin["headers"], json={"resolution": "整改完成"})
    connection.execute("UPDATE dossiers SET lifecycle_state='quarantined' WHERE id=?", (dossier["id"],))
    connection.execute("UPDATE incident_snapshots SET released_at=NULL WHERE dossier_id=?", (dossier["id"],))
    again = client.post("/api/incidents/rebuild", headers=admin["headers"])
    assert dossier["id"] in again.json()["released"]
    assert dossier_state(client, admin, dossier["id"]) == "available"


def test_contain_marks_case_and_is_idempotent(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-121")
    case_id = report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}]).json()["case"]["id"]

    contained = client.post(
        f"/api/incidents/{case_id}/contain", headers=admin["headers"], json={"note": "泄露范围已确认"}
    )
    assert contained.status_code == 200, contained.text
    assert contained.json()["case"]["state"] == "contained"
    assert contained.json()["replayed"] is False

    again = client.post(f"/api/incidents/{case_id}/contain", headers=admin["headers"], json={})
    assert again.status_code == 200
    assert again.json()["replayed"] is True
    assert dossier_state(client, admin, dossier["id"]) == "quarantined"


def test_restrictions_rebuilt_when_service_restarts(client, admin):
    from fastapi.testclient import TestClient

    from app.database import get_connection
    from app.main import app

    dossier = create_dossier(client, admin, code="SEC-D-911")
    report_leak(client, admin, [{"link_type": "dossier", "dossier_id": dossier["id"]}], clue_key="MSG-RESTART")

    # 模拟停机期间隔离状态被绕过
    get_connection().execute("UPDATE dossiers SET lifecycle_state='available' WHERE id=?", (dossier["id"],))

    # 新的 TestClient 触发 lifespan，服务恢复时按事件状态重建限制
    with TestClient(app) as restarted:
        detail = restarted.get(f"/api/dossiers/{dossier['id']}", headers=admin["headers"])
        assert detail.json()["lifecycle_state"] == "quarantined"


def test_report_requires_incidents_manage_permission(client, admin):
    dossier = create_dossier(client, admin, code="SEC-D-111")
    create_user(client, admin, "plain-researcher", ["researcher"])
    response = client.post(
        "/api/incidents",
        headers=login(client, "plain-researcher"),
        json={
            "clue_key": "MSG-DENY", "incident_type": "邮件误发", "severity": "low",
            "description": "无权限用户尝试上报", "links": [{"link_type": "dossier", "dossier_id": dossier["id"]}],
        },
    )
    assert response.status_code == 403
    assert dossier_state(client, admin, dossier["id"]) == "available"
