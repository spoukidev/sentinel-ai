from datetime import datetime, timedelta, timezone

from conftest import register
from sqlalchemy import select

from app.models import AuthSession, OrganizationMember
from app.seed import catalog

P = "/api/v1"
ASSET = {"hostname": "lab-01", "ip_address": "192.0.2.10", "operating_system": "Linux", "owner": "Demo Owner"}


def sample(offset=0, outcome="failure"):
    return {
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=1, seconds=offset)).isoformat(),
        "source": "windows",
        "category": "authentication",
        "event_type": "login",
        "hostname": "lab-01",
        "username": "demo-user",
        "action": "login",
        "outcome": outcome,
        "raw_event": "Synthetic authentication",
    }


def add_rule(client, auth, index=0):
    result = client.post(P + "/rules", headers=auth, json=catalog()[index].model_dump())
    assert result.status_code == 201, result.text
    return result.json()


def test_auth_rotation_logout_and_expiration(client, auth, db):
    assert client.get(P + "/auth/me", headers=auth).json()["role"] == "administrator"
    old_refresh = client.cookies.get("sentinel_refresh")
    refreshed = client.post(P + "/auth/refresh")
    assert refreshed.status_code == 200
    new_auth = {"Authorization": "Bearer " + refreshed.json()["access_token"]}
    assert client.get(P + "/auth/me", headers=auth).status_code == 401
    new_refresh = client.cookies.get("sentinel_refresh")
    assert new_refresh != old_refresh
    client.cookies.set("sentinel_refresh", old_refresh, domain="testserver.local", path="/api/v1/auth")
    assert client.post(P + "/auth/refresh").status_code == 401
    client.cookies.set("sentinel_refresh", new_refresh, domain="testserver.local", path="/api/v1/auth")
    assert client.post(P + "/auth/logout", headers=new_auth).status_code == 200
    assert client.get(P + "/auth/me", headers=new_auth).status_code == 401
    assert client.post(P + "/auth/refresh").status_code == 401
    assert all(s.revoked for s in db.scalars(select(AuthSession)).all())


def test_auth_errors_rate_limit_and_origin(client, auth):
    assert client.post(P + "/auth/refresh", headers={"Origin": "https://evil.example"}).status_code == 403
    wrong = client.post(P + "/auth/login", json={"email": "alice@example.com", "password": "wrong"})
    missing = client.post(P + "/auth/login", json={"email": "nobody@example.com", "password": "wrong"})
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json()
    for _ in range(10):
        result = client.post(P + "/auth/login", json={"email": "nobody@example.com", "password": "wrong"})
    assert result.status_code == 429
    assert client.get(P + "/assets").status_code == 401


def test_asset_crud_and_atomic_csv(client, auth):
    created = client.post(P + "/assets", headers=auth, json=ASSET)
    assert created.status_code == 201
    assert client.post(P + "/assets", headers=auth, json=ASSET).status_code == 409


def test_asset_update_search_delete(client, auth):
    asset_id = client.post(P + "/assets", headers=auth, json=ASSET).json()["id"]
    assert (
        client.put(P + f"/assets/{asset_id}", headers=auth, json={**ASSET, "owner": "New Demo Owner"}).json()["owner"]
        == "New Demo Owner"
    )
    assert client.get(P + "/assets?q=lab-", headers=auth).json()["total"] == 1
    assert client.get(P + "/assets?q=missing", headers=auth).json()["total"] == 0
    csv = "hostname,ip_address\nnew-host,192.0.2.20\nbad-host,invalid"
    assert client.post(P + "/assets/import", headers=auth, json={"content": csv}).status_code == 422
    assert client.get(P + "/assets", headers=auth).json()["total"] == 1
    assert client.delete(P + f"/assets/{asset_id}", headers=auth).status_code == 204
    assert client.get(P + f"/assets/{asset_id}", headers=auth).status_code == 404


def test_tenant_isolation_and_mass_assignment(client, auth):
    asset_id = client.post(P + "/assets", headers=auth, json=ASSET).json()["id"]
    rule = add_rule(client, auth)
    client.post(P + "/events/batch", headers=auth, json={"events": [sample(i) for i in range(5)]})
    alert_id = client.get(P + "/alerts", headers=auth).json()["items"][0]["id"]
    other = register(client, "other@example.com")
    for resource, resource_id in [("assets", asset_id), ("alerts", alert_id)]:
        assert client.get(P + f"/{resource}/{resource_id}", headers=other).status_code == 404
    assert client.put(P + f"/rules/{rule['id']}", headers=other, json=catalog()[0].model_dump()).status_code == 404
    assert client.post(P + f"/alerts/{alert_id}/notes", headers=other, json={"body": "cross tenant"}).status_code == 404
    for resource in ["assets", "events", "alerts", "rules"]:
        assert client.get(P + "/" + resource, headers=other).json()["total"] == 0
    assert client.post(P + "/assets", headers=other, json={**ASSET, "organization_id": "injected"}).status_code == 422


def test_viewer_cannot_write(client, auth, db):
    member = db.scalar(select(OrganizationMember))
    member.role = "viewer"
    db.commit()
    assert client.get(P + "/assets", headers=auth).status_code == 200
    assert client.post(P + "/assets", headers=auth, json=ASSET).status_code == 403
    assert client.post(P + "/events", headers=auth, json=sample()).status_code == 403
    assert client.post(P + "/rules", headers=auth, json=catalog()[0].model_dump()).status_code == 403


def test_threshold_dedup_evidence_and_status(client, auth):
    add_rule(client, auth)
    first = [sample(i) for i in range(4)]
    assert client.post(P + "/events/batch", headers=auth, json={"events": first}).json()["accepted"] == 4
    assert client.get(P + "/alerts", headers=auth).json()["total"] == 0
    fifth = sample(-5)
    assert client.post(P + "/events", headers=auth, json=fifth).status_code == 201
    assert client.post(P + "/events/batch", headers=auth, json={"events": first + [fifth]}).json()["duplicates"] == 5
    listing = client.get(P + "/alerts", headers=auth).json()
    assert listing["total"] == 1
    alert_id = listing["items"][0]["id"]
    detail = client.get(P + f"/alerts/{alert_id}", headers=auth).json()
    assert len(detail["evidence"]) == 5
    assert "5 matching events" in detail["description"]
    assert client.patch(P + f"/alerts/{alert_id}", headers=auth, json={"status": "false_positive"}).status_code == 422
    assert client.patch(P + f"/alerts/{alert_id}", headers=auth, json={"status": "investigating"}).status_code == 200
    assert (
        client.post(
            P + f"/alerts/{alert_id}/notes", headers=auth, json={"body": "Checked synthetic source."}
        ).status_code
        == 201
    )
    detail = client.get(P + f"/alerts/{alert_id}", headers=auth).json()
    assert detail["notes"][0]["body"] == "Checked synthetic source."
    assert detail["history"][0]["previous"] == "new"
    assert client.get(P + "/audit-logs", headers=auth).json()["total"] >= 4


def test_windows_disabled_rules_and_benign_events(client, auth):
    rule = add_rule(client, auth)
    old = sample(900)
    client.post(P + "/events/batch", headers=auth, json={"events": [old] + [sample(i) for i in range(4)]})
    assert client.get(P + "/alerts", headers=auth).json()["total"] == 0
    data = catalog()[0].model_dump()
    data["enabled"] = False
    client.put(P + f"/rules/{rule['id']}", headers=auth, json=data)
    client.post(P + "/events/batch", headers=auth, json={"events": [sample(-i) for i in range(5)]})
    assert client.get(P + "/alerts", headers=auth).json()["total"] == 0
    client.post(P + "/events/batch", headers=auth, json={"events": [sample(i, "success") for i in range(10)]})
    assert client.get(P + "/alerts", headers=auth).json()["total"] == 0


def test_invalid_events_body_limits_and_safe_rules(client, auth):
    bad = {**sample(), "source_ip": "999.1.1.1"}
    assert client.post(P + "/events/batch", headers=auth, json={"events": [sample(), bad]}).status_code == 422
    assert client.get(P + "/events", headers=auth).json()["total"] == 0
    assert (
        client.post(P + "/events", headers=auth, json={**sample(), "timestamp": "2020-01-01T00:00:00"}).status_code
        == 422
    )
    assert client.post(P + "/events", headers=auth, content="x" * 2_000_001).status_code == 413
    rule = catalog()[0].model_dump()
    rule["conditions"] = [{"field": "__import__", "op": "eq", "value": "os"}]
    assert client.post(P + "/rules", headers=auth, json=rule).status_code == 422


def test_seed_rule_catalog_all_rules_create_alerts(client, auth):
    for rule in catalog():
        response = client.post(P + "/rules", headers=auth, json=rule.model_dump())
        assert response.status_code == 201
        items = []
        for i in range(rule.threshold):
            data = {
                **sample(i),
                "source": rule.source,
                "hostname": rule.name.replace(" ", "-").lower(),
                "parsed_metadata": {},
            }
            condition = rule.conditions[0]
            if condition.field.startswith("meta."):
                data["parsed_metadata"][condition.field[5:]] = condition.value
            else:
                data[condition.field] = condition.value
            items.append(data)
        assert client.post(P + "/events/batch", headers=auth, json={"events": items}).status_code == 201
    result = client.get(P + "/alerts", headers=auth).json()
    assert result["total"] == 10
    assert {item["severity"] for item in result["items"]} == {"informational", "low", "medium", "high", "critical"}
    assert client.get(P + "/dashboard", headers=auth).json()["active_alerts"] == 10


def test_expired_session_and_jwt_are_rejected(client, auth, db):
    import jwt

    from app.db import now, settings

    token = auth["Authorization"].split()[1]
    claims = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"], audience="sentinelai-web")
    claims["exp"] = now() - timedelta(seconds=1)
    expired = jwt.encode(claims, settings.jwt_secret, algorithm="HS256")
    assert client.get(P + "/auth/me", headers={"Authorization": "Bearer " + expired}).status_code == 401
    session = db.scalar(select(AuthSession))
    session.expires_at = now() - timedelta(seconds=1)
    db.commit()
    assert client.get(P + "/auth/me", headers=auth).status_code == 401
    assert client.post(P + "/auth/refresh").status_code == 401


def test_cross_tenant_assignee_and_analyst_rule_write_rejected(client, auth, db):
    add_rule(client, auth, 7)
    data = {**sample(), "source": "dns", "parsed_metadata": {"domain": "blocked.example"}}
    client.post(P + "/events", headers=auth, json=data)
    alert_id = client.get(P + "/alerts", headers=auth).json()["items"][0]["id"]
    other = register(client, "outsider@example.com")
    other_id = client.get(P + "/auth/me", headers=other).json()["id"]
    assert (
        client.patch(
            P + f"/alerts/{alert_id}", headers=auth, json={"status": "investigating", "assignee": other_id}
        ).status_code
        == 422
    )
    member = db.scalar(select(OrganizationMember).where(OrganizationMember.user_id != other_id))
    member.role = "analyst"
    db.commit()
    assert client.post(P + "/rules", headers=auth, json=catalog()[0].model_dump()).status_code == 403
    assert client.post(P + "/assets", headers=auth, json=ASSET).status_code == 201


def test_auth_origin_required_and_validation_does_not_echo_password(client):
    data = {"email": "invalid", "password": "never-echo-this-password"}
    assert client.post(P + "/auth/login", headers={"Origin": "https://evil.example"}, json=data).status_code == 403
    result = client.post(P + "/auth/login", json=data)
    assert result.status_code == 422
    assert data["password"] not in result.text
    assert "x-request-id" in result.headers


def test_dashboard_mtta_and_mttr_use_first_transitions(client, auth, db):
    from app.models import Alert, AlertStatusHistory

    add_rule(client, auth, 7)
    client.post(
        P + "/events",
        headers=auth,
        json={**sample(), "source": "dns", "parsed_metadata": {"domain": "blocked.example"}},
    )
    alert_id = client.get(P + "/alerts", headers=auth).json()["items"][0]["id"]
    for status in ("investigating", "resolved", "investigating", "resolved"):
        assert client.patch(P + f"/alerts/{alert_id}", headers=auth, json={"status": status}).status_code == 200
    alert = db.get(Alert, alert_id)
    rows = db.scalars(
        select(AlertStatusHistory)
        .where(AlertStatusHistory.alert_id == alert_id)
        .order_by(AlertStatusHistory.created_at)
    ).all()
    assert len(rows) == 4
    for minutes, row in zip((10, 30, 50, 70), rows, strict=True):
        row.created_at = alert.created_at + timedelta(minutes=minutes)
    db.commit()
    dashboard = client.get(P + "/dashboard", headers=auth).json()
    assert dashboard["mtta_minutes"] == 10.0
    assert dashboard["mttr_minutes"] == 30.0
    other = register(client, "outsider@example.com")
    assert client.get(P + "/dashboard", headers=other).json()["mtta_minutes"] is None
