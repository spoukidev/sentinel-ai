import csv
import hashlib
import io
from collections import Counter
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import get_db, now, settings
from .detection import ingest
from .models import (
    Alert,
    AlertEvidence,
    AlertNote,
    AlertStatusHistory,
    Asset,
    AuditLog,
    AuthSession,
    DetectionRule,
    Organization,
    OrganizationMember,
    SecurityEvent,
    User,
)
from .schemas import (
    AlertUpdate,
    AssetInput,
    Batch,
    CsvInput,
    EventInput,
    Login,
    NoteInput,
    Register,
    RoleInput,
    RuleInput,
)
from .security import (
    administrators,
    audit,
    current_member,
    hasher,
    issue,
    origin_check,
    rate_limit,
    verify_password,
    writers,
)

app = FastAPI(title="SentinelAI", version="0.1.0", description="Defensive SOC foundation. Synthetic demo data only.")
P = "/api/v1"


@app.middleware("http")
async def boundaries(request: Request, call_next):
    request_id = str(uuid4())
    # Bound chunked bodies too, before JSON parsing or authentication work.
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 2_000_000:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
    request._body = bytes(body)
    response = await call_next(request)
    response.headers.update(
        {
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        }
    )
    return response


@app.exception_handler(IntegrityError)
async def conflict(_, exc):
    return JSONResponse({"detail": "Resource conflicts with existing data"}, status_code=409)


@app.exception_handler(RequestValidationError)
async def invalid(_, exc):
    return JSONResponse(
        {
            "detail": "Invalid request",
            "errors": [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()],
        },
        status_code=422,
    )


def serialize(obj):
    return {
        column.name: getattr(obj, column.name)
        for column in obj.__table__.columns
        if column.name not in {"password_hash", "token_hash", "fingerprint", "dedup_key"}
    }


def scoped(db, model, resource_id, member):
    obj = db.scalar(select(model).where(model.id == resource_id, model.organization_id == member.organization_id))
    if obj is None:
        raise HTTPException(404, "Resource not found")
    return obj


def page(db, query, page_number, size):
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    return {
        "items": [serialize(item) for item in db.scalars(query.offset((page_number - 1) * size).limit(size)).all()],
        "total": total,
        "page": page_number,
        "page_size": size,
    }


@app.get(P + "/health")
def health():
    return {"status": "ok", "version": "0.1.0", "demo_mode": settings.demo_mode}


@app.get(P + "/health/ready")
def ready(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    db.execute(select(Organization.id).limit(1))
    return {"status": "ready"}


@app.post(P + "/auth/register", status_code=201, dependencies=[Depends(origin_check), Depends(rate_limit)])
def register(data: Register, response: Response, db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == data.email.lower())):
        raise HTTPException(400, "Unable to register with these details")
    org = Organization(name=data.organization)
    user = User(email=data.email.lower(), name=data.name, password_hash=hasher.hash(data.password))
    db.add_all([org, user])
    db.flush()
    member = OrganizationMember(organization_id=org.id, user_id=user.id, role="administrator")
    db.add(member)
    audit(db, member, "auth.register", "user", user.id)
    result = issue(db, user, response)
    db.commit()
    return result


@app.post(P + "/auth/login", dependencies=[Depends(origin_check), Depends(rate_limit)])
def login(data: Login, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    valid = verify_password(data.password, user.password_hash if user else None)
    if not user or not valid:
        if user:
            member = db.scalar(select(OrganizationMember).where(OrganizationMember.user_id == user.id))
            audit(db, member, "auth.login_failed", "user", user.id)
            db.commit()
        raise HTTPException(401, "Invalid email or password")
    member = db.scalar(select(OrganizationMember).where(OrganizationMember.user_id == user.id))
    result = issue(db, user, response)
    audit(db, member, "auth.login", "user", user.id)
    db.commit()
    return result


@app.post(P + "/auth/refresh", dependencies=[Depends(origin_check), Depends(rate_limit)])
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    digest = hashlib.sha256(request.cookies.get("sentinel_refresh", "").encode()).hexdigest()
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == digest).with_for_update())
    if not session or session.revoked or session.expires_at <= now():
        raise HTTPException(401, "Authentication required")
    session.revoked = True
    result = issue(db, db.get(User, session.user_id), response)
    db.commit()
    return result


@app.post(P + "/auth/logout", dependencies=[Depends(origin_check)])
def logout(request: Request, response: Response, member=Depends(current_member), db: Session = Depends(get_db)):
    db.execute(update(AuthSession).where(AuthSession.user_id == member.user_id).values(revoked=True))
    response.delete_cookie("sentinel_refresh", path="/api/v1/auth")
    audit(db, member, "auth.logout", "user", member.user_id)
    db.commit()
    return {"detail": "All sessions revoked"}


@app.get(P + "/auth/me")
def me(member=Depends(current_member), db: Session = Depends(get_db)):
    return {
        **serialize(db.get(User, member.user_id)),
        "role": member.role,
        "organization": serialize(db.get(Organization, member.organization_id)),
    }


@app.get(P + "/organizations/members")
def members(member=Depends(current_member), db: Session = Depends(get_db)):
    return [
        {"id": m.user_id, "role": m.role, "name": u.name, "email": u.email}
        for m, u in db.execute(
            select(OrganizationMember, User)
            .join(User, User.id == OrganizationMember.user_id)
            .where(OrganizationMember.organization_id == member.organization_id)
        )
    ]


@app.patch(P + "/organizations/members/{user_id}")
def role_change(user_id: str, data: RoleInput, member=Depends(administrators), db: Session = Depends(get_db)):
    target = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == member.organization_id, OrganizationMember.user_id == user_id
        )
    )
    if not target:
        raise HTTPException(404, "Member not found")
    if user_id == member.user_id:
        raise HTTPException(400, "Self role changes are not allowed")
    target.role = data.role
    audit(db, member, "member.role_changed", "user", user_id, {"role": data.role})
    db.commit()
    return {"role": target.role}


@app.get(P + "/assets")
def assets(
    q: str = Query("", max_length=120),
    status: str = "",
    sort: str = "hostname",
    page_number: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    member=Depends(current_member),
    db: Session = Depends(get_db),
):
    query = select(Asset).where(
        Asset.organization_id == member.organization_id,
        or_(Asset.hostname.ilike(f"%{q}%"), Asset.ip_address.ilike(f"%{q}%")),
    )
    if status:
        query = query.where(Asset.status == status)
    result = page(
        db, query.order_by(Asset.created_at.desc() if sort == "newest" else Asset.hostname), page_number, page_size
    )
    for item in result["items"]:
        item["risk_score"] = (
            db.scalar(
                select(func.max(Alert.risk_score)).where(
                    Alert.organization_id == member.organization_id,
                    Alert.asset_id == item["id"],
                    Alert.status.in_(["new", "investigating"]),
                )
            )
            or 0
        )
    return result


@app.post(P + "/assets", status_code=201)
def create_asset(data: AssetInput, member=Depends(writers), db: Session = Depends(get_db)):
    asset = Asset(organization_id=member.organization_id, **data.model_dump(mode="json"))
    db.add(asset)
    db.flush()
    audit(db, member, "asset.created", "asset", asset.id)
    db.commit()
    return serialize(asset)


@app.post(P + "/assets/import", status_code=201)
def import_assets(data: CsvInput, member=Depends(writers), db: Session = Depends(get_db)):
    try:
        rows = list(csv.DictReader(io.StringIO(data.content)))
        if not rows or len(rows) > 100:
            raise ValueError("CSV must contain 1â€“100 rows")
        validated = [AssetInput.model_validate(row) for row in rows]
    except (ValidationError, ValueError, csv.Error):
        raise HTTPException(422, "Invalid asset CSV; use the documented sample") from None
    for row in validated:
        db.add(Asset(organization_id=member.organization_id, **row.model_dump(mode="json")))
    audit(db, member, "asset.imported", "asset", "batch", {"count": len(rows)})
    db.commit()
    return {"imported": len(rows)}


@app.get(P + "/assets/{asset_id}")
def asset_detail(asset_id: str, member=Depends(current_member), db: Session = Depends(get_db)):
    asset = scoped(db, Asset, asset_id, member)
    return {
        **serialize(asset),
        "alerts": [
            serialize(a)
            for a in db.scalars(
                select(Alert).where(Alert.organization_id == member.organization_id, Alert.asset_id == asset.id)
            ).all()
        ],
    }


@app.put(P + "/assets/{asset_id}")
def edit_asset(asset_id: str, data: AssetInput, member=Depends(writers), db: Session = Depends(get_db)):
    asset = scoped(db, Asset, asset_id, member)
    for key, value in data.model_dump(mode="json").items():
        setattr(asset, key, value)
    audit(db, member, "asset.updated", "asset", asset.id)
    db.commit()
    return serialize(asset)


@app.delete(P + "/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: str, member=Depends(administrators), db: Session = Depends(get_db)):
    asset = scoped(db, Asset, asset_id, member)
    audit(db, member, "asset.deleted", "asset", asset.id)
    db.delete(asset)
    db.commit()


@app.post(P + "/events/batch", status_code=201)
def batch(data: Batch, member=Depends(writers), db: Session = Depends(get_db)):
    result = ingest(db, member.organization_id, data.events)
    audit(db, member, "events.ingested", "event", "batch", result)
    db.commit()
    return result


@app.post(P + "/events", status_code=201)
def event(data: EventInput, member=Depends(writers), db: Session = Depends(get_db)):
    result = ingest(db, member.organization_id, [data])
    audit(db, member, "events.ingested", "event", "single", result)
    db.commit()
    return result


@app.get(P + "/events")
def events(
    q: str = Query("", max_length=120),
    source: str = "",
    page_number: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    member=Depends(current_member),
    db: Session = Depends(get_db),
):
    query = select(SecurityEvent).where(
        SecurityEvent.organization_id == member.organization_id,
        or_(SecurityEvent.hostname.ilike(f"%{q}%"), SecurityEvent.event_type.ilike(f"%{q}%")),
    )
    if source:
        query = query.where(SecurityEvent.source == source)
    return page(db, query.order_by(SecurityEvent.timestamp.desc()), page_number, page_size)


@app.get(P + "/rules")
def rules(member=Depends(current_member), db: Session = Depends(get_db)):
    return page(
        db,
        select(DetectionRule)
        .where(DetectionRule.organization_id == member.organization_id)
        .order_by(DetectionRule.name),
        1,
        100,
    )


@app.post(P + "/rules", status_code=201)
def create_rule(data: RuleInput, member=Depends(administrators), db: Session = Depends(get_db)):
    if (
        db.scalar(
            select(func.count())
            .select_from(DetectionRule)
            .where(DetectionRule.organization_id == member.organization_id)
        )
        >= 100
    ):
        raise HTTPException(409, "Workspace rule limit reached")
    rule = DetectionRule(organization_id=member.organization_id, **data.model_dump())
    db.add(rule)
    db.flush()
    audit(db, member, "rule.created", "rule", rule.id)
    db.commit()
    return serialize(rule)


@app.put(P + "/rules/{rule_id}")
def edit_rule(rule_id: str, data: RuleInput, member=Depends(administrators), db: Session = Depends(get_db)):
    rule = scoped(db, DetectionRule, rule_id, member)
    for key, value in data.model_dump().items():
        setattr(rule, key, value)
    audit(db, member, "rule.updated", "rule", rule.id)
    db.commit()
    return serialize(rule)


@app.delete(P + "/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, member=Depends(administrators), db: Session = Depends(get_db)):
    rule = scoped(db, DetectionRule, rule_id, member)
    if db.scalar(select(Alert.id).where(Alert.rule_id == rule.id).limit(1)):
        raise HTTPException(409, "Rule has historical alerts; disable it instead")
    audit(db, member, "rule.deleted", "rule", rule.id)
    db.delete(rule)
    db.commit()


@app.get(P + "/alerts")
def alerts(
    q: str = Query("", max_length=120),
    severity: str = "",
    status: str = "",
    sort: str = "newest",
    page_number: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    member=Depends(current_member),
    db: Session = Depends(get_db),
):
    query = select(Alert).where(
        Alert.organization_id == member.organization_id,
        or_(Alert.title.ilike(f"%{q}%"), Alert.hostname.ilike(f"%{q}%")),
    )
    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    return page(
        db,
        query.order_by(Alert.risk_score.desc() if sort == "risk" else Alert.last_seen.desc(), Alert.id),
        page_number,
        page_size,
    )


@app.get(P + "/alerts/{alert_id}")
def alert_detail(alert_id: str, member=Depends(current_member), db: Session = Depends(get_db)):
    alert = scoped(db, Alert, alert_id, member)
    evidence = db.scalars(
        select(SecurityEvent)
        .join(AlertEvidence, AlertEvidence.event_id == SecurityEvent.id)
        .where(AlertEvidence.alert_id == alert.id, SecurityEvent.organization_id == member.organization_id)
        .order_by(SecurityEvent.timestamp)
    ).all()
    return {
        **serialize(alert),
        "evidence": [serialize(e) for e in evidence],
        "notes": [
            serialize(n)
            for n in db.scalars(
                select(AlertNote).where(AlertNote.alert_id == alert.id).order_by(AlertNote.created_at)
            ).all()
        ],
        "history": [
            serialize(h)
            for h in db.scalars(
                select(AlertStatusHistory)
                .where(AlertStatusHistory.alert_id == alert.id)
                .order_by(AlertStatusHistory.created_at)
            ).all()
        ],
        "recommended_response": db.get(DetectionRule, alert.rule_id).recommended_response,
    }


@app.patch(P + "/alerts/{alert_id}")
def update_alert(alert_id: str, data: AlertUpdate, member=Depends(writers), db: Session = Depends(get_db)):
    alert = scoped(db, Alert, alert_id, member)
    if data.status == "false_positive" and not data.false_positive_reason:
        raise HTTPException(422, "A false-positive reason is required")
    if data.assignee and not db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == member.organization_id, OrganizationMember.user_id == data.assignee
        )
    ):
        raise HTTPException(422, "Invalid assignee")
    if alert.status != data.status:
        db.add(
            AlertStatusHistory(alert_id=alert.id, actor_id=member.user_id, previous=alert.status, status=data.status)
        )
    alert.status, alert.assignee, alert.false_positive_reason = data.status, data.assignee, data.false_positive_reason
    audit(db, member, "alert.updated", "alert", alert.id, {"status": data.status, "assignee": data.assignee})
    db.commit()
    return serialize(alert)


@app.post(P + "/alerts/{alert_id}/notes", status_code=201)
def add_note(alert_id: str, data: NoteInput, member=Depends(writers), db: Session = Depends(get_db)):
    alert = scoped(db, Alert, alert_id, member)
    note = AlertNote(alert_id=alert.id, actor_id=member.user_id, body=data.body)
    db.add(note)
    audit(db, member, "alert.note_added", "alert", alert.id)
    db.commit()
    return serialize(note)


@app.get(P + "/audit-logs")
def audit_logs(
    page_number: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    member=Depends(current_member),
    db: Session = Depends(get_db),
):
    return page(
        db,
        select(AuditLog).where(AuditLog.organization_id == member.organization_id).order_by(AuditLog.created_at.desc()),
        page_number,
        page_size,
    )


@app.get(P + "/dashboard")
def dashboard(member=Depends(current_member), db: Session = Depends(get_db)):
    alert_rows = db.scalars(select(Alert).where(Alert.organization_id == member.organization_id)).all()
    active = [a for a in alert_rows if a.status in ["new", "investigating"]]
    dates = Counter(a.first_seen.strftime("%Y-%m-%d") for a in alert_rows)
    ack, resolved = [], []
    for alert in alert_rows:
        history = db.scalars(
            select(AlertStatusHistory)
            .where(AlertStatusHistory.alert_id == alert.id)
            .order_by(AlertStatusHistory.created_at)
        ).all()
        first_ack = next((h for h in history if h.status != "new"), None)
        first_resolve = next((h for h in history if h.status == "resolved"), None)
        if first_ack:
            ack.append((first_ack.created_at - alert.created_at).total_seconds() / 60)
        if first_resolve:
            resolved.append((first_resolve.created_at - alert.created_at).total_seconds() / 60)
    return {
        "active_alerts": len(active),
        "critical_alerts": sum(a.severity == "critical" for a in active),
        "monitored_assets": db.scalar(
            select(func.count()).select_from(Asset).where(Asset.organization_id == member.organization_id)
        ),
        "events": db.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.organization_id == member.organization_id)
        ),
        "mtta_minutes": round(sum(ack) / len(ack), 1) if ack else None,
        "mttr_minutes": round(sum(resolved) / len(resolved), 1) if resolved else None,
        "by_severity": dict(Counter(a.severity for a in active)),
        "by_source": dict(Counter(a.source for a in alert_rows)),
        "by_tactic": dict(Counter(a.tactic for a in alert_rows)),
        "trend": [{"date": date, "alerts": count} for date, count in sorted(dates.items())],
        "recent_alerts": [
            serialize(a) for a in sorted(active, key=lambda a: (a.risk_score, a.last_seen), reverse=True)[:5]
        ],
        "risky_assets": [
            {
                "hostname": host,
                "risk": max(a.risk_score for a in active if a.hostname == host),
                "alerts": sum(a.hostname == host for a in active),
            }
            for host in sorted(
                set(a.hostname for a in active),
                key=lambda host: max(a.risk_score for a in active if a.hostname == host),
                reverse=True,
            )[:5]
        ],
    }
