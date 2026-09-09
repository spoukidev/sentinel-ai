from datetime import timedelta, timezone

from sqlalchemy import func, select

from .db import SessionLocal, now, settings
from .detection import ingest
from .models import (
    Alert,
    AlertNote,
    AlertStatusHistory,
    Asset,
    DetectionRule,
    Organization,
    OrganizationMember,
    SecurityEvent,
    User,
)
from .schemas import EventInput, RuleInput
from .security import audit, hasher


def catalog():
    examples = [
        ("Repeated failed sign-ins", "windows", "outcome", "eq", "failure", 5, "high", "Credential Access", "T1110"),
        (
            "Privileged sign-in observed",
            "windows",
            "action",
            "eq",
            "privileged_login",
            1,
            "informational",
            "Defense Evasion",
            "T1078",
        ),
        (
            "New country sign-in signal",
            "cloud",
            "meta.new_country",
            "eq",
            True,
            1,
            "medium",
            "Defense Evasion",
            "T1078",
        ),
        ("Administrator role assigned", "cloud", "action", "eq", "assign_admin", 1, "critical", "Persistence", "T1098"),
        ("Unusual outbound volume", "firewall", "meta.bytes", "gte", 50000000, 1, "high", "Exfiltration", "T1048"),
        ("Repeated missing web resources", "web", "outcome", "eq", "not_found", 5, "low", "Reconnaissance", "T1595"),
        (
            "Synthetic command indicator",
            "windows",
            "raw_event",
            "contains",
            "DEMO_POWERSHELL_INDICATOR",
            1,
            "high",
            "Execution",
            "T1059.001",
        ),
        (
            "Demo-blocklisted DNS request",
            "dns",
            "meta.domain",
            "eq",
            "blocked.example",
            1,
            "critical",
            "Command and Control",
            "T1071.004",
        ),
        (
            "Security control disabled",
            "cloud",
            "action",
            "eq",
            "disable_control",
            1,
            "critical",
            "Defense Evasion",
            "T1562.001",
        ),
        ("Synthetic travel signal", "cloud", "meta.travel_signal", "eq", True, 1, "medium", "Defense Evasion", "T1078"),
    ]
    return [
        RuleInput(
            name=name,
            description=f"Synthetic demonstration of {name.lower()}. Verify context before drawing conclusions.",
            source=source,
            conditions=[{"field": field, "op": op, "value": value}],
            threshold=threshold,
            window_seconds=300,
            severity=severity,
            tactic=tactic,
            technique=technique,
            tags=["synthetic", "demo"],
            recommended_response="Review the referenced events, confirm the activity with the asset owner, and compare with approved changes. Document findings before any manual defensive action.",
        )
        for name, source, field, op, value, threshold, severity, tactic, technique in examples
    ]


def seed():
    if not settings.demo_mode or len(settings.demo_password) < 12:
        raise RuntimeError("Set DEMO_MODE=true and a development-only DEMO_PASSWORD of at least 12 characters")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == "admin@sentinel.example")):
            print("Demo already seeded; existing data preserved.")
            return
        org = Organization(name="Northstar Labs")
        db.add(org)
        db.flush()
        admin = None
        for role, name in [("administrator", "Demo Admin"), ("analyst", "Demo Analyst"), ("viewer", "Demo Viewer")]:
            user = User(
                name=name,
                email=f"{'admin' if role == 'administrator' else role}@sentinel.example",
                password_hash=hasher.hash(settings.demo_password),
            )
            db.add(user)
            db.flush()
            member = OrganizationMember(user_id=user.id, organization_id=org.id, role=role)
            db.add(member)
            if role == "administrator":
                admin = member
        hosts = [f"{prefix}-{i:02}" for prefix in ["edge", "srv", "ws", "cloud"] for i in range(1, 6)]
        for i, host in enumerate(hosts):
            db.add(
                Asset(
                    organization_id=org.id,
                    hostname=host,
                    ip_address=f"192.0.2.{i + 10}",
                    operating_system="Windows 11" if host.startswith("ws") else "Linux",
                    asset_type="workstation" if host.startswith("ws") else "server",
                    owner="Demo Operations",
                    department=["Engineering", "Security", "Finance"][i % 3],
                    criticality="critical" if i % 4 == 0 else "medium",
                    tags=["synthetic", "lab"],
                )
            )
        rules = catalog()
        for rule in rules:
            db.add(DetectionRule(organization_id=org.id, **rule.model_dump()))
        db.flush()
        base = now().replace(tzinfo=timezone.utc) - timedelta(days=7)
        inputs = []
        for i in range(500):
            inputs.append(
                EventInput(
                    timestamp=base + timedelta(minutes=i * 19),
                    source=["windows", "linux", "web", "firewall", "dns", "cloud"][i % 6],
                    category="baseline",
                    event_type="routine_activity",
                    hostname=hosts[i % 20],
                    username="demo-user",
                    action="routine",
                    outcome="success",
                    source_ip=f"198.51.100.{i % 100 + 1}",
                    raw_event="Synthetic benign baseline",
                )
            )
        for round_number in range(4):
            for index, rule in enumerate(rules):
                condition = rule.conditions[0]
                for offset in range(rule.threshold):
                    values = dict(
                        timestamp=base + timedelta(days=round_number + 2, minutes=index * 17, seconds=offset * 10),
                        source=rule.source,
                        category="demo",
                        event_type=f"scenario_{index + 1}",
                        hostname=hosts[(index + round_number * 3) % 20],
                        username="demo-user",
                        action="sample",
                        outcome="success",
                        raw_event="Synthetic scenario",
                        parsed_metadata={},
                    )
                    if condition.field.startswith("meta."):
                        values["parsed_metadata"][condition.field[5:]] = condition.value
                    else:
                        values[condition.field] = str(condition.value)
                    inputs.append(EventInput(**values))
        ingest(db, org.id, inputs)
        alerts = db.scalars(select(Alert).where(Alert.organization_id == org.id).order_by(Alert.created_at)).all()
        for index, alert in enumerate(alerts[:10]):
            new_status = "false_positive" if index == 0 else "resolved" if index < 4 else "investigating"
            alert.status = new_status
            alert.false_positive_reason = (
                "Approved synthetic test. Confirmed with the fictional asset owner." if index == 0 else ""
            )
            alert.assignee = admin.user_id
            db.add(AlertStatusHistory(alert_id=alert.id, actor_id=admin.user_id, previous="new", status=new_status))
            db.add(
                AlertNote(
                    alert_id=alert.id,
                    actor_id=admin.user_id,
                    body="Synthetic demonstration: reviewed source event and compared with the lab change schedule.",
                )
            )
            audit(db, admin, "alert.updated", "alert", alert.id, {"status": new_status})
        audit(db, admin, "demo.seeded", "organization", org.id, {"synthetic": True})
        db.commit()
        print(
            f"Seeded 20 assets, {db.scalar(select(func.count()).select_from(SecurityEvent))} events, {len(alerts)} alerts and 10 rules. Password read from environment; never logged."
        )


if __name__ == "__main__":
    seed()
