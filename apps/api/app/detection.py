import hashlib
import json
from datetime import timedelta

from sqlalchemy import select

from .models import Alert, AlertEvidence, Asset, DetectionRule, Organization, SecurityEvent

RISK = {"informational": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}


def matches(event, conditions):
    for condition in conditions:
        field, op, expected = condition["field"], condition["op"], condition["value"]
        actual = event.parsed_metadata.get(field[5:]) if field.startswith("meta.") else getattr(event, field, None)
        if op == "eq" and actual != expected:
            return False
        if op == "contains" and (not isinstance(actual, str) or str(expected).lower() not in actual.lower()):
            return False
        if op == "gte" and (
            not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)) or actual < expected
        ):
            return False
    return True


def evaluate(db, event):
    rules = db.scalars(
        select(DetectionRule).where(
            DetectionRule.organization_id == event.organization_id,
            DetectionRule.enabled.is_(True),
            DetectionRule.source == event.source,
        )
    ).all()
    for rule in rules:
        if not matches(event, rule.conditions):
            continue
        start = event.timestamp - timedelta(seconds=rule.window_seconds)
        candidates = db.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.organization_id == event.organization_id,
                SecurityEvent.source == event.source,
                SecurityEvent.hostname == event.hostname,
                SecurityEvent.username == event.username,
                SecurityEvent.timestamp >= start,
                SecurityEvent.timestamp <= event.timestamp,
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(1000)
        ).all()
        evidence = [candidate for candidate in candidates if matches(candidate, rule.conditions)]
        if len(evidence) < rule.threshold:
            continue
        # Sliding-window suppression is scoped to rule + host + user, not just time buckets.
        previous = db.scalar(
            select(Alert).where(
                Alert.organization_id == event.organization_id,
                Alert.rule_id == rule.id,
                Alert.hostname == event.hostname,
                Alert.username == event.username,
                Alert.last_seen >= start,
                Alert.first_seen <= event.timestamp + timedelta(seconds=rule.window_seconds),
            )
        )
        if previous:
            previous.last_seen = max(previous.last_seen, event.timestamp)
            known = set(db.scalars(select(AlertEvidence.event_id).where(AlertEvidence.alert_id == previous.id)).all())
            for item in evidence:
                if item.id not in known:
                    db.add(AlertEvidence(alert_id=previous.id, event_id=item.id))
            continue
        asset = db.scalar(
            select(Asset).where(Asset.organization_id == event.organization_id, Asset.hostname == event.hostname)
        )
        key = hashlib.sha256(f"{rule.id}:{event.id}".encode()).hexdigest()
        alert = Alert(
            organization_id=event.organization_id,
            title=rule.name,
            description=f"{len(evidence)} matching events for {event.hostname} / {event.username or 'unknown user'} within {rule.window_seconds}s. Conditions: {json.dumps(rule.conditions)}. This is a detection signal, not proof of compromise.",
            severity=rule.severity,
            source=event.source,
            rule_id=rule.id,
            asset_id=asset.id if asset else None,
            username=event.username,
            hostname=event.hostname,
            tactic=rule.tactic,
            technique=rule.technique,
            risk_score=RISK[rule.severity],
            first_seen=min(item.timestamp for item in evidence),
            last_seen=event.timestamp,
            dedup_key=key,
        )
        db.add(alert)
        db.flush()
        for item in evidence:
            db.add(AlertEvidence(alert_id=alert.id, event_id=item.id))


def ingest(db, organization_id, inputs):
    db.execute(select(Organization).where(Organization.id == organization_id).with_for_update()).scalar_one()
    accepted, duplicates = 0, 0
    for data in sorted(inputs, key=lambda item: item.timestamp):
        values = data.model_dump(mode="json")
        fingerprint = hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
        if db.scalar(
            select(SecurityEvent.id).where(
                SecurityEvent.organization_id == organization_id, SecurityEvent.fingerprint == fingerprint
            )
        ):
            duplicates += 1
            continue
        values["timestamp"] = data.timestamp.replace(tzinfo=None)
        event = SecurityEvent(organization_id=organization_id, fingerprint=fingerprint, **values)
        db.add(event)
        db.flush()
        asset = db.scalar(
            select(Asset).where(Asset.organization_id == organization_id, Asset.hostname == event.hostname)
        )
        if asset and (asset.last_seen is None or event.timestamp > asset.last_seen):
            asset.last_seen = event.timestamp
        evaluate(db, event)
        db.flush()
        accepted += 1
    return {"accepted": accepted, "duplicates": duplicates}
