import hashlib
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta
from threading import Lock

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db, now, settings
from .models import AuditLog, AuthSession, OrganizationMember, User

hasher = PasswordHasher()
dummy_hash = hasher.hash(secrets.token_urlsafe(24))
bearer = HTTPBearer(auto_error=False)
attempts: dict[str, deque] = defaultdict(deque)
limit_lock = Lock()


def rate_limit(request: Request):
    key = request.client.host if request.client else "unknown"
    with limit_lock:
        cutoff = time.monotonic() - 60
        for old_key in list(attempts):
            while attempts[old_key] and attempts[old_key][0] < cutoff:
                attempts[old_key].popleft()
            if not attempts[old_key]:
                del attempts[old_key]
        if len(attempts[key]) >= 10:
            raise HTTPException(429, "Too many attempts; try again later", headers={"Retry-After": "60"})
        attempts[key].append(time.monotonic())


def audit(db, member, action, target_type, target_id, metadata=None):
    db.add(
        AuditLog(
            organization_id=member.organization_id,
            actor_id=member.user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            safe_metadata=metadata or {},
        )
    )


def origin_check(request: Request):
    if request.headers.get("origin") != settings.app_origin:
        raise HTTPException(403, "Origin not allowed")


def issue(db: Session, user: User, response: Response):
    token = secrets.token_urlsafe(48)
    session = AuthSession(
        user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=now() + timedelta(days=7)
    )
    db.add(session)
    db.flush()
    access = jwt.encode(
        {
            "sub": user.id,
            "sid": session.id,
            "exp": now() + timedelta(minutes=15),
            "iat": now(),
            "iss": "sentinelai",
            "aud": "sentinelai-web",
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    response.set_cookie(
        "sentinel_refresh",
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api/v1/auth",
        max_age=604800,
    )
    return {"access_token": access, "token_type": "bearer", "expires_in": 900}


def current_member(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)):
    try:
        if not credentials:
            raise ValueError()
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],
            audience="sentinelai-web",
            issuer="sentinelai",
            options={"require": ["sub", "sid", "exp", "iat"]},
        )
        session = db.get(AuthSession, payload["sid"])
        if not session or session.revoked or session.expires_at <= now() or session.user_id != payload["sub"]:
            raise ValueError()
        member = db.scalar(select(OrganizationMember).where(OrganizationMember.user_id == payload["sub"]))
        if not member:
            raise ValueError()
        return member
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "Authentication required") from None


def writers(member=Depends(current_member)):
    if member.role == "viewer":
        raise HTTPException(403, "Analyst role required")
    return member


def administrators(member=Depends(current_member)):
    if member.role != "administrator":
        raise HTTPException(403, "Administrator role required")
    return member


def verify_password(password, stored):
    try:
        return hasher.verify(stored or dummy_hash, password)
    except VerificationError:
        return False
