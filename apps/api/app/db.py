import secrets
from datetime import datetime, timezone
from uuid import uuid4

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Settings(BaseSettings):
    database_url: str = "sqlite:///./sentinel.db"
    jwt_secret: str = ""
    app_origin: str = "http://localhost:3000"
    cookie_secure: bool = False
    demo_mode: bool = False
    demo_password: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
if not settings.jwt_secret:
    if not settings.database_url.startswith("sqlite"):
        raise RuntimeError("JWT_SECRET is required for PostgreSQL deployments")
    settings.jwt_secret = secrets.token_urlsafe(48)
elif len(settings.jwt_secret) < 32:
    raise RuntimeError("JWT_SECRET must contain at least 32 characters")

engine = create_engine(settings.database_url, pool_pre_ping=True)
if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def sqlite_constraints(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")


SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def uid():
    return str(uuid4())


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_db():
    with SessionLocal() as db:
        yield db
