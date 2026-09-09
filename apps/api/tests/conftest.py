import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.security import attempts


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def constraints(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with sessionmaker(engine, expire_on_commit=False)() as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(db):
    def override():
        yield db

    app.dependency_overrides[get_db] = override
    attempts.clear()
    with TestClient(app, headers={"Origin": "http://localhost:3000"}) as client:
        yield client
    app.dependency_overrides.clear()


def register(client, email="alice@example.com"):
    result = client.post(
        "/api/v1/auth/register",
        json={
            "name": "Demo Analyst",
            "email": email,
            "password": "Test-only-password-426!",
            "organization": "Example Lab",
        },
    )
    assert result.status_code == 201, result.text
    return {"Authorization": f"Bearer {result.json()['access_token']}"}


@pytest.fixture
def auth(client):
    return register(client)
