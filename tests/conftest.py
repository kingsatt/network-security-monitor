import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from nsm.db.database import Base
from nsm.main import app
from nsm.api.routes import get_db


TEST_DATABASE_URL = "sqlite://"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    bind=test_engine,
    autoflush=False,
    autocommit=False,
)


@pytest.fixture
def client():
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()

        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    import nsm.services.scan_service as scan_service

    original_session_local = scan_service.SessionLocal
    scan_service.SessionLocal = TestingSessionLocal

    with TestClient(app) as test_client:
        yield test_client

    scan_service.SessionLocal = original_session_local

    app.dependency_overrides.clear()

    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture
def db():
    Base.metadata.create_all(bind=test_engine)

    db = TestingSessionLocal()

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)