"""
GHOSTSENTINEL Ω — Pytest Configuration & Fixtures
Sets test environment variables and configures the in-memory SQLite database.
"""
import os
import pytest

# Set test environment variables before any app modules are loaded
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars"
os.environ["DEBUG"] = "false"

from app.database import init_db, engine
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Ensure database tables are created once for the test session."""
    init_db()
    yield


@pytest.fixture(scope="session")
def client():
    """Yield a FastAPI TestClient with the application lifespan active."""
    with TestClient(app) as c:
        yield c
