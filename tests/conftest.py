import pytest
from fastapi.testclient import TestClient

from helpers import ADMIN, ANALYST, enroll, login, make_app, register_agent


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def db(app):
    from server.app.db import SessionLocal
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture
def admin_h(client):
    return login(client, ADMIN)


@pytest.fixture
def analyst_h(client):
    return login(client, ANALYST)


@pytest.fixture
def agent(client):
    return register_agent(client)  # (headers, endpoint_id)


@pytest.fixture
def key(agent):
    return agent[0]


@pytest.fixture
def auth(client, admin_h, tmp_path):
    return enroll(client, admin_h, tmp_path)
