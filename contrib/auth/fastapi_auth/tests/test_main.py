import pytest
from fastapi.testclient import TestClient

from pathlib import Path
import importlib.util

MODULE_PATH = Path(__file__).resolve().parents[1] / "main.py"

@pytest.fixture
def fresh_client():
    spec = importlib.util.spec_from_file_location("fastapi_auth_main", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = TestClient(module.app)
    return client

def test_health(fresh_client):
    for path in ["/api/v1/_health", "/api/v1/health"]:
        resp = fresh_client.get(path)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def test_user_lifecycle(fresh_client):
    data = {"username": "alice", "email": "alice@example.com"}
    resp = fresh_client.post("/api/v1/auth/users", json=data)
    assert resp.status_code == 201
    resp = fresh_client.get("/api/v1/auth/users/alice")
    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"
    resp = fresh_client.get("/api/v1/auth/users")
    assert resp.status_code == 200
    assert any(u["username"] == "alice" for u in resp.json()["results"])
    resp = fresh_client.delete("/api/v1/auth/users/alice")
    assert resp.status_code == 204
    assert fresh_client.get("/api/v1/auth/users/alice").status_code == 404


def test_group_and_membership(fresh_client):
    fresh_client.post("/api/v1/auth/users", json={"username": "alice"})
    resp = fresh_client.post("/api/v1/auth/groups", json={"id": "dev"})
    assert resp.status_code == 201
    resp = fresh_client.put("/api/v1/auth/groups/dev/members/alice")
    assert resp.status_code == 201
    resp = fresh_client.get("/api/v1/auth/users/alice/groups")
    assert resp.status_code == 200
    assert any(g["id"] == "dev" for g in resp.json()["results"])
    resp = fresh_client.delete("/api/v1/auth/groups/dev/members/alice")
    assert resp.status_code == 204
    resp = fresh_client.delete("/api/v1/auth/groups/dev")
    assert resp.status_code == 204


def test_policy_and_credentials(fresh_client):
    fresh_client.post("/api/v1/auth/users", json={"username": "alice"})
    resp = fresh_client.post(
        "/api/v1/auth/policies", json={"name": "read", "acl": "*", "creation_date": 0}
    )
    assert resp.status_code == 201
    resp = fresh_client.put("/api/v1/auth/users/alice/policies/read")
    assert resp.status_code == 201
    resp = fresh_client.get("/api/v1/auth/users/alice/policies", params={"effective": True})
    assert any(p["name"] == "read" for p in resp.json()["results"])
    cred = fresh_client.post("/api/v1/auth/users/alice/credentials").json()
    assert "access_key_id" in cred and "secret_access_key" in cred
    resp = fresh_client.get(f"/api/v1/auth/users/alice/credentials/{cred['access_key_id']}")
    assert resp.status_code == 200
    resp = fresh_client.delete(f"/api/v1/auth/users/alice/credentials/{cred['access_key_id']}")
    assert resp.status_code == 204

