from pathlib import Path
from fastapi.testclient import TestClient

from qkd_kms.simulator import DEFAULT_SEED_HEX, MockKmsService
from qkd_kms.web import create_app


def test_standalone_dashboard_auth_controls_and_presets():
    service = MockKmsService(
        "127.0.0.1", 0, DEFAULT_SEED_HEX, 1000, 4096, 4096, "SAE_002", "SAE_001"
    )
    app = create_app(
        service,
        password="test-password",
        presets_dir=Path(__file__).parents[1] / "src/qkd_kms/presets",
    )
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/health").json() == {"status": "ok"}
        assert client.get("/api/status").status_code == 401
        assert client.post("/api/login", json={"password": "wrong"}).status_code == 401
        login = client.post("/api/login", json={"password": "test-password"})
        assert login.status_code == 200
        csrf = {"x-csrf-token": login.json()["csrf_token"]}
        assert client.get("/api/status").status_code == 200
        assert (
            client.put("/api/buffer", json={"available_bytes": 32}).status_code == 403
        )
        assert (
            client.put(
                "/api/buffer", json={"available_bytes": 32}, headers=csrf
            ).status_code
            == 200
        )
        presets = client.get("/api/presets").json()["presets"]
        assert (
            client.post(
                f"/api/presets/{presets[0]['id']}/apply", headers=csrf
            ).status_code
            == 200
        )
        assert client.post("/api/history/clear", headers=csrf).status_code == 200
        assert client.post("/api/logout", headers=csrf).status_code == 200
        assert client.get("/api/status").status_code == 401


def test_outage_requires_authentication_csrf_and_is_isolated_by_session():
    service = MockKmsService("127.0.0.1", 0, DEFAULT_SEED_HEX, 1000,
                             4096, 4096, "SAE_002", "SAE_001")
    app = create_app(service, password="test-password",
                     presets_dir=Path(__file__).parents[1] / "src/qkd_kms/presets")
    with TestClient(app) as client:
        assert client.put("/api/outage", json={"enabled": True}).status_code == 401
        login = client.post("/api/login", json={"password": "test-password"})
        assert client.put("/api/outage", json={"enabled": True}).status_code == 403
        headers = {"x-csrf-token": login.json()["csrf_token"], "X-LinQKD-Session": "team-one"}
        assert client.put("/api/outage", json={"enabled": "true"}, headers=headers).status_code == 422
        response = client.put("/api/outage", json={"enabled": True}, headers=headers)
        assert response.status_code == 200
        status = response.json()
        assert status["outage_active"] is True
        assert status["current_rate_bytes_per_second"] == 0
        assert status["configuration"]["generation_enabled"] is True
        assert service.status()["outage_active"] is False
        assert client.get("/api/status", headers=headers).json()["outage_active"] is True
        resumed = client.put("/api/outage", json={"enabled": False}, headers=headers).json()
        assert resumed["outage_active"] is False
        assert resumed["current_rate_bytes_per_second"] == 1000
