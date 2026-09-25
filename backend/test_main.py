import os
from pathlib import Path

TEST_DB = Path(__file__).resolve().parents[1] / "test_runtime.db"
if TEST_DB.exists(): TEST_DB.unlink()
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["FLOOD_THRESHOLD"] = "3"
os.environ["FLOOD_WINDOW_SECONDS"] = "10"
os.environ["TEMP_BLOCK_SECONDS"] = "2"

from fastapi.testclient import TestClient
import main
from main import app

client = TestClient(app)

def token():
    response = client.post("/token", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    return response.json()["access_token"]

def analyze(url):
    return client.post("/analyze", json={"url": url, "method": "GET", "source": "pytest"})

def test_health_and_auth():
    assert client.get("/health").json()["database"] == "SQLite"
    assert client.get("/events").status_code == 401
    assert client.get("/events", headers={"Authorization": f"Bearer {token()}"}).status_code == 200

def test_explainable_attack_detection_and_rule_creation():
    main.request_windows.clear(); main.temporary_blocks.clear(); main.RATE_LIMIT = 100
    cases = {
        "https://x.test/?q=%3CScRiPt%3Ealert(1)": "XSS",
        "https://x.test/?id=%2527%2520OR%25201%253D1": "SQL Injection",
        "https://x.test/..%2F..%2Fetc%2Fpasswd": "Path Traversal",
        "https://x.test/?cmd=%3Bcat%20%2Fetc%2Fpasswd": "Command Injection",
    }
    for url, expected in cases.items():
        data = analyze(url).json()
        assert data["decision"] == "BLOCK"
        assert data["attack_type"] == expected
        assert data["explanation"]
        assert data["action"] == "DROP_REQUEST"
        assert data["execution_layer"] == "APPLICATION_LAYER_DROP"
        assert data["protection_rule"]["status"] == "ACTIVE"

def test_allow_and_csv_export():
    main.request_windows.clear(); main.temporary_blocks.clear(); main.RATE_LIMIT = 100
    assert analyze("https://example.com/safe").json()["decision"] == "ALLOW"
    response = client.get("/events/export", headers={"Authorization": f"Bearer {token()}"})
    assert response.status_code == 200
    assert "Event ID" in response.text
    assert "Threat category" in response.text

def test_request_flood_temporarily_blocks():
    main.request_windows.clear(); main.temporary_blocks.clear(); main.RATE_LIMIT = 3
    for _ in range(3): analyze("https://safe.test/")
    blocked = analyze("https://safe.test/").json()
    assert blocked["attack_type"] == "Request Flood"
    assert blocked["decision"] == "BLOCK"
    assert blocked["action"] == "DROP_REQUEST"
    assert blocked["execution_layer"] == "APPLICATION_LAYER_DROP"
    status = client.get("/self-healing/status", headers={"Authorization": f"Bearer {token()}"}).json()
    assert status["temporary_blocks"] == 1
    
    # Test Recovery
    import time
    time.sleep(2.5)  # Let TEMP_BLOCK_SECONDS=2 expire
    recovery = analyze("https://safe.test/").json()
    assert recovery["decision"] == "ALLOW"
