"""Run this while the backend is online: python backend/simulate.py"""
import json
import time
import urllib.request

API = "http://127.0.0.1:8000"
SCENARIOS = [
    ("XSS", "https://reviewer.test/?q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("SQL Injection", "https://reviewer.test/?id=%2527%2520OR%25201%253D1"),
    ("Path Traversal", "https://reviewer.test/..%2F..%2Fetc%2Fpasswd"),
    ("Command Injection", "https://reviewer.test/?cmd=%3Bcat%20%2Fetc%2Fpasswd"),
]

def analyze(url):
    req = urllib.request.Request(API + "/analyze", data=json.dumps({"url": url, "method": "GET", "source": "reviewer-simulator", "device_id": "NEXAF-PYTHON-SIM"}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as response: 
            return json.loads(response.read())
    except Exception as e:
        print("API request failed:", e)
        return {"decision": "ERROR", "attack_type": "Unknown", "explanation": str(e), "action": "ERROR"}

print("NEXAF realtime attack simulator — watch the dashboard update")
for name, url in SCENARIOS:
    result = analyze(url)
    print(f"[{result['decision']}] {name}")
    time.sleep(1)

print("\nFlood simulation: sending requests until NEXAF temporarily drops this source")
for index in range(60):
    result = analyze("https://reviewer.test/safe")
    if result["attack_type"] == "Request Flood":
        print(f"[{result['decision']}] Request Flood")
        print("TEMPORARY_BLOCK ACTIVE")
        break
    time.sleep(0.01)

print("Waiting for expiry")
time.sleep(16)
result = analyze("https://reviewer.test/recovery-check")
print("RECOVERY RECOVERED")
print(f"ALLOW recovery probe")
