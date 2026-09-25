import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
IST = timezone(timedelta(hours=5, minutes=30))

# Load local .env without external dependencies
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f.read().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()

from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, func
from sqlalchemy.orm import Session, declarative_base, sessionmaker

ROOT = Path(__file__).resolve().parents[1]
DB_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'nexaf.db'}")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="VIEWER")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(IST))

class Device(Base):
    __tablename__ = "devices"
    device_id = Column(String, primary_key=True)
    device_name = Column(String)
    browser_name = Column(String)
    browser_version = Column(String)
    os_name = Column(String)
    extension_version = Column(String)
    user_agent = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(IST))
    last_seen = Column(DateTime, default=lambda: datetime.now(IST))
    status = Column(String, default="ONLINE")
    risk_status = Column(String, default="LOW")
    total_events = Column(Integer, default=0)
    blocked_events = Column(Integer, default=0)
    active_incidents = Column(Integer, default=0)

class Incident(Base):
    __tablename__ = "incidents"
    incident_id = Column(String, primary_key=True)
    device_id = Column(String, index=True)
    source_ip = Column(String, index=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(IST))
    last_seen = Column(DateTime, default=lambda: datetime.now(IST))
    threat_categories = Column(Text, default="[]")
    max_risk_score = Column(Integer, default=0)
    event_count = Column(Integer, default=1)
    current_status = Column(String, default="OPEN")
    response_action = Column(String, default="MONITORING")
    recovery_status = Column(String, default="PENDING")

class AiExplanation(Base):
    __tablename__ = "ai_explanations"
    id = Column(Integer, primary_key=True)
    event_id = Column(String, index=True)
    provider = Column(String)
    summary = Column(Text)
    technical_reason = Column(Text)
    user_action = Column(Text)
    administrator_action = Column(Text)
    timestamp = Column(DateTime, default=lambda: datetime.now(IST))

class SecurityEvent(Base):
    __tablename__ = "security_events"
    event_id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(IST), index=True)
    event_type = Column(String, index=True)
    attack_type = Column(String, index=True)
    decision = Column(String, index=True)
    source_ip = Column(String, index=True)
    request_path = Column(Text)
    reason = Column(Text)
    action = Column(String)
    status = Column(String)
    severity = Column(String)
    ai_provider = Column(String, default="local-rules")
    execution_layer = Column(String, default="APPLICATION_LAYER_DROP")
    
    # New columns
    device_id = Column(String, index=True, nullable=True)
    method = Column(String, nullable=True)
    host = Column(String, nullable=True)
    query_params = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)
    referer = Column(Text, nullable=True)
    request_size = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    risk_factors = Column(Text, nullable=True)
    incident_id = Column(String, index=True, nullable=True)


class ProtectionRule(Base):
    __tablename__ = "protection_rules"
    rule_id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=lambda: datetime.now(IST))
    attack_type = Column(String, index=True)
    action = Column(String)
    reason = Column(Text)
    status = Column(String, default="ACTIVE")

class SelfHealingEvent(Base):
    __tablename__ = "self_healing_events"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(IST))
    action = Column(String)
    details = Column(Text)
    status = Column(String)
    source_ip = Column(String)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(IST))

    action_type = Column(String)
    details = Column(Text)

Base.metadata.create_all(engine)

def migrate_sqlite():
    """Keep the demo database upgrade-safe without adding a migration framework."""
    if not DB_URL.startswith("sqlite"):
        return
    from sqlalchemy import inspect, text
    inspector = inspect(engine)
    
    if "security_events" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("security_events")}
        new_cols = {
            "ai_provider": "VARCHAR DEFAULT 'local-rules'",
            "execution_layer": "VARCHAR DEFAULT 'APPLICATION_LAYER_DROP'",
            "device_id": "VARCHAR",
            "method": "VARCHAR",
            "host": "VARCHAR",
            "query_params": "TEXT",
            "user_agent": "TEXT",
            "referer": "TEXT",
            "request_size": "INTEGER DEFAULT 0",
            "risk_score": "INTEGER DEFAULT 0",
            "risk_factors": "TEXT",
            "incident_id": "VARCHAR"
        }
        with engine.begin() as conn:
            for col, dtype in new_cols.items():
                if col not in columns:
                    try:
                        conn.execute(text(f"ALTER TABLE security_events ADD COLUMN {col} {dtype}"))
                    except Exception:
                        pass # Ignore if it exists or fails
                        
    if "self_healing_events" in inspector.get_table_names():
        healing_columns = {c["name"] for c in inspector.get_columns("self_healing_events")}
        if "source_ip" not in healing_columns:
            with engine.begin() as conn:
                try:
                    conn.execute(text("ALTER TABLE self_healing_events ADD COLUMN source_ip VARCHAR"))
                except Exception:
                    pass

migrate_sqlite()

# ---------------- Authentication ----------------
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-demo-secret")
TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
bearer = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    return base64.b64encode(salt + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120000)).decode()

def verify_password(password: str, encoded: str) -> bool:
    try:
        raw = base64.b64decode(encoded)
        # 120000 is the current setting; 100000 keeps existing NEXAF demo accounts usable.
        return any(hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], rounds), raw[16:]) for rounds in (120000, 100000))
    except Exception:
        return False

def token_for(username: str, role: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = {"sub": username, "role": role, "exp": int(time.time() + TOKEN_MINUTES * 60)}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    sig = hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"

def decode_token(token: str) -> dict:
    try:
        a, b, c = token.split(".")
        expected = hmac.new(SECRET_KEY.encode(), f"{a}.{b}".encode(), hashlib.sha256).digest()
        actual = base64.urlsafe_b64decode(c + "=" * (-len(c) % 4))
        if not hmac.compare_digest(expected, actual): raise ValueError("bad signature")
        data = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
        if data["exp"] < time.time(): raise ValueError("expired")
        return data
    except Exception as exc:
        raise HTTPException(401, f"Invalid token: {exc}")

def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(lambda: SessionLocal())):
    if not credentials:
        raise HTTPException(401, "Authentication required")
    data = decode_token(credentials.credentials)
    user = db.query(User).filter(User.username == data.get("sub"), User.active.is_(True)).first()
    db.close()
    if not user: raise HTTPException(401, "User not found")
    return {"username": user.username, "role": user.role}

def require_roles(*roles):
    def check(user=Depends(current_user)):
        if user["role"] not in roles: raise HTTPException(403, "Insufficient privileges")
        return user
    return check

with SessionLocal() as db:
    if not db.query(User).filter_by(username="admin").first():
        db.add(User(username="admin", hashed_password=hash_password("admin"), role="ADMIN", active=True))
        db.commit()

# ---------------- Detection and self-healing ----------------
DEMO_MODE = os.getenv("DEMO_MODE", "0") == "1"
RATE_LIMIT = int(os.getenv("FLOOD_THRESHOLD", "8" if DEMO_MODE else "50"))
RATE_WINDOW = int(os.getenv("FLOOD_WINDOW_SECONDS", "10"))
BLOCK_SECONDS = int(os.getenv("TEMP_BLOCK_SECONDS", "15" if DEMO_MODE else "30"))
request_windows = defaultdict(deque)
temporary_blocks = {}
state_lock = threading.Lock()

RULES = {
    "XSS": (re.compile(r"(?:<\s*script|javascript\s*:|on(?:error|load|click)\s*=|<\s*svg)", re.I), 95, "This request was blocked because it contains executable JavaScript or HTML markup (Cross-Site Scripting). If permitted, this payload could execute malicious code within a user's browser, potentially stealing session cookies or hijacking accounts. NEXAF dropped the request at Layer 5 to ensure application security."),
    "SQL Injection": (re.compile(r"(?:union\s+select|(?:'|%27)\s*(?:or|and)\s*['\"]?\w+['\"]?\s*=|\bselect\s+.+\s+from\b|sleep\s*\()", re.I), 95, "This connection was severed due to the detection of a SQL Injection attempt. The payload contained database manipulation patterns (like 'UNION SELECT' or logical OR operators) designed to bypass authentication or extract sensitive backend data. NEXAF intervened and dropped the transaction immediately."),
    "Command Injection": (re.compile(r"(?:[;&|`]\s*(?:cat|curl|wget|bash|sh|powershell|cmd|nc)\b|\$\([^)]*\)|\b(?:cmd\.exe|powershell\.exe)\b)", re.I), 98, "Critical Alert: A Command Injection signature was detected. The originating IP attempted to pass shell metacharacters capable of executing unauthorized operating-system commands directly on the host server. NEXAF enacted an immediate connection drop to protect core infrastructure."),
    "Path Traversal": (re.compile(r"(?:\.\.[\\/]\s*|/etc/passwd|windows[\\/]win\.ini|%2e%2e%2f)", re.I), 90, "Security Enforced: This request attempted a Path Traversal exploit. By using directory manipulation sequences (like '../'), the sender tried to access restricted configurations or sensitive system files outside of the permitted public web directory. NEXAF blocked access to prevent file exposure."),
}

def normalize(value: str) -> str:
    current = value or ""
    for _ in range(4):
        decoded = urllib.parse.unquote_plus(current)
        if decoded == current: break
        current = decoded
    return current.lower()

def client_ip(request: Request) -> str:
    # For a local demo, trust the proxy header only when explicitly enabled.
    if os.getenv("TRUST_PROXY_HEADERS", "0") == "1":
        return request.headers.get("x-forwarded-for", request.client.host if request.client else "127.0.0.1").split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def ai_explanation(url: str, attack: str, fallback: str, metadata: dict) -> tuple[str, str, dict]:
    """Optional AI improves wording; deterministic rules always decide safety."""
    provider = os.getenv("AI_PROVIDER", "local-rules").lower()
    
    if provider == "openai-compatible":
        api_base = os.getenv("AI_API_BASE", "https://integrate.api.nvidia.com/v1").rstrip("/")
        api_key = os.getenv("AI_API_KEY")
        model = os.getenv("AI_MODEL")
        if api_key and model:
            try:
                system_prompt = (
                    "You are the explanation component of NEXAF, an explainable web-security system.\n"
                    "The local security engine already made the final decision. Do not change it.\n"
                    "Return JSON only:\n"
                    "{\n"
                    '  "summary": "...",\n'
                    '  "technical_reason": "...",\n'
                    '  "user_action": "...",\n'
                    '  "administrator_action": "..."\n'
                    "}\n\n"
                    f"Attack type: {attack}\n"
                    f"Decision: BLOCK\n"
                    f"URL: {url}\n"
                    f"Metadata: {json.dumps(metadata)}\n\n"
                    "Rules:\n"
                    "- Do not invent evidence.\n"
                    "- Do not expose secrets.\n"
                    "- Do not include HTML or JavaScript.\n"
                    "- Do not claim raw packet inspection.\n"
                    "- Do not change the decision.\n"
                    "- Keep the summary short."
                )
                
                req_data = {
                    "model": model,
                    "messages": [{"role": "system", "content": system_prompt}],
                    "temperature": 0.2,
                    "max_tokens": 1024,
                    "response_format": {"type": "json_object"}
                }
                
                req = urllib.request.Request(
                    f"{api_base}/chat/completions",
                    data=json.dumps(req_data).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    method="POST"
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    res_body = json.loads(response.read().decode())
                    content = res_body["choices"][0]["message"]["content"]
                    parsed = json.loads(content)
                    return parsed.get("summary", fallback), "nvidia-ai", parsed
            except Exception as e:
                print(f"AI API Error: {e}")
                pass
                
    return fallback, "local-rules", {}

def calculate_risk(url: str, method: str, attack: str, history: int = 0) -> tuple[int, str, list]:
    factors = []
    score = 0
    if attack != "None":
        score += RULES.get(attack, [None, 100, None])[1]
        factors.append(f"Matched threat signature: {attack}")
    if "%" in url:
        score += 5
        factors.append("Encoded payload detected")
    if history > 5:
        score += 15
        factors.append("Source has multiple recent violations")
    if "admin" in url.lower() or "etc" in url.lower():
        score += 10
        factors.append("Sensitive path accessed")
    score = min(score, 100)
    
    if score >= 80: return score, "CRITICAL", factors
    if score >= 60: return score, "HIGH", factors
    if score >= 30: return score, "MEDIUM", factors
    return score, "LOW", factors

def save_self_healing(action: str, details: str, status: str, ip: str):
    with SessionLocal() as db:
        db.add(SelfHealingEvent(action=action, details=details, status=status, source_ip=ip))
        db.commit()

def ensure_rule(attack: str, reason: str) -> dict:
    rule_id = "NEXAF-RULE-" + str({"XSS": 1, "SQL Injection": 2, "Path Traversal": 3, "Command Injection": 4, "Request Flood": 5}[attack])
    with SessionLocal() as db:
        rule = db.get(ProtectionRule, rule_id)
        if not rule:
            rule = ProtectionRule(rule_id=rule_id, attack_type=attack, action="BLOCK", reason=reason, status="ACTIVE")
            db.add(rule); db.commit()
        return {"rule_id": rule.rule_id, "attack_type": rule.attack_type, "action": rule.action, "reason": rule.reason, "status": rule.status}

def evaluate_flood(ip: str) -> Optional[dict]:
    now = time.time()
    with state_lock:
        if ip in temporary_blocks:
            if temporary_blocks[ip] > now: return {"remaining_seconds": int(temporary_blocks[ip] - now)}
            del temporary_blocks[ip]
            save_self_healing("RECOVERY", f"Temporary block expired for {ip}; traffic restored.", "RECOVERED", ip)
        window = request_windows[ip]
        window.append(now)
        while window and window[0] < now - RATE_WINDOW: window.popleft()
        if len(window) > RATE_LIMIT:
            temporary_blocks[ip] = now + BLOCK_SECONDS
            window.clear()
            save_self_healing("TEMPORARY_BLOCK", f"Dropped requests from {ip} after {RATE_LIMIT} requests in {RATE_WINDOW} seconds.", "ACTIVE", ip)
            return {"remaining_seconds": BLOCK_SECONDS}
    return None

# ---------------- API ----------------
app = FastAPI(title="NEXAF: Next-Generation Explainable Web Security and Automated Threat Response System", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

class AnalyzePayload(BaseModel):
    device_id: str = "unknown"
    url: str = Field(..., min_length=1, max_length=10000)
    method: str = "GET"
    source: str = "browser_extension"
    host: str = ""
    path: str = ""
    query: str = ""
    user_agent: str = ""
    referer: str = ""
    request_size: int = 0

class DeviceRegisterPayload(BaseModel):
    device_id: str
    device_name: str = "Chrome Device"
    browser_name: str = "Chrome"
    browser_version: str = "Unknown"
    os_name: str = "Unknown"
    extension_version: str = "1.0.0"
    user_agent: str = "Unknown"

class HeartbeatPayload(BaseModel):
    device_id: str
    extension_version: str = "1.0.0"
    current_tab_url: str = ""
    status: str = "ONLINE"

class LoginPayload(BaseModel):
    username: str
    password: str

@app.get("/")
def root(): return {"name": "NEXAF", "status": "ONLINE", "mode": "explainable-realtime"}

@app.get("/health")
def health():
    with SessionLocal() as db: db.query(User.id).count()
    return {"status": "ONLINE", "database": "SQLite", "ai_provider": os.getenv("AI_PROVIDER", "local"), "demo_mode": DEMO_MODE}

@app.post("/token")
def login(payload: LoginPayload):
    with SessionLocal() as db:
        user = db.query(User).filter_by(username=payload.username).first()
        if not user or not verify_password(payload.password, user.hashed_password):
            if user: db.add(AuditLog(action_type="LOGIN_FAILED", details=f"User {payload.username}")); db.commit()
            raise HTTPException(401, "Invalid credentials")
        db.add(AuditLog(action_type="LOGIN_SUCCESS", details=f"User {user.username}")); db.commit()
        return {"access_token": token_for(user.username, user.role), "token_type": "bearer", "role": user.role}

@app.get("/users/me")
def me(user=Depends(current_user)): return user

@app.post("/users/logout")
def logout(user=Depends(current_user)):
    with SessionLocal() as db: db.add(AuditLog(action_type="LOGOUT", details=f"User {user['username']}")); db.commit()
    return {"message": "Success"}

@app.post("/devices/register")
def register_device(payload: DeviceRegisterPayload):
    with SessionLocal() as db:
        device = db.get(Device, payload.device_id)
        if not device:
            device = Device(
                device_id=payload.device_id,
                device_name=payload.device_name,
                browser_name=payload.browser_name,
                browser_version=payload.browser_version,
                os_name=payload.os_name,
                extension_version=payload.extension_version,
                user_agent=payload.user_agent,
                created_at=datetime.now(IST),
                last_seen=datetime.now(IST),
                status="ONLINE",
                risk_status="LOW"
            )
            db.add(device)
        else:
            device.last_seen = datetime.now(IST)
            device.status = "ONLINE"
        db.commit()
        return {"status": "success", "device_id": device.device_id, "created_at": device.created_at.isoformat()}

@app.post("/devices/heartbeat")
def heartbeat(payload: HeartbeatPayload):
    with SessionLocal() as db:
        device = db.get(Device, payload.device_id)
        if device:
            device.last_seen = datetime.now(IST)
            device.status = "ONLINE"
            db.commit()
            return {"status": "acknowledged"}
        raise HTTPException(404, "Device not registered")

@app.get("/devices")
def get_devices(user=Depends(require_roles("ADMIN"))):
    with SessionLocal() as db:
        devices = db.query(Device).all()
        now = datetime.now(IST)
        res = []
        for d in devices:
            if (now - d.last_seen).total_seconds() > 60:
                d.status = "OFFLINE"
            else:
                d.status = "ONLINE"
            res.append({
                "device_id": d.device_id,
                "display_name": d.device_name,
                "browser": d.browser_name,
                "operating_system": d.os_name,
                "extension_version": d.extension_version,
                "first_seen": d.created_at.isoformat(),
                "last_seen": d.last_seen.isoformat(),
                "online_status": d.status,
                "total_events": d.total_events,
                "blocked_events": d.blocked_events,
                "active_incidents": d.active_incidents,
                "current_risk_level": d.risk_status
            })
        db.commit()
        return {"devices": res}

@app.post("/analyze")
def analyze(payload: AnalyzePayload, request: Request):
    ip = client_ip(request)
    flood = evaluate_flood(ip)
    normalized = normalize(payload.url)
    attack, risk, reason = "None", 0, "The normalized request contains no known malicious signature. Traffic is allowed and logged."
    
    if flood:
        attack, risk, reason = "Request Flood", 100, f"This source exceeded {RATE_LIMIT} requests in {RATE_WINDOW} seconds. NEXAF is dropping requests for {flood['remaining_seconds']} seconds to protect availability."
    else:
        for name, (pattern, rule_risk, explanation) in RULES.items():
            if pattern.search(normalized): attack, risk, reason = name, rule_risk, explanation; break
            
    # Risk scoring computation
    history = 0
    with SessionLocal() as db:
        history = db.query(SecurityEvent).filter(SecurityEvent.source_ip == ip, SecurityEvent.decision == "BLOCK").count()
        
    score, risk_level, risk_factors = calculate_risk(payload.url, payload.method, attack, history)

    decision = "BLOCK" if attack != "None" else "ALLOW"
    action = "DROP_REQUEST" if decision == "BLOCK" else "ALLOW_REQUEST"
    exec_layer = "APPLICATION_LAYER_DROP" if decision == "BLOCK" else ""
    
    metadata = {
        "method": payload.method,
        "source_ip": ip,
        "device_id": payload.device_id,
        "action": action,
        "risk_score": score,
        "risk_factors": risk_factors
    }
    
    explanation, provider, ai_data = ai_explanation(payload.url, attack, reason, metadata) if decision == "BLOCK" else (reason, "local-rules", {})
    rule = ensure_rule(attack, explanation) if decision == "BLOCK" else None
    
    incident_id_assigned = None
    with SessionLocal() as db:
        if decision == "BLOCK":
            # Incident tracking
            incident = db.query(Incident).filter(Incident.device_id == payload.device_id, Incident.source_ip == ip, Incident.current_status == "OPEN").first()
            if not incident:
                incident_id_assigned = f"NEXAF-INC-{db.query(Incident).count() + 1:06d}"
                incident = Incident(
                    incident_id=incident_id_assigned,
                    device_id=payload.device_id,
                    source_ip=ip,
                    threat_categories=json.dumps([attack]),
                    max_risk_score=score,
                    event_count=1
                )
                db.add(incident)
            else:
                incident_id_assigned = incident.incident_id
                incident.event_count += 1
                incident.last_seen = datetime.now(IST)
                cats = json.loads(incident.threat_categories)
                if attack not in cats: cats.append(attack)
                incident.threat_categories = json.dumps(cats)
                if score > incident.max_risk_score: incident.max_risk_score = score
        
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            event_type="THREAT_BLOCKED" if decision == "BLOCK" else "TRAFFIC_ALLOWED",
            attack_type=attack,
            decision=decision,
            source_ip=ip,
            request_path=payload.url,
            reason=explanation,
            action=action,
            status="ACTIVE",
            severity="CRITICAL" if score >= 80 else risk_level,
            ai_provider=provider,
            execution_layer=exec_layer,
            device_id=payload.device_id,
            method=payload.method,
            host=payload.host,
            query_params=payload.query,
            user_agent=payload.user_agent,
            referer=payload.referer,
            request_size=payload.request_size,
            risk_score=score,
            risk_factors=json.dumps(risk_factors),
            incident_id=incident_id_assigned
        )
        db.add(event)
        
        # update device metrics
        device = db.get(Device, payload.device_id)
        if device:
            device.total_events += 1
            if decision == "BLOCK":
                device.blocked_events += 1
                device.risk_status = risk_level
            if incident_id_assigned:
                device.active_incidents = db.query(Incident).filter(Incident.device_id == payload.device_id, Incident.current_status == "OPEN").count()
        db.commit()
        
    return {
        "decision": decision,
        "attack_type": attack,
        "risk_score": score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "confidence": 99 if provider == "local-rules" else 96,
        "explanation": explanation,
        "action": action,
        "execution_layer": exec_layer,
        "ai_provider": provider,
        "source_ip": ip,
        "device_id": payload.device_id,
        "protection_rule": rule,
        "remaining_seconds": flood["remaining_seconds"] if flood else 0,
        "ai_data": ai_data
    }

@app.get("/protections")
def protections():
    with SessionLocal() as db:
        return {"active_rules": [{"rule_id": r.rule_id, "attack_type": r.attack_type, "action": r.action, "reason": r.reason, "status": r.status} for r in db.query(ProtectionRule).filter_by(status="ACTIVE").all()]}

@app.get("/self-healing/status")
def healing_status(user=Depends(require_roles("ADMIN", "ANALYST", "VIEWER"))):
    now = time.time()
    with state_lock: active = {ip: max(0, int(exp - now)) for ip, exp in temporary_blocks.items() if exp > now}
    return {"status": "ACTIVE", "temporary_blocks": len(active), "blocked_sources": active, "threshold": RATE_LIMIT, "window_seconds": RATE_WINDOW, "block_seconds": BLOCK_SECONDS}

@app.get("/self-healing/events")
def healing_events(user=Depends(require_roles("ADMIN", "ANALYST", "VIEWER"))):
    with SessionLocal() as db:
        rows = db.query(SelfHealingEvent).order_by(SelfHealingEvent.timestamp.desc()).limit(100).all()
        return {"events": [{"id": x.id, "timestamp": x.timestamp.isoformat(), "action": x.action, "details": x.details, "status": x.status, "source_ip": x.source_ip} for x in rows]}

def event_dict(x):
    return {
        "event_id": x.event_id, "timestamp": x.timestamp.isoformat() if x.timestamp else None, "event_type": x.event_type, 
        "attack_type": x.attack_type, "decision": x.decision, "source_ip": x.source_ip, "request_path": x.request_path, 
        "reason": x.reason, "action": x.action, "status": x.status, "severity": x.severity, "ai_provider": x.ai_provider, 
        "execution_layer": getattr(x, "execution_layer", "APPLICATION_LAYER_DROP"),
        "device_id": getattr(x, "device_id", ""), "method": getattr(x, "method", ""), "host": getattr(x, "host", ""),
        "query_params": getattr(x, "query_params", ""), "user_agent": getattr(x, "user_agent", ""), 
        "request_size": getattr(x, "request_size", 0), "risk_score": getattr(x, "risk_score", 0),
        "risk_factors": getattr(x, "risk_factors", "[]"), "incident_id": getattr(x, "incident_id", "")
    }

@app.get("/events")
def events(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), attack_type: Optional[str] = None, decision: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, user=Depends(require_roles("ADMIN", "ANALYST", "VIEWER"))):
    with SessionLocal() as db:
        q = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
        if attack_type: q = q.filter(SecurityEvent.attack_type == attack_type)
        if decision: q = q.filter(SecurityEvent.decision == decision)
        if start_date: q = q.filter(SecurityEvent.timestamp >= start_date)
        if end_date: q = q.filter(SecurityEvent.timestamp <= end_date + "T23:59:59")
        return {"total": q.count(), "events": [event_dict(x) for x in q.offset(offset).limit(limit).all()]}

@app.get("/incidents")
def get_incidents(user=Depends(require_roles("ADMIN", "ANALYST"))):
    with SessionLocal() as db:
        rows = db.query(Incident).order_by(Incident.last_seen.desc()).limit(100).all()
        res = []
        for r in rows:
            res.append({
                "incident_id": r.incident_id,
                "device_id": r.device_id,
                "source_ip": r.source_ip,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "threat_categories": json.loads(r.threat_categories) if r.threat_categories else [],
                "max_risk_score": r.max_risk_score,
                "event_count": r.event_count,
                "current_status": r.current_status,
                "response_action": r.response_action,
                "recovery_status": r.recovery_status
            })
        return {"incidents": res}

@app.get("/devices/{device_id}")
def get_device(device_id: str, user=Depends(require_roles("ADMIN", "ANALYST"))):
    with SessionLocal() as db:
        device = db.get(Device, device_id)
        if not device:
            raise HTTPException(404, "Device not found")
        now = datetime.now(IST)
        if (now - device.last_seen).total_seconds() > 60:
            device.status = "OFFLINE"
        db.commit()
        return {
            "device_id": device.device_id,
            "display_name": device.device_name,
            "browser": device.browser_name,
            "operating_system": device.os_name,
            "extension_version": device.extension_version,
            "first_seen": device.created_at.isoformat(),
            "last_seen": device.last_seen.isoformat(),
            "online_status": device.status,
            "total_events": device.total_events,
            "blocked_events": device.blocked_events,
            "active_incidents": device.active_incidents,
            "current_risk_level": device.risk_status
        }

@app.get("/devices/{device_id}/self-healing/status")
def device_healing_status(device_id: str, user=Depends(require_roles("ADMIN", "ANALYST", "VIEWER"))):
    with SessionLocal() as db:
        device_events = db.query(SecurityEvent).filter(SecurityEvent.device_id == device_id).all()
        ips = {e.source_ip for e in device_events if e.source_ip}
    now = time.time()
    with state_lock:
        active = {ip: max(0, int(exp - now)) for ip, exp in temporary_blocks.items() if exp > now and ip in ips}
    return {"status": "ACTIVE", "temporary_blocks": len(active), "blocked_devices": active, "blocked_sources": active, "threshold": RATE_LIMIT, "window_seconds": RATE_WINDOW, "block_seconds": BLOCK_SECONDS, "execution_layer": "APPLICATION_LAYER_DROP"}

@app.get("/devices/{device_id}/events/export")
def export_device_events(device_id: str, format: str = Query("csv"), user=Depends(require_roles("ADMIN", "ANALYST"))):
    with SessionLocal() as db:
        device = db.get(Device, device_id)
        if not device: raise HTTPException(404, "Device not found")
        q = db.query(SecurityEvent).filter(SecurityEvent.device_id == device_id).order_by(SecurityEvent.timestamp.desc())
        rows = [event_dict(x) for x in q.limit(10000).all()]
        db.add(AuditLog(action_type="EXPORT", details=f"User {user['username']} exported {len(rows)} events for device {device_id}")); db.commit()
        
    mapped_rows = []
    for r in rows:
        mapped_rows.append({
            "Time (UTC)": r.get("timestamp"),
            "Device ID": r.get("device_id"),
            "Device Name": device.device_name,
            "Event ID": r.get("event_id"),
            "Decision": r.get("decision"),
            "Threat Category": r.get("attack_type"),
            "Risk Score": r.get("risk_score"),
            "Risk Level": "CRITICAL" if r.get("risk_score", 0) >= 80 else "MEDIUM",
            "Source IP": r.get("source_ip"),
            "HTTP Method": r.get("method"),
            "Host": r.get("host"),
            "Path": r.get("request_path"),
            "Requested URL": r.get("request_path"),
            "What NEXAF Did": r.get("action"),
            "Why It Happened": r.get("reason"),
            "Protection State": r.get("status"),
            "AI Provider": r.get("ai_provider"),
            "Execution Layer": r.get("execution_layer"),
            "Incident ID": r.get("incident_id"),
            "Recovery Status": ""
        })

    if format.lower() == "json":
        out = io.StringIO()
        json.dump(mapped_rows, out)
        return StreamingResponse(iter([out.getvalue()]), media_type="application/json", headers={"Content-Disposition": f"attachment; filename=nexaf-device-{device_id}-security-log.json"})
    else:
        out = io.StringIO()
        fieldnames = ["Time (UTC)", "Device ID", "Device Name", "Event ID", "Decision", "Threat Category", "Risk Score", "Risk Level", "Source IP", "HTTP Method", "Host", "Path", "Requested URL", "What NEXAF Did", "Why It Happened", "Protection State", "AI Provider", "Execution Layer", "Incident ID", "Recovery Status"]
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(mapped_rows or [{k: "" for k in fieldnames}])
        return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=nexaf-device-{device_id}-security-log.csv"})

@app.get("/events/stats")
def stats(user=Depends(require_roles("ADMIN", "ANALYST", "VIEWER"))):
    with SessionLocal() as db:
        total = db.query(SecurityEvent).count(); blocked = db.query(SecurityEvent).filter_by(decision="BLOCK").count()
        return {"total_events": total, "blocked": blocked, "allowed": total - blocked, "recoveries": db.query(SelfHealingEvent).filter_by(action="RECOVERY").count()}

@app.get("/events/export")
def export_events(attack_type: Optional[str] = None, decision: Optional[str] = None, start_date: Optional[str] = None, end_date: Optional[str] = None, user=Depends(require_roles("ADMIN", "ANALYST"))):
    with SessionLocal() as db:
        q = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
        if attack_type: q = q.filter(SecurityEvent.attack_type == attack_type)
        if decision: q = q.filter(SecurityEvent.decision == decision)
        if start_date: q = q.filter(SecurityEvent.timestamp >= start_date)
        if end_date: q = q.filter(SecurityEvent.timestamp <= end_date + "T23:59:59")
        rows = [event_dict(x) for x in q.limit(10000).all()]
        db.add(AuditLog(action_type="EXPORT", details=f"User {user['username']} exported {len(rows)} events")); db.commit()
        
    mapped_rows = []
    for r in rows:
        mapped_rows.append({
            "Time (IST)": r.get("timestamp"),
            "Event ID": r.get("event_id"),
            "Decision": "BLOCKED" if r.get("decision") == "BLOCK" else "ALLOWED",
            "Threat category": r.get("attack_type"),
            "Severity": r.get("severity"),
            "Source IP": r.get("source_ip"),
            "Requested URL": r.get("request_path"),
            "What NEXAF did": "Dropped the request" if r.get("action") == "DROP_REQUEST" else "Allowed the request",
            "Why it happened": r.get("reason"),
            "Protection state": r.get("status"),
            "Explanation provider": r.get("ai_provider"),
            "Execution layer": r.get("execution_layer")
        })
        
    out = io.StringIO()
    fieldnames = ["Time (IST)", "Event ID", "Decision", "Threat category", "Severity", "Source IP", "Requested URL", "What NEXAF did", "Why it happened", "Protection state", "Explanation provider", "Execution layer"]
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(mapped_rows or [{"Time (IST)": "No events"}])
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=nexaf-security-log.csv"})

@app.get("/events/{event_id}")
def event(event_id: str, user=Depends(require_roles("ADMIN", "ANALYST", "VIEWER"))):
    with SessionLocal() as db: row = db.get(SecurityEvent, event_id)
    if not row: raise HTTPException(404, "Event not found")
    return event_dict(row)
