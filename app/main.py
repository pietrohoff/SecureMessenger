
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List

from .core.secure_core import (
    get_conn, init_db, ensure_ca, add_user, list_users,
    send_message, list_inbox, read_message, verify_audit
)

app = FastAPI(title="Secure Messenger API")

# Serve Web UI (static)
app.mount("/static", StaticFiles(directory="app/frontend"), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    with open("app/frontend/index.html", "r", encoding="utf-8") as f:
        return f.read()

class NewUser(BaseModel):
    name: str

class SendReq(BaseModel):
    sender: str
    to: List[str]
    subject: str
    body: str

@app.post("/init-ca")
def init_ca():
    conn = get_conn(); init_db(conn); ensure_ca(conn)
    return {"ok": True}

@app.post("/users")
def create_user(body: NewUser):
    try:
        conn = get_conn(); init_db(conn); add_user(conn, body.name)
        return {"ok": True, "name": body.name}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/users")
def users():
    conn = get_conn(); init_db(conn)
    return {"users": list_users(conn)}

@app.post("/send")
def send(body: SendReq):
    try:
        conn = get_conn(); init_db(conn)
        mid = send_message(conn, body.sender, body.to, body.subject, body.body)
        return {"ok": True, "message_id": mid}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/inbox/{user}")
def inbox(user: str):
    conn = get_conn(); init_db(conn)
    rows = list_inbox(conn, user)
    return {"inbox": [dict(r) for r in rows]}

@app.get("/read/{user}/{msg_id}")
def read(user: str, msg_id: int):
    try:
        conn = get_conn(); init_db(conn)
        meta, body = read_message(conn, user, msg_id)
        return {"meta": meta, "body": body}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/audit")
def audit():
    conn = get_conn(); init_db(conn)
    rows = conn.execute("SELECT id, ts, event, payload_json FROM audit ORDER BY id").fetchall()
    return {"audit": [dict(r) for r in rows]}

@app.get("/audit/verify")
def audit_verify():
    conn = get_conn(); init_db(conn)
    return {"ok": verify_audit(conn)}
