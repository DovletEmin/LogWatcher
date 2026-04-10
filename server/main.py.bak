"""
Log Collector Server
Accepts WebSocket connections from agents on remote PCs,
stores logs in memory, and serves them to the web frontend via REST + WebSocket.
"""

import asyncio
import json
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Log Collector Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── storage ────────────────────────────────────────────────────────────
MAX_LOGS_PER_HOST = 2000

# ip -> deque of log entries
logs_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_LOGS_PER_HOST))

# ip -> agent info  {"ip": ..., "hostname": ..., "os": ..., "connected_at": ..., "last_seen": ...}
agents_info: Dict[str, dict] = {}

# ip -> set of frontend WebSocket connections watching that host
frontend_listeners: Dict[str, Set[WebSocket]] = defaultdict(set)


# ── helpers ────────────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


async def broadcast_to_listeners(ip: str, message: dict):
    """Send a message to all frontend clients watching a given IP."""
    dead: List[WebSocket] = []
    for ws in list(frontend_listeners[ip]):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        frontend_listeners[ip].discard(ws)


# ── agent WebSocket endpoint ───────────────────────────────────────────
@app.websocket("/ws/agent")
async def agent_endpoint(websocket: WebSocket):
    """
    Agents connect here and send JSON messages:
      {"type": "register", "ip": "192.168.1.5", "hostname": "PC-NAME", "os": "Windows 10"}
      {"type": "log", "level": "INFO|WARN|ERROR|DEBUG", "source": "System", "message": "..."}
    """
    await websocket.accept()
    agent_ip = None
    try:
        async for raw in websocket.iter_text():
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            if msg_type == "register":
                agent_ip = data.get("ip", websocket.client.host)
                agents_info[agent_ip] = {
                    "ip": agent_ip,
                    "hostname": data.get("hostname", "unknown"),
                    "os": data.get("os", "unknown"),
                    "connected_at": now_iso(),
                    "last_seen": now_iso(),
                    "status": "online",
                }
                await broadcast_to_listeners(
                    agent_ip,
                    {"type": "agent_status", "ip": agent_ip, "status": "online",
                     "info": agents_info[agent_ip]},
                )

            elif msg_type == "log" and agent_ip:
                entry = {
                    "id": str(uuid.uuid4()),
                    "timestamp": now_iso(),
                    "level": data.get("level", "INFO").upper(),
                    "source": data.get("source", "unknown"),
                    "message": data.get("message", ""),
                }
                logs_store[agent_ip].append(entry)
                if agent_ip in agents_info:
                    agents_info[agent_ip]["last_seen"] = entry["timestamp"]

                await broadcast_to_listeners(
                    agent_ip,
                    {"type": "log", "ip": agent_ip, "entry": entry},
                )

    except WebSocketDisconnect:
        pass
    finally:
        if agent_ip and agent_ip in agents_info:
            agents_info[agent_ip]["status"] = "offline"
            await broadcast_to_listeners(
                agent_ip,
                {"type": "agent_status", "ip": agent_ip, "status": "offline",
                 "info": agents_info[agent_ip]},
            )


# ── frontend WebSocket endpoint ────────────────────────────────────────
@app.websocket("/ws/view/{ip}")
async def view_endpoint(websocket: WebSocket, ip: str):
    """
    Frontend clients subscribe to logs for a specific IP.
    They immediately receive all buffered logs, then get live updates.
    """
    await websocket.accept()
    frontend_listeners[ip].add(websocket)

    # send buffered logs immediately
    buffered = list(logs_store.get(ip, []))
    await websocket.send_text(json.dumps({
        "type": "history",
        "ip": ip,
        "entries": buffered,
        "agent_info": agents_info.get(ip),
    }))

    try:
        # keep connection alive; client can send {"type": "ping"}
        async for raw in websocket.iter_text():
            try:
                data = json.loads(raw)
                if data.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        frontend_listeners[ip].discard(websocket)


# ── REST endpoints ─────────────────────────────────────────────────────
@app.get("/api/agents")
def list_agents():
    """Return list of all known agents."""
    return JSONResponse(list(agents_info.values()))


@app.get("/api/logs/{ip}")
def get_logs(ip: str, limit: int = 500, level: str = None, search: str = None):
    """Return buffered logs for an IP with optional filtering."""
    if ip not in logs_store and ip not in agents_info:
        raise HTTPException(status_code=404, detail="No data for this IP")

    entries = list(logs_store.get(ip, []))

    if level:
        level_upper = level.upper()
        entries = [e for e in entries if e["level"] == level_upper]

    if search:
        search_lower = search.lower()
        entries = [
            e for e in entries
            if search_lower in e["message"].lower() or search_lower in e["source"].lower()
        ]

    return JSONResponse({
        "ip": ip,
        "agent_info": agents_info.get(ip),
        "total": len(entries),
        "entries": entries[-limit:],
    })


@app.delete("/api/logs/{ip}")
def clear_logs(ip: str):
    """Clear all buffered logs for an IP."""
    if ip in logs_store:
        logs_store[ip].clear()
    return JSONResponse({"status": "cleared", "ip": ip})


@app.get("/api/health")
def health():
    return {"status": "ok", "agents_connected": len(agents_info)}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
