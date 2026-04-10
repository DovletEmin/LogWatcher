"""
Log Collector Server
Accepts WebSocket connections from agents on remote PCs,
stores logs, activity data, browser history, and system metrics.
Serves them to the web frontend via REST + WebSocket.
"""

import asyncio
import json
import uuid
import base64
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocketState
import uvicorn

app = FastAPI(title="Log Collector Server", version="3.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_LOGS_PER_HOST = 5000

logs_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_LOGS_PER_HOST))
agents_info: Dict[str, dict] = {}
frontend_listeners: Dict[str, Set[WebSocket]] = defaultdict(set)

stats_store: Dict[str, dict] = {}

def _new_stats() -> dict:
    return {
        "total": 0,
        "by_level": {"INFO": 0, "WARN": 0, "ERROR": 0, "DEBUG": 0},
        "per_minute": deque(maxlen=60),
        "sources": defaultdict(int),
    }

metrics_store: Dict[str, dict] = {}

activity_store: Dict[str, dict] = {}       # ip -> latest activity snapshot
history_store: Dict[str, list] = {}        # ip -> latest browser history
screenshot_store: Dict[str, str] = {}      # ip -> latest base64 JPEG

multi_listeners: Set[WebSocket] = set()


def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def _minute_key() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M")


async def broadcast_to_listeners(ip: str, message: dict):
    dead: List[WebSocket] = []
    for ws in list(frontend_listeners[ip]):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        frontend_listeners[ip].discard(ws)


async def broadcast_to_multi(message: dict):
    dead: List[WebSocket] = []
    for ws in list(multi_listeners):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        multi_listeners.discard(ws)


def update_stats(ip: str, level: str, source: str):
    if ip not in stats_store:
        stats_store[ip] = _new_stats()
    s = stats_store[ip]
    s["total"] += 1
    level_u = level.upper()
    if level_u in s["by_level"]:
        s["by_level"][level_u] += 1
    s["sources"][source] += 1
    mk = _minute_key()
    if s["per_minute"] and s["per_minute"][-1]["minute"] == mk:
        s["per_minute"][-1]["count"] += 1
    else:
        s["per_minute"].append({"minute": mk, "count": 1})


async def broadcast_screenshot_binary(ip: str, jpeg_bytes: bytes):
    """Send screenshot as binary to frontend listeners, store b64 for REST."""
    b64 = base64.b64encode(jpeg_bytes).decode("ascii")
    screenshot_store[ip] = b64
    if ip in agents_info:
        agents_info[ip]["last_seen"] = now_iso()
    dead_v: List[WebSocket] = []
    for ws in list(frontend_listeners[ip]):
        try:
            await ws.send_bytes(jpeg_bytes)
        except Exception:
            dead_v.append(ws)
    for ws in dead_v:
        frontend_listeners[ip].discard(ws)
    dead_m: List[WebSocket] = []
    for ws in list(multi_listeners):
        try:
            await ws.send_bytes(jpeg_bytes)
        except Exception:
            dead_m.append(ws)
    for ws in dead_m:
        multi_listeners.discard(ws)


# ── agent WebSocket endpoint ───────────────────────────────────────────
@app.websocket("/ws/agent")
async def agent_endpoint(websocket: WebSocket):
    await websocket.accept()
    agent_ip = None
    try:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break

            # Binary frame = raw JPEG screenshot
            if "bytes" in message and message["bytes"]:
                if agent_ip:
                    await broadcast_screenshot_binary(agent_ip, message["bytes"])
                continue

            # Text frame = JSON message
            raw = message.get("text", "")
            if not raw:
                continue
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
                    "group": data.get("group", ""),
                    "connected_at": now_iso(),
                    "last_seen": now_iso(),
                    "status": "online",
                }
                msg = {
                    "type": "agent_status", "ip": agent_ip,
                    "status": "online", "info": agents_info[agent_ip],
                }
                await broadcast_to_listeners(agent_ip, msg)
                await broadcast_to_multi(msg)

            elif msg_type == "log" and agent_ip:
                entry = {
                    "id": str(uuid.uuid4()),
                    "timestamp": now_iso(),
                    "level": data.get("level", "INFO").upper(),
                    "source": data.get("source", "unknown"),
                    "message": data.get("message", ""),
                }
                logs_store[agent_ip].append(entry)
                update_stats(agent_ip, entry["level"], entry["source"])
                if agent_ip in agents_info:
                    agents_info[agent_ip]["last_seen"] = entry["timestamp"]
                msg = {"type": "log", "ip": agent_ip, "entry": entry}
                await broadcast_to_listeners(agent_ip, msg)
                await broadcast_to_multi(msg)

            elif msg_type == "metrics" and agent_ip:
                metrics_store[agent_ip] = {
                    "timestamp": now_iso(),
                    **data.get("metrics", {}),
                }
                if agent_ip in agents_info:
                    agents_info[agent_ip]["last_seen"] = now_iso()
                msg = {"type": "metrics", "ip": agent_ip,
                       "metrics": metrics_store[agent_ip]}
                await broadcast_to_listeners(agent_ip, msg)
                await broadcast_to_multi(msg)

            elif msg_type == "activity" and agent_ip:
                activity_data = data.get("activity", {})
                activity_data["timestamp"] = now_iso()
                activity_store[agent_ip] = activity_data
                if agent_ip in agents_info:
                    agents_info[agent_ip]["last_seen"] = now_iso()
                msg = {"type": "activity", "ip": agent_ip,
                       "activity": activity_data}
                await broadcast_to_listeners(agent_ip, msg)
                await broadcast_to_multi(msg)

            elif msg_type == "browser_history" and agent_ip:
                history = data.get("history", [])
                history_store[agent_ip] = history
                if agent_ip in agents_info:
                    agents_info[agent_ip]["last_seen"] = now_iso()
                msg = {"type": "browser_history", "ip": agent_ip,
                       "history": history}
                await broadcast_to_listeners(agent_ip, msg)
                await broadcast_to_multi(msg)

            elif msg_type == "screenshot" and agent_ip:
                b64 = data.get("data", "")
                if b64:
                    screenshot_store[agent_ip] = b64
                    if agent_ip in agents_info:
                        agents_info[agent_ip]["last_seen"] = now_iso()
                    msg = {"type": "screenshot", "ip": agent_ip,
                           "data": b64}
                    await broadcast_to_listeners(agent_ip, msg)
                    await broadcast_to_multi(msg)

    except WebSocketDisconnect:
        pass
    finally:
        if agent_ip and agent_ip in agents_info:
            agents_info[agent_ip]["status"] = "offline"
            msg = {
                "type": "agent_status", "ip": agent_ip,
                "status": "offline", "info": agents_info[agent_ip],
            }
            await broadcast_to_listeners(agent_ip, msg)
            await broadcast_to_multi(msg)


@app.websocket("/ws/view/{ip}")
async def view_endpoint(websocket: WebSocket, ip: str):
    await websocket.accept()
    frontend_listeners[ip].add(websocket)

    await websocket.send_text(json.dumps({
        "type": "history",
        "ip": ip,
        "entries": list(logs_store.get(ip, [])),
        "agent_info": agents_info.get(ip),
        "metrics": metrics_store.get(ip),
        "activity": activity_store.get(ip),
        "browser_history": history_store.get(ip),
        "screenshot": screenshot_store.get(ip),
    }))

    try:
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


@app.websocket("/ws/multi")
async def multi_view_endpoint(websocket: WebSocket):
    await websocket.accept()
    multi_listeners.add(websocket)

    all_entries = []
    for ip, entries in logs_store.items():
        for e in entries:
            all_entries.append({**e, "agent_ip": ip})
    all_entries.sort(key=lambda x: x.get("timestamp", ""))

    await websocket.send_text(json.dumps({
        "type": "multi_history",
        "entries": all_entries[-2000:],
        "agents": list(agents_info.values()),
        "metrics": {k: v for k, v in metrics_store.items()},
        "all_activity": {k: v for k, v in activity_store.items()},
        "all_history": {k: v for k, v in history_store.items()},
    }))

    try:
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
        multi_listeners.discard(websocket)


@app.get("/api/agents")
def list_agents():
    return JSONResponse(list(agents_info.values()))


@app.get("/api/agents/groups")
def list_groups():
    groups: Dict[str, list] = defaultdict(list)
    for info in agents_info.values():
        g = info.get("group", "") or "Ungrouped"
        groups[g].append(info)
    return JSONResponse(dict(groups))


@app.get("/api/logs/{ip}")
def get_logs(ip: str, limit: int = 500, level: str = None, search: str = None):
    if ip not in logs_store and ip not in agents_info:
        raise HTTPException(status_code=404, detail="No data for this IP")
    entries = list(logs_store.get(ip, []))
    if level:
        lu = level.upper()
        entries = [e for e in entries if e["level"] == lu]
    if search:
        sl = search.lower()
        entries = [e for e in entries
                   if sl in e["message"].lower() or sl in e["source"].lower()]
    return JSONResponse({
        "ip": ip, "agent_info": agents_info.get(ip),
        "total": len(entries), "entries": entries[-limit:],
    })


@app.delete("/api/logs/{ip}")
def clear_logs(ip: str):
    if ip in logs_store:
        logs_store[ip].clear()
    if ip in stats_store:
        stats_store[ip] = _new_stats()
    return JSONResponse({"status": "cleared", "ip": ip})


@app.get("/api/activity/{ip}")
def get_activity(ip: str):
    return JSONResponse({
        "ip": ip,
        "activity": activity_store.get(ip),
        "browser_history": history_store.get(ip),
    })


@app.get("/api/screenshot/{ip}")
def get_screenshot(ip: str):
    b64 = screenshot_store.get(ip)
    if not b64:
        return JSONResponse({"ip": ip, "data": None}, status_code=200)
    return JSONResponse({"ip": ip, "data": b64})


@app.get("/api/stats")
def global_stats():
    total = 0
    by_level = {"INFO": 0, "WARN": 0, "ERROR": 0, "DEBUG": 0}
    agg_pm = defaultdict(int)
    agg_src = defaultdict(int)
    for ip, s in stats_store.items():
        total += s["total"]
        for lv, c in s["by_level"].items():
            by_level[lv] += c
        for pm in s["per_minute"]:
            agg_pm[pm["minute"]] += pm["count"]
        for src, c in s["sources"].items():
            agg_src[src] += c
    pm_sorted = sorted(agg_pm.items())[-30:]
    top_src = sorted(agg_src.items(), key=lambda x: x[1], reverse=True)[:10]
    online = sum(1 for a in agents_info.values() if a.get("status") == "online")
    return JSONResponse({
        "total_logs": total, "by_level": by_level,
        "per_minute": [{"minute": m, "count": c} for m, c in pm_sorted],
        "top_sources": [{"source": s, "count": c} for s, c in top_src],
        "agents_online": online, "agents_total": len(agents_info),
        "metrics": {k: v for k, v in metrics_store.items()},
    })


@app.get("/api/stats/{ip}")
def agent_stats(ip: str):
    if ip not in stats_store and ip not in agents_info:
        raise HTTPException(status_code=404, detail="No data for this IP")
    s = stats_store.get(ip, _new_stats())
    pm = [{"minute": p["minute"], "count": p["count"]} for p in s["per_minute"]]
    top = sorted(s["sources"].items(), key=lambda x: x[1], reverse=True)[:10]
    return JSONResponse({
        "ip": ip, "agent_info": agents_info.get(ip),
        "total_logs": s["total"], "by_level": dict(s["by_level"]),
        "per_minute": pm[-30:],
        "top_sources": [{"source": sr, "count": c} for sr, c in top],
        "metrics": metrics_store.get(ip),
    })


@app.get("/api/metrics/{ip}")
def get_metrics(ip: str):
    if ip not in metrics_store:
        raise HTTPException(status_code=404, detail="No metrics for this IP")
    return JSONResponse(metrics_store[ip])


@app.get("/api/health")
def health():
    return JSONResponse({
        "status": "ok", "uptime": now_iso(),
        "agents": len(agents_info),
        "agents_online": sum(1 for a in agents_info.values() if a.get("status") == "online"),
    })


import pathlib as _pathlib
_frontend_dir = _pathlib.Path(__file__).resolve().parent.parent / "frontend"
if _frontend_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False,
                ws_max_size=10 * 1024 * 1024)
