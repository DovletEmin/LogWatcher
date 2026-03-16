# LogWatcher — Real-time Remote Log Viewer

LogWatcher is a small real-time remote log viewer.

## Architecture

```
[Monitored PC (agent)] --WebSocket--> [FastAPI Server] <--WebSocket-- [Browser (frontend)]
```

- `agent/` — Python agent run on each monitored machine
- `server/` — FastAPI server (central collector and API)
- `frontend/` — Browser UI (static frontend)

---

## Quick start

### 1. Run the server

```bash
cd server
pip install -r requirements.txt
python main.py
```

The server listens on `http://0.0.0.0:8000` by default.

### 2. Run the agent (on each monitored machine)

```bash
cd agent
pip install -r requirements.txt
python agent.py --server ws://<SERVER_IP>:8000/ws/agent
```

For reading real Windows Event Logs (optional):

```bash
pip install pywin32
```

Without `pywin32` the agent runs in demo mode and generates sample log entries.

### 3. Open the web UI

Open `frontend/index.html` in your browser.

Set the **Server** to `ws://<SERVER_IP>:8000` (for example `ws://192.168.1.100:8000`).
Enter the monitored machine IP in **Computer IP** and click **Watch logs**.

---

## Agent arguments

| Argument     | Default                        | Description                     |
| ------------ | ------------------------------ | ------------------------------- |
| `--server`   | `ws://localhost:8000/ws/agent` | WebSocket URL of the log server |
| `--interval` | `3`                            | Log polling interval (seconds)  |

---

## Server REST API

| Method | URL                          | Description                             |
| ------ | ---------------------------- | --------------------------------------- |
| GET    | `/api/agents`                | List known agents                       |
| GET    | `/api/logs/{ip}`             | Get buffered logs for an IP             |
| GET    | `/api/logs/{ip}?level=ERROR` | Filter by level                         |
| GET    | `/api/logs/{ip}?search=fail` | Search by text                          |
| DELETE | `/api/logs/{ip}`             | Clear buffered logs                     |
| GET    | `/api/health`                | Server health                           |
| WS     | `/ws/agent`                  | WebSocket endpoint for agents           |
| WS     | `/ws/view/{ip}`              | WebSocket endpoint for frontend viewers |

FastAPI also exposes interactive API docs at `/docs` when the server is running.
