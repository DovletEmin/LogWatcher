"""
Log Agent
Runs on each monitored PC. Collects Windows Event Logs (or syslog on Linux/macOS)
and streams them to the central server over WebSocket.

Usage:
    python agent.py --server ws://192.168.1.100:8000/ws/agent

Optional flags:
    --server   WebSocket URL of the server  (default: ws://localhost:8000/ws/agent)
    --interval Log polling interval in seconds (default: 3)
"""

import argparse
import asyncio
import json
import platform
import socket
import sys
import time
from datetime import datetime, timezone

import websockets

# ── platform detection ─────────────────────────────────────────────────
OS_NAME = platform.system()          # "Windows" | "Linux" | "Darwin"
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)

# ── Windows-only import ────────────────────────────────────────────────
if OS_NAME == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import pywintypes
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
else:
    WIN32_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════
# Log collectors
# ══════════════════════════════════════════════════════════════════════

class WindowsEventCollector:
    """Reads Windows Event Log channels."""

    CHANNELS = {
        "System":      "System",
        "Application": "Application",
        "Security":    "Security",
    }

    EVENT_TYPE_MAP = {
        win32evtlog.EVENTLOG_ERROR_TYPE:       "ERROR",
        win32evtlog.EVENTLOG_WARNING_TYPE:     "WARN",
        win32evtlog.EVENTLOG_INFORMATION_TYPE: "INFO",
        win32evtlog.EVENTLOG_AUDIT_SUCCESS:    "INFO",
        win32evtlog.EVENTLOG_AUDIT_FAILURE:    "ERROR",
    } if WIN32_AVAILABLE else {}

    def __init__(self):
        self._handles = {}
        self._last_read = {}
        for ch in self.CHANNELS:
            try:
                self._handles[ch] = win32evtlog.OpenEventLog(None, ch)
                # seek to end so we only get new events going forward
                total = win32evtlog.GetNumberOfEventLogRecords(self._handles[ch])
                self._last_read[ch] = total
            except Exception:
                pass

    def collect(self):
        """Yield new log entries since last call."""
        for ch, handle in self._handles.items():
            try:
                flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                for ev in events:
                    level = self.EVENT_TYPE_MAP.get(ev.EventType, "INFO")
                    try:
                        msg = win32evtlogutil.SafeFormatMessage(ev, ch)
                    except Exception:
                        msg = f"(Event ID {ev.EventID & 0xFFFF})"
                    ts = ev.TimeGenerated.Format("%Y-%m-%dT%H:%M:%S") + "Z"
                    yield {
                        "level": level,
                        "source": f"{ch}/{ev.SourceName}",
                        "message": msg.strip().replace("\r\n", " ").replace("\n", " "),
                        "timestamp_hint": ts,
                    }
            except Exception:
                pass


class LinuxSyslogCollector:
    """Tails /var/log/syslog (or /var/log/messages) for new lines."""

    SYSLOG_PATHS = ["/var/log/syslog", "/var/log/messages", "/var/log/system.log"]

    LEVEL_KEYWORDS = {
        "ERROR": ["error", "fail", "critical", "emerg", "alert", "crit"],
        "WARN":  ["warn", "warning"],
        "DEBUG": ["debug"],
    }

    def __init__(self):
        self._file = None
        for path in self.SYSLOG_PATHS:
            try:
                self._file = open(path, "r", encoding="utf-8", errors="replace")
                self._file.seek(0, 2)  # seek to end
                break
            except (PermissionError, FileNotFoundError):
                pass

    def _detect_level(self, line: str) -> str:
        lower = line.lower()
        for level, keywords in self.LEVEL_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                return level
        return "INFO"

    def collect(self):
        if self._file is None:
            return
        while True:
            line = self._file.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            yield {
                "level": self._detect_level(line),
                "source": "syslog",
                "message": line,
            }


class DemoCollector:
    """Generates fake log entries for demonstration / testing."""

    import random as _random
    import itertools as _it

    _COUNTER = 0
    _SOURCES = ["Kernel", "NetworkManager", "DHCP", "Auth", "App", "Scheduler"]
    _MESSAGES = [
        ("INFO",  "Service started successfully"),
        ("INFO",  "Configuration loaded"),
        ("INFO",  "Connection established"),
        ("WARN",  "High memory usage detected: 85%"),
        ("WARN",  "Disk space low on C:\\: 12% remaining"),
        ("ERROR", "Failed to connect to remote host"),
        ("ERROR", "Authentication failure for user admin"),
        ("DEBUG", "Polling interval tick"),
        ("INFO",  "Backup completed"),
        ("WARN",  "Slow response time from DNS server"),
    ]

    def collect(self):
        import random
        DemoCollector._COUNTER += 1
        n = random.randint(1, 4)
        for _ in range(n):
            level, msg = random.choice(self._MESSAGES)
            yield {
                "level": level,
                "source": random.choice(self._SOURCES),
                "message": f"[#{DemoCollector._COUNTER}] {msg}",
            }


def build_collector():
    if OS_NAME == "Windows" and WIN32_AVAILABLE:
        print("[agent] Using Windows Event Log collector")
        return WindowsEventCollector()
    elif OS_NAME in ("Linux", "Darwin"):
        c = LinuxSyslogCollector()
        if c._file:
            print(f"[agent] Using syslog collector")
            return c
    print("[agent] pywin32 not found or unsupported OS — using demo collector")
    return DemoCollector()


# ══════════════════════════════════════════════════════════════════════
# WebSocket agent loop
# ══════════════════════════════════════════════════════════════════════

async def run_agent(server_url: str, interval: float):
    collector = build_collector()

    while True:
        try:
            print(f"[agent] Connecting to {server_url} ...")
            async with websockets.connect(server_url, ping_interval=20, ping_timeout=10) as ws:
                # register
                await ws.send(json.dumps({
                    "type": "register",
                    "ip": LOCAL_IP,
                    "hostname": HOSTNAME,
                    "os": f"{OS_NAME} {platform.release()}",
                }))
                print(f"[agent] Connected. Streaming logs from {HOSTNAME} ({LOCAL_IP})")

                while True:
                    for entry in collector.collect():
                        payload = {
                            "type": "log",
                            "level": entry.get("level", "INFO"),
                            "source": entry.get("source", "system"),
                            "message": entry.get("message", ""),
                        }
                        await ws.send(json.dumps(payload))
                    await asyncio.sleep(interval)

        except (websockets.ConnectionClosed, OSError, ConnectionRefusedError) as e:
            print(f"[agent] Connection lost: {e}. Retrying in 5 s...")
            await asyncio.sleep(5)
        except Exception as e:
            print(f"[agent] Unexpected error: {e}. Retrying in 5 s...")
            await asyncio.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="Log streaming agent")
    parser.add_argument(
        "--server",
        default="ws://localhost:8000/ws/agent",
        help="WebSocket URL of the log server",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Log polling interval in seconds (default: 3)",
    )
    args = parser.parse_args()
    asyncio.run(run_agent(args.server, args.interval))


if __name__ == "__main__":
    main()
