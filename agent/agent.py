"""
Log & Activity Agent
Runs on each monitored PC. Collects Windows Event Logs, user activity
(active window, open apps, browser history), system metrics, and screenshots,
then streams everything to the central server over WebSocket.
"""

import argparse
import asyncio
import base64
import io
import json
import os
import platform
import random
import shutil
import socket
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import websockets

# ── platform detection ─────────────────────────────────────────────────
OS_NAME = platform.system()
HOSTNAME = socket.gethostname()
LOCAL_IP = socket.gethostbyname(HOSTNAME)

# ── Optional imports ───────────────────────────────────────────────────
if OS_NAME == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import pywintypes
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
    try:
        import ctypes
        import ctypes.wintypes
        WIN32GUI_AVAILABLE = True
    except ImportError:
        WIN32GUI_AVAILABLE = False
else:
    WIN32_AVAILABLE = False
    WIN32GUI_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import mss
    from PIL import Image
    MSS_AVAILABLE = True
except ImportError:
    MSS_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "server": "ws://localhost:8000/ws/agent",
    "interval": 3,
    "channels": ["System", "Application", "Security"],
    "log_files": [],
    "metrics_enabled": True,
    "metrics_interval": 10,
    "activity_enabled": True,
    "activity_interval": 5,
    "browser_history_enabled": True,
    "browser_history_limit": 50,
    "screenshot_enabled": True,
    "screenshot_interval": 1,
    "screenshot_quality": 35,
    "screenshot_max_width": 800,
    "group": "",
}


def load_config(path: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            config.update(user_config)
            print(f"[agent] Config loaded from {path}")
        except Exception as e:
            print(f"[agent] Warning: could not read {path}: {e}")
    else:
        print(f"[agent] No config file at {path}, using defaults")
    return config


# ══════════════════════════════════════════════════════════════════════
# Activity Collector — active window, open apps, browser history
# ══════════════════════════════════════════════════════════════════════

class ActivityCollector:
    """Collects user activity: active window, open apps, browser history."""

    def __init__(self, history_limit=50):
        self._history_limit = history_limit
        self._last_history_ids = set()
        if OS_NAME == "Windows" and WIN32GUI_AVAILABLE:
            self._user32 = ctypes.windll.user32
            self._kernel32 = ctypes.windll.kernel32
        else:
            self._user32 = None

    # ── Active window ──────────────────────────────────────────────────
    def get_active_window(self) -> dict:
        if not self._user32:
            return {"title": "", "process": ""}
        try:
            hwnd = self._user32.GetForegroundWindow()
            length = self._user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            self._user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value

            pid = ctypes.wintypes.DWORD()
            self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            process_name = ""
            if PSUTIL_AVAILABLE and pid.value:
                try:
                    process_name = psutil.Process(pid.value).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return {"title": title, "process": process_name}
        except Exception:
            return {"title": "", "process": ""}

    # system / background processes to skip
    _SKIP_PROCESSES = {
        "applicationframehost.exe", "textinputhost.exe", "shellexperiencehost.exe",
        "searchhost.exe", "searchui.exe", "startmenuexperiencehost.exe",
        "lockapp.exe", "runtimebroker.exe", "dwm.exe", "csrss.exe",
        "svchost.exe", "conhost.exe", "taskhostw.exe", "sihost.exe",
        "ctfmon.exe", "fontdrvhost.exe", "dllhost.exe", "smartscreen.exe",
        "securityhealthsystray.exe", "securityhealthservice.exe",
        "systemsettings.exe", "systemsettingsbroker.exe",
        "gamebarpresencewriter.exe", "gamebarftserver.exe",
        "widgetservice.exe", "widgets.exe", "ai.exe",
        "windowsinternal.composableshell.experiences.textinput.inputapp.exe",
        "ntoskrnl.exe", "registry", "system", "idle",
        "searchapp.exe", "corewindow.exe",
    }
    _SKIP_TITLES = {
        "program manager", "windows input experience",
        "microsoft text input application", "settings",
        "msrdc", "search", "DesktopWindowXamlSource",
    }

    # ── Open windows ───────────────────────────────────────────────────
    def get_open_windows(self) -> list:
        if not self._user32:
            return []
        windows = []
        seen_pids = set()

        def enum_callback(hwnd, _):
            if not self._user32.IsWindowVisible(hwnd):
                return True
            length = self._user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            self._user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value.strip()
            if not title:
                return True

            # skip known system titles
            if title.lower() in self._SKIP_TITLES:
                return True

            pid = ctypes.wintypes.DWORD()
            self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pid_val = pid.value

            if pid_val in seen_pids:
                return True
            seen_pids.add(pid_val)

            process_name = ""
            if PSUTIL_AVAILABLE and pid_val:
                try:
                    process_name = psutil.Process(pid_val).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return True

            # skip system/background processes
            if process_name.lower() in self._SKIP_PROCESSES:
                return True

            windows.append({
                "title": title[:200],
                "process": process_name,
                "pid": pid_val,
            })
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(
            ctypes.c_bool, ctypes.c_int, ctypes.POINTER(ctypes.c_int)
        )
        self._user32.EnumWindows(WNDENUMPROC(enum_callback), 0)
        return windows

    # ── Browser history ────────────────────────────────────────────────
    def get_browser_history(self) -> list:
        entries = []
        entries.extend(self._read_chromium_history("Google\\Chrome"))
        entries.extend(self._read_chromium_history("Microsoft\\Edge"))
        entries.extend(self._read_firefox_history())
        entries.sort(key=lambda x: x.get("visit_time", ""), reverse=True)
        return entries[:self._history_limit]

    def _read_chromium_history(self, browser_subpath: str) -> list:
        if OS_NAME != "Windows":
            return []
        local_app = os.environ.get("LOCALAPPDATA", "")
        if not local_app:
            return []
        db_path = os.path.join(
            local_app, browser_subpath, "User Data", "Default", "History"
        )
        if not os.path.isfile(db_path):
            return []
        return self._query_chromium_db(db_path, browser_subpath.split("\\")[-1])

    def _query_chromium_db(self, db_path: str, browser_name: str) -> list:
        entries = []
        tmp_path = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
            os.close(tmp_fd)
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            conn.execute("PRAGMA journal_mode=WAL")
            cursor = conn.execute("""
                SELECT u.url, u.title, v.visit_time
                FROM urls u
                JOIN visits v ON u.id = v.url
                ORDER BY v.visit_time DESC
                LIMIT ?
            """, (self._history_limit,))
            for url, title, visit_time in cursor.fetchall():
                ts = self._chromium_time_to_iso(visit_time)
                entries.append({
                    "browser": browser_name,
                    "url": url,
                    "title": title or "",
                    "visit_time": ts,
                })
            conn.close()
        except Exception:
            pass
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        return entries

    def _read_firefox_history(self) -> list:
        if OS_NAME != "Windows":
            return []
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            return []
        profiles_dir = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
        if not os.path.isdir(profiles_dir):
            return []

        entries = []
        for profile in os.listdir(profiles_dir):
            db_path = os.path.join(profiles_dir, profile, "places.sqlite")
            if not os.path.isfile(db_path):
                continue
            entries.extend(self._query_firefox_db(db_path))
            break
        return entries

    def _query_firefox_db(self, db_path: str) -> list:
        entries = []
        tmp_path = None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
            os.close(tmp_fd)
            shutil.copy2(db_path, tmp_path)

            conn = sqlite3.connect(tmp_path)
            cursor = conn.execute("""
                SELECT p.url, p.title, h.visit_date
                FROM moz_places p
                JOIN moz_historyvisits h ON p.id = h.place_id
                ORDER BY h.visit_date DESC
                LIMIT ?
            """, (self._history_limit,))
            for url, title, visit_date in cursor.fetchall():
                ts = self._firefox_time_to_iso(visit_date)
                entries.append({
                    "browser": "Firefox",
                    "url": url,
                    "title": title or "",
                    "visit_time": ts,
                })
            conn.close()
        except Exception:
            pass
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        return entries

    @staticmethod
    def _chromium_time_to_iso(chromium_ts) -> str:
        try:
            epoch_us = chromium_ts - 11644473600000000
            dt = datetime.fromtimestamp(epoch_us / 1_000_000, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return ""

    @staticmethod
    def _firefox_time_to_iso(ff_ts) -> str:
        try:
            dt = datetime.fromtimestamp(ff_ts / 1_000_000, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return ""

    def collect(self) -> dict:
        return {
            "active_window": self.get_active_window(),
            "open_windows": self.get_open_windows(),
        }

    def collect_history(self) -> list:
        return self.get_browser_history()


# ══════════════════════════════════════════════════════════════════════
# Screenshot Collector — captures screen as JPEG base64
# ══════════════════════════════════════════════════════════════════════

class ScreenshotCollector:
    def __init__(self, quality=35, max_width=800):
        self._quality = quality
        self._max_width = max_width
        self._sct = None

    def _get_sct(self):
        if self._sct is None:
            self._sct = mss.mss()
        return self._sct

    def capture(self) -> str:
        """Returns base64-encoded JPEG screenshot, or empty string on failure."""
        if not MSS_AVAILABLE:
            return ""
        try:
            sct = self._get_sct()
            monitor = sct.monitors[0]  # full virtual screen
            raw = sct.grab(monitor)
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
            # resize to save bandwidth
            w, h = img.size
            if w > self._max_width:
                ratio = self._max_width / w
                img = img.resize((self._max_width, int(h * ratio)), Image.BILINEAR)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=self._quality, optimize=False)
            return base64.b64encode(buf.getvalue()).decode("ascii")
        except Exception:
            self._sct = None
            return ""

    def capture_bytes(self) -> bytes:
        """Returns raw JPEG bytes (no base64), or empty bytes on failure."""
        if not MSS_AVAILABLE:
            return b""
        try:
            sct = self._get_sct()
            monitor = sct.monitors[0]
            raw = sct.grab(monitor)
            img = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")
            w, h = img.size
            if w > self._max_width:
                ratio = self._max_width / w
                img = img.resize((self._max_width, int(h * ratio)), Image.BILINEAR)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=self._quality, optimize=False)
            return buf.getvalue()
        except Exception:
            self._sct = None
            return b""


# ══════════════════════════════════════════════════════════════════════
# App Log Collector — logs real app focus changes & app open/close
# ══════════════════════════════════════════════════════════════════════

class AppLogCollector:
    """Tracks which apps the user switches to, opens, and closes."""

    def __init__(self):
        self._prev_active = ""
        self._prev_windows = set()  # set of (pid, process_name)

    def update(self, activity_data: dict):
        """Given activity snapshot, yield log entries about app events."""
        entries = []
        # Focus change
        aw = activity_data.get("active_window", {})
        current_title = aw.get("title", "")
        current_proc = aw.get("process", "")
        active_key = f"{current_proc}|{current_title}"
        if active_key != self._prev_active and current_title:
            entries.append({
                "level": "INFO",
                "source": "Işjeňlik",
                "message": f"🖥️ Açyldy: {current_title} ({current_proc})",
            })
            self._prev_active = active_key

        # Open/close detection
        open_windows = activity_data.get("open_windows", [])
        current_set = set()
        for w in open_windows:
            current_set.add((w.get("pid", 0), w.get("process", "")))

        if self._prev_windows:
            # newly opened
            for pid, proc in current_set - self._prev_windows:
                if proc:
                    entries.append({
                        "level": "INFO",
                        "source": "Işjeňlik",
                        "message": f"▶️ Programma açyldy: {proc}",
                    })
            # closed
            for pid, proc in self._prev_windows - current_set:
                if proc:
                    entries.append({
                        "level": "WARN",
                        "source": "Işjeňlik",
                        "message": f"⏹️ Programma ýapyldy: {proc}",
                    })
        self._prev_windows = current_set
        return entries


# ══════════════════════════════════════════════════════════════════════
# Log collectors (unchanged)
# ══════════════════════════════════════════════════════════════════════

class WindowsEventCollector:
    EVENT_TYPE_MAP = {
        win32evtlog.EVENTLOG_ERROR_TYPE:       "ERROR",
        win32evtlog.EVENTLOG_WARNING_TYPE:     "WARN",
        win32evtlog.EVENTLOG_INFORMATION_TYPE: "INFO",
        win32evtlog.EVENTLOG_AUDIT_SUCCESS:    "INFO",
        win32evtlog.EVENTLOG_AUDIT_FAILURE:    "ERROR",
    } if WIN32_AVAILABLE else {}

    def __init__(self, channels=None):
        self._channels = channels or ["System", "Application", "Security"]
        self._handles = {}
        for ch in self._channels:
            try:
                self._handles[ch] = win32evtlog.OpenEventLog(None, ch)
                win32evtlog.GetNumberOfEventLogRecords(self._handles[ch])
            except Exception as e:
                print(f"[agent] Could not open channel '{ch}': {e}")

    def collect(self):
        for ch, handle in self._handles.items():
            try:
                flags = (win32evtlog.EVENTLOG_SEQUENTIAL_READ
                         | win32evtlog.EVENTLOG_FORWARDS_READ)
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


class LogFileCollector:
    LEVEL_KEYWORDS = {
        "ERROR": ["error", "fail", "critical", "emerg", "alert", "crit", "fatal"],
        "WARN":  ["warn", "warning"],
        "DEBUG": ["debug", "trace"],
    }

    def __init__(self, paths):
        self._files = {}
        for path in paths:
            try:
                f = open(path, "r", encoding="utf-8", errors="replace")
                f.seek(0, 2)
                self._files[path] = f
                print(f"[agent] Tailing file: {path}")
            except (PermissionError, FileNotFoundError) as e:
                print(f"[agent] Cannot open {path}: {e}")

    def _detect_level(self, line: str) -> str:
        lower = line.lower()
        for level, keywords in self.LEVEL_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                return level
        return "INFO"

    def collect(self):
        for path, f in self._files.items():
            while True:
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                yield {
                    "level": self._detect_level(line),
                    "source": os.path.basename(path),
                    "message": line,
                }


class LinuxSyslogCollector:
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
                self._file.seek(0, 2)
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
        DemoCollector._COUNTER += 1
        n = random.randint(1, 4)
        for _ in range(n):
            level, msg = random.choice(self._MESSAGES)
            yield {
                "level": level,
                "source": random.choice(self._SOURCES),
                "message": f"[#{DemoCollector._COUNTER}] {msg}",
            }


# ══════════════════════════════════════════════════════════════════════
# System metrics collector
# ══════════════════════════════════════════════════════════════════════

class MetricsCollector:
    @staticmethod
    def collect() -> dict:
        m = {}
        try:
            m["cpu_percent"] = psutil.cpu_percent(interval=0)
        except Exception:
            m["cpu_percent"] = None
        try:
            mem = psutil.virtual_memory()
            m["ram_total_gb"] = round(mem.total / (1024 ** 3), 2)
            m["ram_used_gb"] = round(mem.used / (1024 ** 3), 2)
            m["ram_percent"] = mem.percent
        except Exception:
            pass
        try:
            disk = psutil.disk_usage("/" if OS_NAME != "Windows" else "C:\\")
            m["disk_total_gb"] = round(disk.total / (1024 ** 3), 2)
            m["disk_used_gb"] = round(disk.used / (1024 ** 3), 2)
            m["disk_percent"] = disk.percent
        except Exception:
            pass
        return m


# ══════════════════════════════════════════════════════════════════════
# Builder
# ══════════════════════════════════════════════════════════════════════

def build_collectors(config: dict):
    collectors = []
    channels = config.get("channels", ["System", "Application", "Security"])

    if OS_NAME == "Windows" and WIN32_AVAILABLE:
        print(f"[agent] Windows Event Log collector (channels: {channels})")
        collectors.append(WindowsEventCollector(channels=channels))
    elif OS_NAME in ("Linux", "Darwin"):
        c = LinuxSyslogCollector()
        if c._file:
            print("[agent] Using syslog collector")
            collectors.append(c)

    log_files = config.get("log_files", [])
    if log_files:
        collectors.append(LogFileCollector(log_files))

    if not collectors:
        print("[agent] No real sources — using demo collector")
        collectors.append(DemoCollector())

    return collectors


# ══════════════════════════════════════════════════════════════════════
# WebSocket agent loop
# ══════════════════════════════════════════════════════════════════════

async def run_agent(config: dict):
    server_url = config["server"]
    interval = config.get("interval", 3)
    metrics_enabled = config.get("metrics_enabled", True) and PSUTIL_AVAILABLE
    metrics_interval = config.get("metrics_interval", 10)
    activity_enabled = config.get("activity_enabled", True)
    activity_interval = config.get("activity_interval", 5)
    history_enabled = config.get("browser_history_enabled", True)
    history_limit = config.get("browser_history_limit", 50)
    screenshot_enabled = config.get("screenshot_enabled", True) and MSS_AVAILABLE
    screenshot_interval = config.get("screenshot_interval", 1)
    screenshot_quality = config.get("screenshot_quality", 35)
    screenshot_max_width = config.get("screenshot_max_width", 800)
    group = config.get("group", "")

    collectors = build_collectors(config)
    metrics_collector = MetricsCollector() if metrics_enabled else None
    activity_collector = ActivityCollector(history_limit=history_limit) if activity_enabled else None
    screenshot_collector = ScreenshotCollector(quality=screenshot_quality, max_width=screenshot_max_width) if screenshot_enabled else None
    app_log_collector = AppLogCollector() if activity_enabled else None

    while True:
        try:
            print(f"[agent] Connecting to {server_url} ...")
            async with websockets.connect(
                server_url, ping_interval=20, ping_timeout=10,
                max_size=10 * 1024 * 1024,
            ) as ws:
                await ws.send(json.dumps({
                    "type": "register",
                    "ip": LOCAL_IP,
                    "hostname": HOSTNAME,
                    "os": f"{OS_NAME} {platform.release()}",
                    "group": group,
                }))
                print(f"[agent] Connected — {HOSTNAME} ({LOCAL_IP})")

                if metrics_collector:
                    await ws.send(json.dumps({
                        "type": "metrics",
                        "metrics": metrics_collector.collect(),
                    }))

                # ── Screenshot streaming task (independent, high-FPS) ──
                async def screenshot_loop():
                    while True:
                        try:
                            jpg = screenshot_collector.capture_bytes()
                            if jpg:
                                await ws.send(jpg)  # binary frame
                        except Exception:
                            pass
                        await asyncio.sleep(screenshot_interval)

                screenshot_task = None
                if screenshot_collector:
                    screenshot_task = asyncio.create_task(screenshot_loop())

                last_metrics = time.monotonic()
                last_activity = time.monotonic()
                last_history = 0.0

                try:
                    while True:
                        # ── Logs ───────────────────────────────────────────
                        for collector in collectors:
                            for entry in collector.collect():
                                await ws.send(json.dumps({
                                    "type": "log",
                                    "level": entry.get("level", "INFO"),
                                    "source": entry.get("source", "system"),
                                    "message": entry.get("message", ""),
                                }))

                        # ── Metrics ────────────────────────────────────────
                        now = time.monotonic()
                        if metrics_collector and (now - last_metrics) >= metrics_interval:
                            await ws.send(json.dumps({
                                "type": "metrics",
                                "metrics": metrics_collector.collect(),
                            }))
                            last_metrics = now

                        # ── Activity ───────────────────────────────────────
                        if activity_collector and (now - last_activity) >= activity_interval:
                            activity_data = activity_collector.collect()
                            await ws.send(json.dumps({
                                "type": "activity",
                                "activity": activity_data,
                            }))
                            # App log entries (focus changes, open/close)
                            if app_log_collector:
                                for entry in app_log_collector.update(activity_data):
                                    await ws.send(json.dumps({
                                        "type": "log",
                                        "level": entry["level"],
                                        "source": entry["source"],
                                        "message": entry["message"],
                                    }))
                            last_activity = now

                        # ── Browser history (every 30s) ────────────────────
                        if (activity_collector and history_enabled
                                and (now - last_history) >= 30):
                            history = activity_collector.collect_history()
                            await ws.send(json.dumps({
                                "type": "browser_history",
                                "history": history,
                            }))
                            last_history = now

                        await asyncio.sleep(interval)
                finally:
                    if screenshot_task:
                        screenshot_task.cancel()
                        try:
                            await screenshot_task
                        except asyncio.CancelledError:
                            pass

        except (websockets.ConnectionClosed, OSError, ConnectionRefusedError) as e:
            print(f"[agent] Connection lost: {e}. Retrying in 5 s...")
            await asyncio.sleep(5)
        except Exception as e:
            print(f"[agent] Unexpected error: {e}. Retrying in 5 s...")
            await asyncio.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="Log & Activity streaming agent")
    parser.add_argument("--server", help="WebSocket URL of the log server")
    parser.add_argument("--interval", type=float, help="Polling interval (s)")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--group", help="Agent group name")
    args = parser.parse_args()

    if not os.path.isabs(args.config):
        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), args.config
        )
    else:
        config_path = args.config

    config = load_config(config_path)

    if args.server:
        config["server"] = args.server
    if args.interval:
        config["interval"] = args.interval
    if args.group:
        config["group"] = args.group

    asyncio.run(run_agent(config))


if __name__ == "__main__":
    main()
