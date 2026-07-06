"""
app.py — Optical Lab Portal
Full-stack web layer for managing Polatis optical switches.
Supports multiple switches (selected per-session), user authentication,
and a change log. Cisco T5 and Circuit Provisioning are placeholders.

Users:   users.json      {"alice": "pass1"}
Switches: switches.json  (list of switch definitions)
Log:     change_log.json (appended on every create/remove)

Run:
    python3 app.py
"""

import json
import logging
import os
import re
import socket
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, jsonify, request, send_from_directory,
                   session, redirect, url_for)

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
USERS_FILE     = os.path.join(BASE_DIR, "users.json")
CHANGELOG_FILE = os.path.join(BASE_DIR, "change_log.json")
SWITCHES_FILE  = os.path.join(BASE_DIR, "switches.json")
TIMERS_FILE    = os.path.join(BASE_DIR, "patch_timers.json")
SERVER_PORT    = int(os.environ.get("SERVER_PORT", "8888"))

NUM_PORTS          = 114
EXPIRING_THRESHOLD = 300
MAX_LABEL_LEN      = 64
MAX_DURATION_MIN   = 10080
READ_PAUSE         = 1.5
MAX_TRIES          = 4
TIMEOUT            = 30

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")


# --------------------------------------------------------------------------- #
# Switch registry
# --------------------------------------------------------------------------- #
def load_switches() -> list:
    with open(SWITCHES_FILE) as f:
        return json.load(f)


def get_switch_cfg(switch_id: str) -> dict:
    for sw in load_switches():
        if sw["id"] == switch_id:
            return sw
    return None


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        default = {"admin": "admin123"}
        with open(USERS_FILE, "w") as f:
            json.dump(default, f, indent=2)
        log.warning("users.json not found — created with default admin/admin123")
        return default
    with open(USERS_FILE) as f:
        return json.load(f)


def check_credentials(username: str, password: str) -> bool:
    return load_users().get(username) == password


# --------------------------------------------------------------------------- #
# Change log
# --------------------------------------------------------------------------- #
def _load_changelog() -> list:
    if not os.path.exists(CHANGELOG_FILE):
        return []
    try:
        with open(CHANGELOG_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def append_changelog(entry: dict):
    entries = _load_changelog()
    entries.append(entry)
    with open(CHANGELOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)


# --------------------------------------------------------------------------- #
# Timer persistence (shared across all switches, keyed by switch_id+patchkey)
# --------------------------------------------------------------------------- #
_timers_lock = threading.Lock()
_timers: dict = {}


def _load_timers():
    global _timers
    if not os.path.exists(TIMERS_FILE):
        _timers = {}
        return
    try:
        with open(TIMERS_FILE) as f:
            _timers = json.load(f)
    except Exception:
        _timers = {}


def _save_timers():
    tmp = TIMERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_timers, f, indent=2)
    os.replace(tmp, TIMERS_FILE)


def _tkey(switch_id, a, b):
    return f"{switch_id}:{min(a,b)}-{max(a,b)}"


def tkey_short(a, b):
    return f"{min(a,b)}-{max(a,b)}"


def get_timer(switch_id, patch_key):
    full = _tkey(switch_id, *map(int, patch_key.split("-")))
    with _timers_lock:
        v = _timers.get(full)
        return dict(v) if v else None


def set_timer(switch_id, patch_key, expires_iso, label):
    full = _tkey(switch_id, *map(int, patch_key.split("-")))
    with _timers_lock:
        _timers[full] = {"expires": expires_iso, "label": label or ""}
        _save_timers()


def del_timer(switch_id, patch_key):
    full = _tkey(switch_id, *map(int, patch_key.split("-")))
    with _timers_lock:
        existed = _timers.pop(full, None) is not None
        if existed:
            _save_timers()


def timers_snapshot(switch_id):
    prefix = f"{switch_id}:"
    with _timers_lock:
        return {
            k[len(prefix):]: dict(v)
            for k, v in _timers.items()
            if k.startswith(prefix)
        }


# --------------------------------------------------------------------------- #
# TL1 switch I/O  (self-contained, no switch1_menu dependency)
# --------------------------------------------------------------------------- #
def _tl1_connect(host, port, user, password):
    sock = socket.create_connection((host, int(port)), 10)
    sock.settimeout(10)
    _tl1_send_read(sock, f"act-user::{user}:1::{password};")
    return sock


def _tl1_send_read(sock, cmd):
    import re as _re
    if not cmd.endswith(";"):
        cmd += ";"
    sock.sendall((cmd + "\r\n").encode("ascii"))
    buf = ""
    while True:
        try:
            chunk = sock.recv(4096).decode("ascii", errors="replace")
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if _re.search(r"(?m)^\s*;\s*$", buf):
            break
    return buf


def _tl1_rw(sock, cmd):
    sock.sendall((cmd + "\r\n").encode())
    time.sleep(READ_PAUSE)
    r = b""
    try:
        sock.settimeout(1.0)
        while True:
            c = sock.recv(4096)
            if not c:
                break
            r += c
    except socket.timeout:
        pass
    finally:
        sock.settimeout(TIMEOUT)
    return r.decode(errors="replace")


def sw_get_patches(sw):
    import re as _re
    try:
        sock = _tl1_connect(sw["host"], sw["port"], sw["user"], sw["pass"])
        raw = _tl1_send_read(sock, "rtrv-patch:::1:;")
        sock.close()
    except Exception as e:
        raise ConnectionError(str(e))
    patches = {}
    for line in raw.splitlines():
        line = line.strip().strip('"')
        m = _re.match(r"(\d+)\s*,\s*(\d+)", line)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            patches[a] = b
            patches[b] = a
    return patches


def sw_get_power(sw):
    import re as _re
    try:
        sock = _tl1_connect(sw["host"], sw["port"], sw["user"], sw["pass"])
        _tl1_send_read(sock, "set-port-pmon::1&&114:1:::wave=1310;")
        raw = _tl1_send_read(sock, "rtrv-port-pmon::1&&114:1:;")
        sock.close()
    except Exception as e:
        raise ConnectionError(str(e))
    out = {}
    for line in raw.splitlines():
        line = line.strip().strip('"')
        m = _re.match(r"(\d+):([\d.]+),([\d.-]+),(\d+)", line)
        if m:
            try:
                out[int(m.group(1))] = float(m.group(3))
            except Exception:
                pass
    return {p: out.get(p) for p in range(1, NUM_PORTS + 1)}


def sw_mk_patch(sw, a, b):
    try:
        sock = _tl1_connect(sw["host"], sw["port"], sw["user"], sw["pass"])
        cmd = f"ent-patch::{a},{b}:1:;"
        for i in range(1, MAX_TRIES + 1):
            _tl1_rw(sock, cmd)
            time.sleep(READ_PAUSE)
            v = _tl1_send_read(sock, "rtrv-patch:::1:;")
            if f"{a},{b}" in v or f"{b},{a}" in v:
                sock.close()
                return
        sock.close()
        raise RuntimeError("patch not confirmed after retries")
    except RuntimeError:
        raise
    except Exception as e:
        raise ConnectionError(str(e))


def sw_dl_patch(sw, a, b):
    try:
        sock = _tl1_connect(sw["host"], sw["port"], sw["user"], sw["pass"])
        cmd = f"dlt-patch::{a}&{b}:1:;"
        for i in range(1, MAX_TRIES + 1):
            _tl1_rw(sock, cmd)
            time.sleep(READ_PAUSE)
            v = _tl1_send_read(sock, "rtrv-patch:::1:;")
            if f"{a},{b}" not in v and f"{b},{a}" not in v:
                sock.close()
                return
        sock.close()
        raise RuntimeError("patch still present after retries")
    except RuntimeError:
        raise
    except Exception as e:
        raise ConnectionError(str(e))


# --------------------------------------------------------------------------- #
# Background watcher — expires patches for all switches
# --------------------------------------------------------------------------- #
def _watcher():
    while True:
        time.sleep(30)
        now = datetime.utcnow()
        with _timers_lock:
            expired = [
                k for k, v in _timers.items()
                if _parse_iso(v["expires"]) <= now
            ]
        for full_key in expired:
            try:
                switch_id, patch_key = full_key.split(":", 1)
                a, b = map(int, patch_key.split("-"))
                sw = get_switch_cfg(switch_id)
                if sw:
                    sw_dl_patch(sw, a, b)
                with _timers_lock:
                    _timers.pop(full_key, None)
                    _save_timers()
                log.info("watcher: expired patch %s on %s removed", patch_key, switch_id)
            except Exception as e:
                log.warning("watcher: failed to remove %s: %s", full_key, e)


# --------------------------------------------------------------------------- #
# Domain helpers
# --------------------------------------------------------------------------- #
def _parse_iso(s):
    """Parse ISO-8601 datetime string — compatible with Python 3.6."""
    # strip microseconds suffix if present, then parse
    s = s.split(".")[0].replace("T", " ")
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def remaining_seconds(entry):
    if not entry:
        return None
    try:
        expires = _parse_iso(entry["expires"])
    except (KeyError, ValueError):
        return None
    return int((expires - datetime.utcnow()).total_seconds())


def derive_port_status(port, patches, timers):
    if port not in patches:
        return "free"
    key = tkey_short(port, patches[port])
    entry = timers.get(key)
    if not entry:
        return "patched"
    rem = remaining_seconds(entry)
    if rem is None:
        return "patched"
    if rem <= 0:
        return "expired"
    if rem <= EXPIRING_THRESHOLD:
        return "expiring"
    return "patched"


def build_patches(patches, timers):
    seen, out = set(), []
    for port, partner in patches.items():
        key = tkey_short(port, partner)
        if key in seen:
            continue
        seen.add(key)
        entry = timers.get(key)
        out.append({
            "patch_id":          key,
            "port_a":            min(port, partner),
            "port_b":            max(port, partner),
            "label":             (entry or {}).get("label", ""),
            "expires":           (entry or {}).get("expires"),
            "remaining_seconds": remaining_seconds(entry),
        })
    out.sort(key=lambda p: p["port_a"])
    return out


def err(message, code):
    return jsonify({"status": "error", "message": message}), code


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Not authenticated"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def get_active_switch():
    """Return the switch config for the current session, defaulting to first."""
    switches = load_switches()
    sid = session.get("switch_id", switches[0]["id"])
    sw = get_switch_cfg(sid)
    return sw if sw else switches[0]


# --------------------------------------------------------------------------- #
# Flask app
# --------------------------------------------------------------------------- #
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.environ.get("SECRET_KEY", "optical-lab-portal-secret-key")


# ---- Auth ----

@app.get("/login")
def login_page():
    return send_from_directory(app.static_folder, "login.html")


@app.post("/api/login")
def api_login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return err("Username and password are required", 400)
    if not check_credentials(username, password):
        return err("Invalid username or password", 401)
    session["username"] = username
    # default to first switch
    session["switch_id"] = load_switches()[0]["id"]
    log.info("User '%s' logged in", username)
    return jsonify({"status": "ok", "username": username})


@app.post("/api/logout")
def api_logout():
    username = session.pop("username", None)
    session.pop("switch_id", None)
    if username:
        log.info("User '%s' logged out", username)
    return jsonify({"status": "ok"})


@app.get("/api/me")
def api_me():
    if "username" not in session:
        return jsonify({"authenticated": False})
    sw = get_active_switch()
    return jsonify({
        "authenticated": True,
        "username": session["username"],
        "switch_id": sw["id"],
        "switch_label": sw["label"],
    })


# ---- Switch selection ----

@app.get("/api/switches")
@login_required
def api_switches():
    return jsonify({"switches": load_switches()})


@app.post("/api/switches/select")
@login_required
def api_select_switch():
    body = request.get_json(silent=True) or {}
    sid = body.get("switch_id", "")
    if not get_switch_cfg(sid):
        return err(f"Unknown switch: {sid}", 400)
    session["switch_id"] = sid
    sw = get_switch_cfg(sid)
    log.info("User '%s' selected switch %s (%s)", session["username"], sid, sw["host"])
    return jsonify({"status": "ok", "switch_id": sid, "switch_label": sw["label"]})


# ---- Main UI ----

@app.get("/")
@login_required
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---- Polatis API ----

@app.get("/api/ports")
@login_required
def api_ports():
    sw = get_active_switch()
    try:
        patches = sw_get_patches(sw)
    except Exception as e:
        return err(f"Switch unreachable: {e}", 503)
    timers = timers_snapshot(sw["id"])
    ports = [
        {"port": p, "status": derive_port_status(p, patches, timers)}
        for p in range(1, NUM_PORTS + 1)
    ]
    return jsonify({
        "switch_id":    sw["id"],
        "switch_label": sw["label"],
        "ports":        ports,
        "patches":      build_patches(patches, timers),
    })


@app.post("/api/patches")
@login_required
def api_create_patch():
    sw = get_active_switch()
    body = request.get_json(silent=True) or {}
    try:
        port_a   = int(body["port_a"])
        port_b   = int(body["port_b"])
        duration = int(body["duration_minutes"])
    except (KeyError, TypeError, ValueError):
        return err("port_a, port_b and duration_minutes are required integers", 400)

    label = (body.get("label") or "").strip()

    if not (1 <= port_a <= NUM_PORTS) or not (1 <= port_b <= NUM_PORTS):
        return err(f"port numbers must be between 1 and {NUM_PORTS}", 400)
    if port_a == port_b:
        return err("port_a and port_b must differ", 400)
    if not (0 < duration <= MAX_DURATION_MIN):
        return err(f"duration_minutes must be between 1 and {MAX_DURATION_MIN}", 400)
    if len(label) > MAX_LABEL_LEN:
        return err(f"label exceeds {MAX_LABEL_LEN} characters", 400)

    try:
        patches = sw_get_patches(sw)
        if port_a in patches or port_b in patches:
            busy = port_a if port_a in patches else port_b
            return err(f"port {busy} is already in an active patch", 409)
        sw_mk_patch(sw, port_a, port_b)
    except ConnectionError as e:
        return err(f"Switch unreachable: {e}", 503)
    except RuntimeError as e:
        return err(f"Switch refused operation: {e}", 502)

    key     = tkey_short(port_a, port_b)
    expires = (datetime.utcnow() + timedelta(minutes=duration)).isoformat()
    set_timer(sw["id"], key, expires, label)

    append_changelog({
        "action":    "create",
        "switch":    sw["id"],
        "patch_id":  key,
        "port_a":    min(port_a, port_b),
        "port_b":    max(port_a, port_b),
        "label":     label,
        "duration":  duration,
        "expires":   expires,
        "user":      session.get("username", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
    })

    return jsonify({
        "patch_id":         key,
        "port_a":           min(port_a, port_b),
        "port_b":           max(port_a, port_b),
        "label":            label,
        "duration_minutes": duration,
        "expires":          expires,
    }), 201


@app.delete("/api/patches/<patch_id>")
@login_required
def api_delete_patch(patch_id):
    sw = get_active_switch()
    m = re.fullmatch(r"(\d+)-(\d+)", patch_id)
    if not m:
        return err("patch_id must be of the form '<int>-<int>'", 400)
    a, b = int(m.group(1)), int(m.group(2))

    try:
        patches = sw_get_patches(sw)
        if patches.get(a) != b:
            return err(f"patch {patch_id} not found", 404)
        timer_entry = get_timer(sw["id"], patch_id)
        label = (timer_entry or {}).get("label", "")
        sw_dl_patch(sw, a, b)
    except ConnectionError as e:
        return err(f"Switch unreachable: {e}", 503)
    except RuntimeError as e:
        return err(f"Switch refused operation: {e}", 502)

    del_timer(sw["id"], patch_id)

    append_changelog({
        "action":    "remove",
        "switch":    sw["id"],
        "patch_id":  patch_id,
        "port_a":    a,
        "port_b":    b,
        "label":     label,
        "user":      session.get("username", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
    })

    return jsonify({"patch_id": patch_id, "port_a": a, "port_b": b, "label": label})


@app.get("/api/power")
@login_required
def api_power():
    sw = get_active_switch()
    try:
        readings = sw_get_power(sw)
    except Exception as e:
        return err(f"Switch unreachable: {e}", 503)
    out = [{"port": p, "dbm": readings.get(p)} for p in range(1, NUM_PORTS + 1)]
    return jsonify({"readings": out})


@app.get("/api/changelog")
@login_required
def api_changelog():
    entries = _load_changelog()
    return jsonify({"entries": list(reversed(entries))})


# --------------------------------------------------------------------------- #
# T5 / Cisco 400G-XP-LC API
# --------------------------------------------------------------------------- #
import t5_backend as t5b


@app.get("/api/t5/nodes")
@login_required
def api_t5_nodes():
    return jsonify({"nodes": t5b.load_nodes()})


@app.get("/api/t5/discover/<node_id>")
@login_required
def api_t5_discover(node_id):
    try:
        cards = t5b.discover_cards(node_id)
    except t5b.T5Unreachable as e:
        return err(str(e), 503)
    except t5b.T5Error as e:
        return err(str(e), 400)
    return jsonify({"node_id": node_id, "cards": cards})


@app.post("/api/t5/action")
@login_required
def api_t5_action():
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id")
    shelf = body.get("shelf")
    slot = body.get("slot")
    port_num = body.get("port")
    action_key = body.get("action")
    freq = body.get("freq")

    if not all([node_id, shelf is not None, slot is not None, port_num is not None, action_key]):
        return err("node_id, shelf, slot, port, and action are required", 400)

    try:
        ok, message = t5b.execute_action(node_id, int(shelf), int(slot), int(port_num), action_key, freq)
    except t5b.T5Unreachable as e:
        return err(str(e), 503)
    except t5b.T5Error as e:
        return err(str(e), 400)

    append_changelog({
        "action":    "t5_" + action_key,
        "switch":    node_id,
        "patch_id":  "SLOT-{}-{} port {}".format(shelf, slot, port_num),
        "port_a":    port_num,
        "port_b":    0,
        "label":     action_key + (" FREQ=" + freq if freq else ""),
        "user":      session.get("username", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
    })

    return jsonify({"ok": ok, "message": message})


@app.post("/api/t5/guided/plan")
@login_required
def api_t5_guided_plan():
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id")
    shelf = body.get("shelf")
    slot = body.get("slot")
    client_port = body.get("client_port")
    freq = body.get("freq")

    if not all([node_id, shelf is not None, slot is not None, client_port is not None]):
        return err("node_id, shelf, slot, and client_port are required", 400)

    try:
        plan = t5b.guided_build_plan(node_id, int(shelf), int(slot), int(client_port), freq)
    except t5b.T5Unreachable as e:
        return err(str(e), 503)
    except t5b.T5Error as e:
        return err(str(e), 400)

    return jsonify(plan)


@app.post("/api/t5/guided/execute")
@login_required
def api_t5_guided_execute():
    body = request.get_json(silent=True) or {}
    node_id = body.get("node_id")
    shelf = body.get("shelf")
    slot = body.get("slot")
    client_port = body.get("client_port")
    freq = body.get("freq")

    if not all([node_id, shelf is not None, slot is not None, client_port is not None]):
        return err("node_id, shelf, slot, and client_port are required", 400)

    try:
        results = t5b.guided_build_execute(node_id, int(shelf), int(slot), int(client_port), freq)
    except t5b.T5Unreachable as e:
        return err(str(e), 503)
    except t5b.T5Error as e:
        return err(str(e), 400)

    # log the guided build
    all_ok = all(r["ok"] for r in results)
    append_changelog({
        "action":    "t5_guided_build",
        "switch":    node_id,
        "patch_id":  "SLOT-{}-{} client {}".format(shelf, slot, client_port),
        "port_a":    client_port,
        "port_b":    0,
        "label":     "guided build ({})".format("OK" if all_ok else "PARTIAL"),
        "user":      session.get("username", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
    })

    return jsonify({"results": results, "all_ok": all_ok})


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    _load_timers()
    threading.Thread(target=_watcher, daemon=True, name="patch-watcher").start()
    log.info("Optical Lab Portal starting on 0.0.0.0:%s", SERVER_PORT)
    app.run(host="0.0.0.0", port=SERVER_PORT)


if __name__ == "__main__":
    main()
