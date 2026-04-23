"""
dashboard/server.py - Full interactive server with terminal streaming + command control
"""
import json, os, sys, subprocess, threading, queue, time
from datetime import datetime
from flask import Flask, jsonify, request, Response, send_from_directory

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(THIS_DIR)
sys.path.insert(0, ROOT_DIR)
os.chdir(ROOT_DIR)

from config.settings import (
    BATTLE_LOG, FORENSIC_REPORT, DASHBOARD_PORT,
    ATTACK_ACTIONS, DEFEND_ACTIONS
)

app = Flask(__name__, static_folder=THIS_DIR)

# Allow CORS manually
@app.after_request
def add_cors(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return r

_state = {
    "training_process": None,
    "is_running": False,
    "terminal_lines": [],
    "episodes": 300,
    "security_level": "low",
}
_subscribers = []
_lock = threading.Lock()

def _broadcast(entry):
    dead = []
    for q in _subscribers:
        try:
            q.put_nowait(entry)
        except:
            dead.append(q)
    for q in dead:
        try: _subscribers.remove(q)
        except: pass

def _capture_output(proc):
    for raw in iter(proc.stdout.readline, b''):
        try:
            line = raw.decode('utf-8', errors='replace').rstrip()
        except:
            line = str(raw)
        ts = datetime.now().strftime("%H:%M:%S")
        entry = {"ts": ts, "line": line}
        with _lock:
            _state["terminal_lines"].append(entry)
            if len(_state["terminal_lines"]) > 3000:
                _state["terminal_lines"] = _state["terminal_lines"][-2000:]
        _broadcast(entry)
    with _lock:
        _state["is_running"] = False
        _state["training_process"] = None
    _broadcast({"ts": datetime.now().strftime("%H:%M:%S"), "line": "─── Training ended ───"})

@app.route("/")
def index():
    return send_from_directory(THIS_DIR, "index.html")

@app.route("/api/status")
def api_status():
    with _lock:
        return jsonify({
            "is_running": _state["is_running"],
            "episodes": _state["episodes"],
            "security_level": _state["security_level"],
            "attack_actions": ATTACK_ACTIONS,
            "defend_actions": DEFEND_ACTIONS,
        })

@app.route("/api/terminal")
def api_terminal():
    n = int(request.args.get("n", 300))
    with _lock:
        return jsonify(_state["terminal_lines"][-n:])

@app.route("/api/terminal/stream")
def api_terminal_stream():
    def generate():
        with _lock:
            existing = list(_state["terminal_lines"][-100:])
        for e in existing:
            yield f"data: {json.dumps(e)}\n\n"
        q = queue.Queue()
        with _lock:
            _subscribers.append(q)
        try:
            while True:
                try:
                    item = q.get(timeout=15)
                    yield f"data: {json.dumps(item)}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        finally:
            try:
                with _lock:
                    _subscribers.remove(q)
            except:
                pass
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

@app.route("/api/train/start", methods=["POST","OPTIONS"])
def api_train_start():
    if request.method == "OPTIONS": return jsonify({"ok":True})
    body = request.json or {}
    episodes = int(body.get("episodes", 300))
    quiet    = bool(body.get("quiet", False))
    resume   = bool(body.get("resume", False))
    sec      = body.get("security_level", "low")
    with _lock:
        if _state["is_running"]:
            return jsonify({"ok": False, "error": "Training already running"})
    _update_env("DVWA_SECURITY_LEVEL", sec)
    cmd = [sys.executable, "train.py", f"--episodes={episodes}"]
    if quiet:  cmd.append("--quiet")
    if resume: cmd.append("--resume")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=ROOT_DIR, bufsize=1)
        with _lock:
            _state["training_process"] = proc
            _state["is_running"]       = True
            _state["episodes"]         = episodes
            _state["security_level"]   = sec
            _state["terminal_lines"]   = []
        threading.Thread(target=_capture_output, args=(proc,), daemon=True).start()
        return jsonify({"ok": True, "pid": proc.pid})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/train/stop", methods=["POST","OPTIONS"])
def api_train_stop():
    if request.method == "OPTIONS": return jsonify({"ok":True})
    with _lock:
        proc = _state["training_process"]
        if not proc:
            return jsonify({"ok": False, "error": "Not running"})
        try:
            proc.terminate()
            _state["is_running"] = False
            _state["training_process"] = None
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True})

@app.route("/api/attack", methods=["POST","OPTIONS"])
def api_attack():
    if request.method == "OPTIONS": return jsonify({"ok":True})
    body = request.json or {}
    action = body.get("action", "sqli_union")
    if action not in ATTACK_ACTIONS:
        return jsonify({"ok": False, "error": f"Unknown: {action}"})
    try:
        from environment.dvwa_session   import DVWASession
        from environment.attack_modules import execute_attack
        session = DVWASession()
        if not session.connect(retries=3, delay=1.0):
            return jsonify({"ok": False, "error": "Cannot connect to DVWA"})
        result = execute_attack(action, session)
        msg = f"[MANUAL ATK] {action} → {'BREACH' if result.success else 'FAILED'} | {result.evidence[:80]}"
        entry = {"ts": datetime.now().strftime("%H:%M:%S"), "line": msg}
        with _lock:
            _state["terminal_lines"].append(entry)
        _broadcast(entry)
        return jsonify({"ok":True,"action":result.action,"success":result.success,
                        "payload":result.payload,"evidence":result.evidence,
                        "response_code":result.response_code,"duration_ms":result.duration_ms})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/defend", methods=["POST","OPTIONS"])
def api_defend():
    if request.method == "OPTIONS": return jsonify({"ok":True})
    body = request.json or {}
    action = body.get("action", "alert_only")
    if action not in DEFEND_ACTIONS:
        return jsonify({"ok": False, "error": f"Unknown: {action}"})
    try:
        from environment.defend_modules import execute_defense
        result = execute_defense(action, {
            "payload": body.get("payload","test"),
            "attack_action": body.get("attack_action","unknown"),
            "state": {}, "session": None,
        })
        msg = f"[MANUAL DEF] {action} → {'BLOCKED' if result.would_block else 'LOGGED'} | {result.details[:80]}"
        entry = {"ts": datetime.now().strftime("%H:%M:%S"), "line": msg}
        with _lock:
            _state["terminal_lines"].append(entry)
        _broadcast(entry)
        return jsonify({"ok":True,"action":result.action,"would_block":result.would_block,
                        "method":result.method,"details":result.details,"duration_ms":result.duration_ms})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/events")
def api_events():
    events = []
    try:
        log_path = os.path.join(ROOT_DIR, BATTLE_LOG)
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-300:]:
            line = line.strip()
            if line:
                try: events.append(json.loads(line))
                except: pass
    except FileNotFoundError:
        pass
    return jsonify(events)

@app.route("/api/report")
def api_report():
    try:
        rep_path = os.path.join(ROOT_DIR, FORENSIC_REPORT)
        with open(rep_path, encoding="utf-8") as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({"error": "No report yet"})

@app.route("/api/settings", methods=["POST","OPTIONS"])
def api_settings():
    if request.method == "OPTIONS": return jsonify({"ok":True})
    body = request.json or {}
    allowed = {"DVWA_URL","DVWA_USERNAME","DVWA_PASSWORD","DVWA_SECURITY_LEVEL",
               "MAX_EPISODES","MAX_STEPS_PER_EPISODE","LEARNING_RATE","EPSILON_START"}
    updated = {}
    for k,v in body.items():
        if k in allowed:
            _update_env(k, str(v))
            updated[k] = v
    return jsonify({"ok": True, "updated": updated})

def _update_env(key, value):
    env_path = os.path.join(ROOT_DIR, ".env")
    try:
        lines = []
        if os.path.exists(env_path):
            with open(env_path) as f:
                lines = f.readlines()
        new_lines, found = [], False
        for line in lines:
            if line.startswith(f"{key}="):
                new_lines.append(f"{key}={value}\n"); found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"{key}={value}\n")
        with open(env_path, "w") as f:
            f.writelines(new_lines)
    except Exception as e:
        print(f"[server] .env update failed: {e}")

if __name__ == "__main__":
    print(f"\n[Dashboard] Root : {ROOT_DIR}")
    print(f"[Dashboard] URL  : http://localhost:{DASHBOARD_PORT}\n")
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, threaded=True)
