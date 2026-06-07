import atexit
import getopt
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template_string


def usage():
    print("usage:", sys.argv[0])
    print("options:")
    print("-h: display this help screen")
    print("-i <interface>: set interface. Default: Wi-Fi")
    print("-p <port>: set web UI port. Default: 8080")
    print("--host <host>: set web UI host. Default: 127.0.0.1")
    print("--auto-start: start protection mode immediately")
    print("--no-auto-start: open UI without starting protection mode")
    print("--no-browser: do not open the browser automatically")


try:
    opts, args = getopt.getopt(
        sys.argv[1:],
        "hi:p:",
        ["host=", "auto-start", "no-auto-start", "no-browser"],
    )
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(2)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INTERFACE = "Wi-Fi"
WEB_HOST = "127.0.0.1"
WEB_PORT = 8080
AUTO_START = False
OPEN_BROWSER = True

for option, argument in opts:
    if option == "-h":
        usage()
        sys.exit()
    if option == "-i":
        INTERFACE = argument
    elif option == "-p":
        WEB_PORT = int(argument)
    elif option == "--host":
        WEB_HOST = argument
    elif option == "--auto-start":
        AUTO_START = True
    elif option == "--no-auto-start":
        AUTO_START = False
    elif option == "--no-browser":
        OPEN_BROWSER = False
    else:
        assert False, "unhandled option"


IP = "127.0.0.1"
DETECTION_PORT = 5003
PIPELINE_UDP_PORTS = [5001, 5002]

PIPELINE = [
    {
        "key": "preprocessor",
        "label": "전처리",
        "script": "Preprocessor.py",
        "args": [],
        "log": "preprocessor.log",
    },
    {
        "key": "detector",
        "label": "SVM 탐지",
        "script": "SVM_deploy.py",
        "args": [],
        "log": "detector.log",
    },
    {
        "key": "capture",
        "label": "패킷 수집",
        "script": "PacketCapture.py",
        "args": ["-i", INTERFACE],
        "log": "capturer.log",
    },
]

app = Flask(__name__)

state_lock = threading.RLock()
listener_stop = threading.Event()
listener_thread = None
listener_socket = None

runtime = {
    "processes": {},
    "log_files": {},
    "started_at": None,
    "last_token": None,
    "last_seen": None,
    "normal_count": 0,
    "attack_count": 0,
    "total_count": 0,
    "events": deque(maxlen=30),
    "listener_error": None,
    "last_error": None,
}


def subprocess_kwargs(log_file):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    kwargs = {
        "stdout": log_file,
        "stderr": log_file,
        "stdin": subprocess.DEVNULL,
        "env": env,
        "cwd": BASE_DIR,
    }

    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["preexec_fn"] = os.setsid

    return kwargs


def stop_process(process):
    if process is None or process.poll() is not None:
        return

    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except Exception:
        process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def reset_detection_state():
    runtime["started_at"] = datetime.now()
    runtime["last_token"] = None
    runtime["last_seen"] = None
    runtime["normal_count"] = 0
    runtime["attack_count"] = 0
    runtime["total_count"] = 0
    runtime["events"].clear()
    runtime["last_error"] = None


def start_udp_listener():
    global listener_socket, listener_thread

    if listener_thread is not None and listener_thread.is_alive():
        return True

    try:
        input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        input_sock.bind((IP, DETECTION_PORT))
        input_sock.settimeout(0.5)
    except OSError as exc:
        with state_lock:
            runtime["listener_error"] = str(exc)
        return False

    listener_stop.clear()
    listener_socket = input_sock
    listener_thread = threading.Thread(target=udp_listener, args=(input_sock,), daemon=True)
    listener_thread.start()
    with state_lock:
        runtime["listener_error"] = None
    return True


def udp_listener(input_sock):
    with input_sock:
        while not listener_stop.is_set():
            try:
                data, addr = input_sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError as exc:
                if listener_stop.is_set():
                    break
                with state_lock:
                    runtime["listener_error"] = str(exc)
                break

            token = data.decode("utf-8", errors="replace").strip()
            record_detection(token, addr)


def stop_udp_listener():
    global listener_socket, listener_thread

    listener_stop.set()
    if listener_socket is not None:
        try:
            listener_socket.close()
        except OSError:
            pass

    if listener_thread is not None and listener_thread.is_alive():
        listener_thread.join(timeout=1)

    listener_socket = None
    listener_thread = None
    with state_lock:
        runtime["listener_error"] = None


def all_tracked_pipeline_running():
    return all(is_process_alive(runtime["processes"].get(item["key"])) for item in PIPELINE)


def cleanup_orphan_pipeline_processes():
    if os.name != "nt":
        return

    def ps_quote(value):
        return "'" + value.replace("'", "''") + "'"

    scripts = ", ".join(ps_quote(item["script"]) for item in PIPELINE)
    ports = ", ".join(str(port) for port in PIPELINE_UDP_PORTS)
    command = f"""
$base = {ps_quote(BASE_DIR)}
$scripts = @({scripts})
$ports = @({ports})
$pidToSkip = {os.getpid()}
$scriptPids = Get-CimInstance Win32_Process | Where-Object {{
  $cmd = $_.CommandLine
  $scriptMatched = $false
  if ($cmd -and $_.ProcessId -ne $pidToSkip) {{
    foreach ($script in $scripts) {{
      if ($cmd.Contains($script)) {{
        $scriptMatched = $true
        break
      }}
    }}
  }}
  $scriptMatched
}} | Select-Object -ExpandProperty ProcessId

$portPids = Get-NetUDPEndpoint -LocalPort $ports -ErrorAction SilentlyContinue |
  Where-Object {{ $_.OwningProcess -ne $pidToSkip }} |
  Select-Object -ExpandProperty OwningProcess

@($scriptPids + $portPids) | Sort-Object -Unique | ForEach-Object {{
  Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
}}
"""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
        )
    except Exception:
        pass


def read_latest_feature_snapshot():
    log_path = os.path.join(BASE_DIR, "preprocessor.log")
    try:
        with open(log_path, "rb") as log_file:
            log_file.seek(0, os.SEEK_END)
            size = log_file.tell()
            log_file.seek(max(0, size - 65536))
            text = log_file.read().replace(b"\x00", b"").decode("utf-8", errors="replace")
    except Exception:
        return None

    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{") or not line.endswith("}"):
            continue
        try:
            snapshot = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(snapshot, dict):
            return snapshot
    return None


def number_or_none(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def status_text(status):
    if status == "normal":
        return "정상"
    if status == "caution":
        return "주의"
    if status == "risk":
        return "위험"
    return "확인"


def build_detection_detail(token, features):
    features = features or {}
    rssi = number_or_none(features.get("RSSI"))
    rtt = number_or_none(features.get("RTT"))
    new_bssid = bool(features.get("new_BSSID"))

    rows = []
    if rssi is None:
        rows.append(
            {
                "title": "RSSI 확인 필요",
                "status": "unknown",
                "label": status_text("unknown"),
            }
        )
    elif rssi >= -70:
        rows.append(
            {
                "title": "RSSI 정상",
                "status": "normal",
                "label": status_text("normal"),
            }
        )
    elif rssi >= -80:
        rows.append(
            {
                "title": "RSSI 주의",
                "status": "caution",
                "label": status_text("caution"),
            }
        )
    else:
        rows.append(
            {
                "title": "RSSI 위험",
                "status": "risk",
                "label": status_text("risk"),
            }
        )

    if rtt is None:
        rows.append(
            {
                "title": "RTT 확인 필요",
                "status": "unknown",
                "label": status_text("unknown"),
            }
        )
    elif rtt < 0:
        rows.append(
            {
                "title": "RTT 정상",
                "status": "normal",
                "label": status_text("normal"),
            }
        )
    elif rtt <= 0.1:
        rows.append(
            {
                "title": "RTT 정상",
                "status": "normal",
                "label": status_text("normal"),
            }
        )
    elif rtt <= 0.3:
        rows.append(
            {
                "title": "RTT 주의",
                "status": "caution",
                "label": status_text("caution"),
            }
        )
    else:
        rows.append(
            {
                "title": "RTT 위험",
                "status": "risk",
                "label": status_text("risk"),
            }
        )

    rows.append(
        {
            "title": "BSSID 위험" if new_bssid else "BSSID 정상",
            "status": "risk" if new_bssid else "normal",
            "label": status_text("risk" if new_bssid else "normal"),
        }
    )

    if token == "1":
        ai_status = "normal"
        ai_title = "AI 분석 정상"
        summary = "최근 판단 결과입니다."
    elif token == "0":
        ai_status = "risk"
        ai_title = "AI 분석 위험"
        summary = "최근 판단 결과입니다."
    else:
        ai_status = "unknown"
        ai_title = "AI 분석 확인 필요"
        summary = "최근 판단 결과입니다."

    rows.append(
        {
            "title": ai_title,
            "status": ai_status,
            "label": status_text(ai_status),
        }
    )

    return {
        "summary": summary,
        "rows": rows,
    }


def record_detection(token, addr):
    now = datetime.now()
    features = read_latest_feature_snapshot()
    detail = build_detection_detail(token, features)

    if token == "1":
        status = "normal"
        title = "NORMAL"
        message = "정상 네트워크 패턴입니다."
    elif token == "0":
        status = "attack"
        title = "HIGH RISK"
        message = "Evil Twin 의심 신호가 감지되었습니다."
    else:
        status = "unknown"
        title = "UNKNOWN"
        message = f"알 수 없는 결과 토큰: {token}"

    with state_lock:
        if runtime["started_at"] is None or not all_tracked_pipeline_running():
            return

        runtime["last_token"] = token
        runtime["last_seen"] = now

        if status == "normal":
            runtime["normal_count"] += 1
            runtime["total_count"] += 1
        elif status == "attack":
            runtime["attack_count"] += 1
            runtime["total_count"] += 1

        runtime["events"].appendleft(
            {
                "time": now.strftime("%H:%M:%S"),
                "status": status,
                "title": title,
                "message": message,
                "token": token,
                "source": f"{addr[0]}:{addr[1]}",
                "detail": detail,
            }
        )


def start_pipeline():
    with state_lock:
        alive_count = sum(1 for item in PIPELINE if is_process_alive(runtime["processes"].get(item["key"])))
        if alive_count == len(PIPELINE):
            return True, "already running"

        stale_processes = list(runtime["processes"].values())
        stale_log_files = list(runtime["log_files"].values())
        runtime["processes"] = {}
        runtime["log_files"] = {}
        runtime["started_at"] = None
        reset_detection_state()

    for process in stale_processes:
        stop_process(process)
    for log_file in stale_log_files:
        try:
            log_file.close()
        except Exception:
            pass

    stop_udp_listener()
    cleanup_orphan_pipeline_processes()

    if not start_udp_listener():
        return False, runtime["listener_error"] or "failed to bind UDP listener"

    started = []
    opened_logs = []
    try:
        python_cmd = sys.executable
        for item in PIPELINE:
            log_path = os.path.join(BASE_DIR, item["log"])
            log_file = open(log_path, "w", encoding="utf-8")
            opened_logs.append(log_file)

            command = [python_cmd, "-u", item["script"], *item["args"]]
            process = subprocess.Popen(command, **subprocess_kwargs(log_file))
            started.append((item, process, log_file))

            with state_lock:
                runtime["processes"][item["key"]] = process
                runtime["log_files"][item["key"]] = log_file

            time.sleep(0.15)
    except Exception as exc:
        for _, process, _ in started:
            stop_process(process)
        for log_file in opened_logs:
            try:
                log_file.close()
            except Exception:
                pass

        with state_lock:
            runtime["last_error"] = str(exc)
            runtime["processes"] = {}
            runtime["log_files"] = {}
            runtime["started_at"] = None
        stop_udp_listener()
        return False, str(exc)

    time.sleep(0.8)
    failed = [item["script"] for item, process, _ in started if process.poll() is not None]
    if failed:
        for _, process, _ in started:
            stop_process(process)
        for log_file in opened_logs:
            try:
                log_file.close()
            except Exception:
                pass

        message = "Pipeline process exited early: " + ", ".join(failed)
        with state_lock:
            runtime["last_error"] = message
            runtime["processes"] = {}
            runtime["log_files"] = {}
            runtime["started_at"] = None
        stop_udp_listener()
        cleanup_orphan_pipeline_processes()
        return False, message

    return True, "started"


def stop_pipeline():
    with state_lock:
        processes = list(runtime["processes"].values())
        log_files = list(runtime["log_files"].values())
        runtime["processes"] = {}
        runtime["log_files"] = {}
        runtime["started_at"] = None

    for process in processes:
        stop_process(process)
    for log_file in log_files:
        try:
            log_file.close()
        except Exception:
            pass

    stop_udp_listener()
    cleanup_orphan_pipeline_processes()
    return True, "stopped"


def shutdown():
    stop_pipeline()
    stop_udp_listener()


def is_process_alive(process):
    return process is not None and process.poll() is None


def process_state(process):
    if process is None:
        return "stopped"
    if process.poll() is None:
        return "running"
    return "exited"


def format_uptime(started_at):
    if started_at is None:
        return "00:00"

    seconds = max(0, int((datetime.now() - started_at).total_seconds()))
    minutes, sec = divmod(seconds, 60)
    hours, minute = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minute:02d}:{sec:02d}"
    return f"{minute:02d}:{sec:02d}"


def build_status():
    with state_lock:
        process_items = []
        alive_count = 0
        exited_count = 0

        for item in PIPELINE:
            process = runtime["processes"].get(item["key"])
            state = process_state(process)
            if state == "running":
                alive_count += 1
            elif state == "exited":
                exited_count += 1

            process_items.append(
                {
                    "key": item["key"],
                    "label": item["label"],
                    "state": state,
                    "pid": process.pid if process is not None else None,
                    "log": item["log"],
                }
            )

        if alive_count == len(PIPELINE):
            mode = "running"
        elif alive_count > 0:
            mode = "degraded"
        else:
            mode = "stopped"

        last_token = runtime["last_token"]
        if mode == "stopped":
            verdict = "idle"
            verdict_label = "대기"
            verdict_message = "보호 시작을 누르세요"
        elif mode != "running":
            verdict = "loading"
            verdict_label = "측정 중"
            verdict_message = "탐지 모듈을 다시 준비하는 중입니다."
        elif last_token == "1":
            verdict = "normal"
            verdict_label = "정상"
            verdict_message = "현재 수신된 최신 결과는 정상입니다."
        elif last_token == "0":
            verdict = "attack"
            verdict_label = "위험"
            verdict_message = "공격 또는 고위험 신호가 감지되었습니다."
        else:
            verdict = "loading"
            verdict_label = "측정 중"
            verdict_message = "모델 결과를 기다리는 중입니다."

        events = list(runtime["events"])
        started_at = runtime["started_at"]
        last_seen = runtime["last_seen"]

        analysis_states = [process_items[0]["state"], process_items[1]["state"]]
        if any(state == "exited" for state in analysis_states):
            analysis_state = "exited"
        elif any(state == "running" for state in analysis_states):
            analysis_state = "running"
        else:
            analysis_state = "stopped"

        steps = [
            {
                "number": 1,
                "title": "패킷 수집",
                "state": process_items[2]["state"],
            },
            {
                "number": 2,
                "title": "분석",
                "state": analysis_state,
            },
            {
                "number": 3,
                "title": "결과 수신",
                "state": verdict,
            },
        ]

        return {
            "mode": mode,
            "alive_count": alive_count,
            "exited_count": exited_count,
            "interface": INTERFACE,
            "detection_port": DETECTION_PORT,
            "uptime": format_uptime(started_at),
            "last_seen": last_seen.strftime("%H:%M:%S") if last_seen else "-",
            "verdict": verdict,
            "verdict_label": verdict_label,
            "verdict_message": verdict_message,
            "normal_count": runtime["normal_count"],
            "attack_count": runtime["attack_count"],
            "total_count": runtime["total_count"],
            "events": events,
            "processes": process_items,
            "steps": steps,
            "listener_error": runtime["listener_error"],
            "last_error": runtime["last_error"],
        }


def find_available_port(host, preferred_port):
    bind_host = "" if host == "0.0.0.0" else host
    for candidate in range(preferred_port, preferred_port + 20):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_sock:
                test_sock.bind((bind_host, candidate))
                return candidate
        except OSError:
            continue
    return preferred_port


def open_browser_later(url):
    if not OPEN_BROWSER:
        return

    def open_url():
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Timer(1.0, open_url).start()


@app.route("/")
def index():
    return render_template_string(
        INDEX_HTML,
        interface=INTERFACE,
        detection_port=DETECTION_PORT,
        web_host=WEB_HOST,
        web_port=WEB_PORT,
    )


@app.route("/api/status")
def api_status():
    return jsonify(build_status())


@app.route("/api/start", methods=["POST"])
def api_start():
    ok, message = start_pipeline()
    response = build_status()
    response["ok"] = ok
    response["message"] = message
    return jsonify(response), 200 if ok else 500


@app.route("/api/stop", methods=["POST"])
def api_stop():
    ok, message = stop_pipeline()
    response = build_status()
    response["ok"] = ok
    response["message"] = message
    return jsonify(response)


@app.route("/api/restart", methods=["POST"])
def api_restart():
    stop_pipeline()
    ok, message = start_pipeline()
    response = build_status()
    response["ok"] = ok
    response["message"] = message
    return jsonify(response), 200 if ok else 500


INDEX_HTML = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TwinGuard</title>
  <style>
    :root {
      --blue-50: #edf6ff;
      --blue-100: #d8ecff;
      --blue-500: #3182f6;
      --blue-600: #1b64da;
      --green-50: #e9f9f0;
      --green-500: #00b875;
      --red-50: #fff0f0;
      --red-500: #f04452;
      --yellow-50: #fff8e6;
      --yellow-500: #f59f00;
      --gray-50: #f7f8fa;
      --gray-100: #f2f4f6;
      --gray-200: #e5e8eb;
      --gray-300: #d1d6db;
      --gray-500: #8b95a1;
      --gray-700: #4e5968;
      --gray-900: #191f28;
      --white: #ffffff;
      --shadow: 0 16px 40px rgba(25, 31, 40, 0.08);
    }

    * {
      box-sizing: border-box;
    }

    html {
      min-height: 100%;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background-color: #f6f9fc;
      background-image:
        linear-gradient(rgba(49, 130, 246, 0.07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(49, 130, 246, 0.07) 1px, transparent 1px);
      background-size: 28px 28px;
      color: var(--gray-900);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }

    body {
      display: flex;
      flex-direction: column;
    }
    body.dark-theme {
      --blue-50: #102846;
      --blue-100: #17375f;
      --blue-500: #5b9dff;
      --blue-600: #86b8ff;
      --green-50: #0d3024;
      --green-500: #21d18f;
      --red-50: #3a171d;
      --red-500: #ff6b7a;
      --yellow-50: #34270f;
      --yellow-500: #ffbd38;
      --gray-50: #161b22;
      --gray-100: #1f2630;
      --gray-200: #303946;
      --gray-300: #465160;
      --gray-500: #9aa6b2;
      --gray-700: #c7d0da;
      --gray-900: #f4f7fb;
      --white: #ffffff;
      --shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
      background-color: #0f141b;
      background-image:
        linear-gradient(rgba(91, 157, 255, 0.08) 1px, transparent 1px),
        linear-gradient(90deg, rgba(91, 157, 255, 0.08) 1px, transparent 1px);
      color-scheme: dark;
    }

    body.dark-theme .panel,
    body.dark-theme .metric,
    body.dark-theme .history-row {
      background: rgba(22, 27, 34, 0.94);
      border-color: rgba(70, 81, 96, 0.82);
    }

    body.dark-theme .panel:hover,
    body.dark-theme .metric:hover,
    body.dark-theme .history-row:hover {
      border-color: rgba(91, 157, 255, 0.38);
      box-shadow: 0 18px 44px rgba(0, 0, 0, 0.28);
    }

    body.dark-theme .signal-visual {
      background: linear-gradient(180deg, rgba(16, 40, 70, 0.72), rgba(22, 27, 34, 0.88));
      border-color: rgba(91, 157, 255, 0.24);
    }

    body.dark-theme .step-badge {
      background: #151b24;
      border-color: var(--gray-200);
    }

    body.dark-theme .empty-state,
    body.dark-theme .detail-card,
    body.dark-theme .guide-button-card,
    body.dark-theme .guide-link-card,
    body.dark-theme .guide-mini-history,
    body.dark-theme .guide-mini-metric,
    body.dark-theme .guide-mini-theme-menu,
    body.dark-theme .guide-mini-theme-toggle,
    body.dark-theme .guide-process-item,
    body.dark-theme .guide-result-card,
    body.dark-theme .guide-screen-card,
    body.dark-theme .guide-shield-stage,
    body.dark-theme .guide-status-row,
    body.dark-theme .guide-status-preview,
    body.dark-theme .guide-step-row {
      background: rgba(31, 38, 48, 0.86);
      border-color: var(--gray-200);
    }

    body.dark-theme .guide-dialog,
    body.dark-theme .server-result-box {
      background: #151b24;
    }


    button {
      font: inherit;
    }

    .page {
      width: min(1180px, calc(100% - 40px));
      margin: 0 auto;
      padding: 34px 0 42px;
      flex: 1 0 auto;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      margin-bottom: 24px;
    }

    .top-menu-button {
      height: 36px;
      padding: 0 14px;
      border: 0;
      border-radius: 8px;
      background: transparent;
      color: var(--gray-700);
      cursor: pointer;
      font-size: 14px;
      font-weight: 800;
      transition: background 120ms ease, color 120ms ease;
    }

    .top-menu-button:hover,
    .top-menu-button:focus-visible {
      background: var(--blue-50);
      color: var(--blue-600);
      outline: none;
    }

    .top-actions {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      flex: 0 0 auto;
    }

    .theme-menu {
      position: relative;
      display: inline-flex;
    }

    .theme-toggle {
      height: 36px;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 0 12px;
      border: 1px solid rgba(229, 232, 235, 0.88);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      color: var(--gray-700);
      cursor: pointer;
      font-size: 13px;
      font-weight: 800;
      box-shadow: var(--shadow);
      transition: background 160ms ease, border-color 160ms ease, color 160ms ease, transform 120ms ease;
    }

    .theme-toggle:hover,
    .theme-toggle:focus-visible {
      background: var(--blue-50);
      border-color: var(--blue-100);
      color: var(--blue-600);
      outline: none;
    }

    .theme-toggle:active {
      transform: scale(0.98);
    }

    body.dark-theme .theme-toggle {
      background: rgba(22, 27, 34, 0.94);
      border-color: rgba(70, 81, 96, 0.82);
    }

    .theme-icon {
      width: 16px;
      text-align: center;
      line-height: 1;
    }

    .theme-panel {
      position: absolute;
      right: 0;
      top: calc(100% + 8px);
      z-index: 30;
      width: 154px;
      display: grid;
      gap: 4px;
      padding: 6px;
      border: 1px solid rgba(229, 232, 235, 0.88);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.98);
      box-shadow: var(--shadow);
      opacity: 0;
      visibility: hidden;
      pointer-events: none;
      transform: translateY(-4px);
      transition: opacity 140ms ease, transform 140ms ease, visibility 140ms ease;
    }

    .theme-menu.open .theme-panel {
      opacity: 1;
      visibility: visible;
      pointer-events: auto;
      transform: translateY(0);
    }

    .theme-option {
      height: 36px;
      padding: 0 10px;
      border: 0;
      border-radius: 8px;
      background: transparent;
      color: var(--gray-700);
      cursor: pointer;
      text-align: left;
      font-size: 13px;
      font-weight: 800;
    }

    .theme-option:hover,
    .theme-option:focus-visible,
    .theme-option.active {
      background: var(--blue-50);
      color: var(--blue-600);
      outline: none;
    }

    body.dark-theme .theme-panel {
      background: rgba(22, 27, 34, 0.98);
      border-color: rgba(70, 81, 96, 0.82);
    }

    .brand-title-row .top-menu-button {
      height: 28px;
      padding: 0 10px;
      font-size: 13px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .brand-mark {
      width: 42px;
      height: 42px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      background: var(--blue-500);
      color: var(--white);
      box-shadow: 0 10px 24px rgba(49, 130, 246, 0.24);
      flex: 0 0 auto;
    }

    .brand-mark svg {
      width: 23px;
      height: 23px;
    }

    .brand h1 {
      margin: 0;
      font-size: 24px;
      line-height: 1.25;
      font-weight: 800;
    }

    .brand-title-row {
      position: relative;
      display: flex;
      align-items: center;
      gap: 7px;
    }

    .brand p {
      margin: 3px 0 0;
      color: var(--gray-500);
      font-size: 14px;
      line-height: 1.4;
    }

    .mode-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      height: 34px;
      padding: 0 12px;
      border: 1px solid rgba(229, 232, 235, 0.88);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.9);
      color: var(--gray-700);
      font-size: 13px;
      font-weight: 700;
      box-shadow: var(--shadow);
      white-space: nowrap;
    }

    .mode-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--gray-300);
    }

    .mode-pill.running .mode-dot {
      background: var(--green-500);
    }

    .mode-pill.degraded .mode-dot {
      background: var(--yellow-500);
    }

    body.dark-theme .mode-pill {
      background: rgba(22, 27, 34, 0.94);
      border-color: rgba(70, 81, 96, 0.82);
      color: var(--gray-700);
    }

    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1.65fr) minmax(300px, 0.75fr);
      gap: 18px;
      align-items: start;
    }

    .panel,
    .metric,
    .history-row {
      background: rgba(255, 255, 255, 0.92);
      border: 1px solid rgba(229, 232, 235, 0.88);
      border-radius: 8px;
      box-shadow: var(--shadow);
      transition: transform 220ms ease, box-shadow 220ms ease, border-color 220ms ease, background 220ms ease;
    }

    .panel:hover,
    .metric:hover,
    .history-row:hover {
      border-color: rgba(209, 226, 255, 0.92);
      box-shadow: 0 18px 44px rgba(25, 31, 40, 0.08);
    }

    .panel {
      padding: 24px;
    }

    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 220px;
      gap: 22px;
      align-items: center;
      min-height: 296px;
    }

    .hero-status-bar {
      grid-column: 1 / -1;
      display: grid;
      gap: 10px;
      margin: -6px 0 2px;
    }

    .hero-status-label {
      margin: 0;
      color: var(--gray-500);
      font-size: 12px;
      font-weight: 800;
      line-height: 1.3;
    }

    .hero-status-track {
      height: 5px;
      border-radius: 999px;
      background: var(--gray-100);
      overflow: hidden;
    }

    .hero-status-fill {
      display: block;
      width: 100%;
      height: 100%;
      border-radius: inherit;
      background: var(--gray-300);
      opacity: 0.45;
      animation: statusFade 1.8s ease-in-out infinite;
      transition: background 220ms ease;
    }

    .hero-status-fill.running,
    .hero-status-fill.normal {
      background: var(--green-500);
    }

    .hero-status-fill.degraded,
    .hero-status-fill.loading {
      background: var(--yellow-500);
    }

    .hero-status-fill.attack {
      background: var(--red-500);
    }

    .hero-title {
      margin: 0;
      font-size: 40px;
      line-height: 1.12;
      font-weight: 800;
      letter-spacing: 0;
      word-break: keep-all;
      white-space: nowrap;
    }

    .hero-copy {
      max-width: 520px;
      margin: 14px 0 0;
      color: var(--gray-700);
      font-size: 16px;
      line-height: 1.65;
    }

    .highlight {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 18px;
      padding: 10px 12px;
      border-radius: 8px;
      background: var(--blue-50);
      color: var(--blue-600);
      font-size: 14px;
      font-weight: 800;
    }

    .highlight.attack {
      background: var(--red-50);
      color: var(--red-500);
    }

    .highlight.loading {
      background: var(--yellow-50);
      color: #ad6800;
    }

    .hero-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 9px;
      margin-top: 24px;
    }

    .button {
      position: relative;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 48px;
      min-width: 118px;
      padding: 0 18px;
      border: 0;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 800;
      transition: transform 120ms ease, background 120ms ease, opacity 120ms ease;
    }

    .button:active {
      transform: scale(0.98);
    }

    .button:disabled {
      cursor: not-allowed;
      opacity: 0.45;
      transform: none;
    }

    .button.primary {
      background: var(--blue-500);
      color: var(--white);
    }

    .button.primary:hover:not(:disabled) {
      background: var(--blue-600);
    }

    .button.weak {
      background: var(--blue-50);
      color: var(--blue-600);
    }

    .button.danger {
      background: var(--red-50);
      color: var(--red-500);
    }

    .button .loader-mini {
      position: absolute;
      opacity: 0;
      pointer-events: none;
    }

    .button.loading .button-label {
      opacity: 0;
    }

    .button.loading .loader-mini {
      opacity: 1;
    }

    .signal-visual {
      justify-self: end;
      width: 220px;
      height: 220px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      background:
        linear-gradient(180deg, rgba(237, 246, 255, 0.8), rgba(255, 255, 255, 0.9));
      border: 1px solid var(--blue-100);
      overflow: hidden;
    }

    .radar {
      position: relative;
      width: 170px;
      height: 170px;
    }

    .ring {
      position: absolute;
      inset: 0;
      border-radius: 50%;
      border: 1px solid rgba(49, 130, 246, 0.24);
      animation: pulse 2.4s ease-out infinite;
    }

    .ring:nth-child(2) {
      inset: 26px;
      animation-delay: 0.25s;
    }

    .ring:nth-child(3) {
      inset: 52px;
      animation-delay: 0.5s;
    }

    .scanner {
      position: absolute;
      inset: 50%;
      width: 80px;
      height: 2px;
      transform-origin: left center;
      background: var(--blue-500);
      animation: scan 2s linear infinite;
      opacity: 0;
      transition: opacity 420ms ease;
    }

    .node {
      position: absolute;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--green-500);
      box-shadow: 0 0 0 6px rgba(0, 184, 117, 0.12);
      opacity: 0;
      transform: scale(0.6);
      transition: opacity 420ms ease, transform 420ms ease;
    }

    .radar.active .scanner,
    .radar.active .node {
      opacity: 1;
    }

    .radar.active .node {
      transform: scale(1);
    }

    .radar.active .node.two {
      transition-delay: 90ms;
    }

    .radar.active .node.three {
      transition-delay: 180ms;
    }

    .node.one {
      top: 38px;
      left: 64px;
    }

    .node.two {
      right: 38px;
      bottom: 54px;
      background: var(--blue-500);
      box-shadow: 0 0 0 6px rgba(49, 130, 246, 0.12);
    }

    .node.three {
      left: 44px;
      bottom: 42px;
      background: var(--red-500);
      box-shadow: 0 0 0 6px rgba(240, 68, 82, 0.12);
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 18px;
    }

    .metric {
      padding: 18px;
    }

    .metric-label {
      color: var(--gray-500);
      font-size: 13px;
      font-weight: 700;
    }

    .metric-value {
      margin-top: 8px;
      font-size: 26px;
      line-height: 1.1;
      font-weight: 800;
    }

    .metric-value.normal {
      color: var(--green-500);
    }

    .metric-value.attack {
      color: var(--red-500);
    }

    .section-title {
      margin: 0 0 18px;
      font-size: 18px;
      line-height: 1.3;
      font-weight: 800;
    }

    .stepper {
      position: relative;
      min-height: 170px;
      padding: 18px 2px 0;
    }

    .analysis-track {
      position: absolute;
      left: 16.666%;
      right: 16.666%;
      top: 40px;
      height: 7px;
      border-radius: 999px;
      background: var(--gray-100);
      overflow: hidden;
      box-shadow: inset 0 0 0 1px rgba(229, 232, 235, 0.9);
    }

    .analysis-fill {
      width: 0;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--blue-500), #00c896);
      box-shadow: 0 0 16px rgba(49, 130, 246, 0.28);
      transition: width 1200ms cubic-bezier(0.16, 1, 0.3, 1);
    }

    .analysis-steps {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .step {
      display: grid;
      justify-items: center;
      align-content: start;
      gap: 10px;
      min-height: 142px;
      padding: 0 4px;
      text-align: center;
      opacity: 0.78;
      transform: translateY(0);
      transition: opacity 320ms ease, transform 420ms cubic-bezier(0.22, 1, 0.36, 1);
    }

    .step.running,
    .step.normal,
    .step.attack,
    .step.loading {
      opacity: 1;
      transform: translateY(-2px);
    }

    .step-badge {
      position: relative;
      z-index: 1;
      width: 48px;
      height: 48px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: #ffffff;
      color: var(--gray-500);
      border: 1px solid var(--gray-200);
      font-size: 14px;
      font-weight: 800;
      box-shadow: 0 8px 22px rgba(15, 23, 42, 0.06);
      transition: background 420ms ease, color 420ms ease, border-color 420ms ease, transform 520ms cubic-bezier(0.22, 1, 0.36, 1), box-shadow 420ms ease;
    }

    .step.running .step-badge,
    .step.normal .step-badge {
      background: var(--blue-500);
      border-color: var(--blue-500);
      color: #ffffff;
      transform: scale(1.08);
      box-shadow: 0 12px 28px rgba(49, 130, 246, 0.28);
    }

    .step.attack .step-badge {
      background: var(--red-500);
      border-color: var(--red-500);
      color: #ffffff;
      transform: scale(1.08);
      box-shadow: 0 12px 28px rgba(244, 63, 94, 0.26);
    }

    .step.loading .step-badge {
      background: var(--yellow-50);
      border-color: rgba(245, 158, 11, 0.24);
      color: #ad6800;
      transform: scale(1.08);
      animation: stepPulse 1200ms ease-in-out infinite;
    }

    .step.current .step-badge::after {
      content: "";
      position: absolute;
      inset: -7px;
      border-radius: inherit;
      border: 2px solid rgba(49, 130, 246, 0.16);
      animation: stepRing 1300ms ease-out infinite;
    }

    .step-title {
      margin: 10px 0 0;
      font-size: 14px;
      font-weight: 800;
      line-height: 1.35;
      word-break: keep-all;
    }

    .step-desc {
      margin: 4px 0 0;
      color: var(--gray-500);
      font-size: 13px;
      line-height: 1.45;
    }

    .state-chip {
      display: inline-flex;
      align-items: center;
      height: 28px;
      padding: 0 10px;
      border-radius: 999px;
      background: var(--gray-100);
      color: var(--gray-700);
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }

    .state-chip.running,
    .state-chip.normal {
      background: var(--green-50);
      color: #008a59;
    }

    .state-chip.attack {
      background: var(--red-50);
      color: var(--red-500);
    }

    .state-chip.loading {
      background: var(--yellow-50);
      color: #ad6800;
    }

    .history {
      display: grid;
      gap: 10px;
    }

    .history-row {
      display: grid;
      grid-template-columns: 10px minmax(0, 1fr) auto;
      align-items: center;
      gap: 12px;
      min-height: 64px;
      padding: 14px;
    }

    .history-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--gray-300);
    }

    .history-row.normal .history-dot {
      background: var(--green-500);
    }

    .history-row.attack .history-dot {
      background: var(--red-500);
    }

    .history-title {
      margin: 0;
      font-size: 14px;
      font-weight: 800;
    }

    .history-message {
      margin: 4px 0 0;
      color: var(--gray-500);
      font-size: 13px;
      line-height: 1.35;
    }

    .history-time {
      color: var(--gray-500);
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }

    .history-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .detail-open-button {
      height: 32px;
      padding: 0 12px;
      border: 0;
      border-radius: 8px;
      background: var(--blue-50);
      color: var(--blue-600);
      cursor: pointer;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }

    .detail-open-button:hover,
    .detail-open-button:focus-visible {
      background: var(--blue-100);
      outline: none;
    }

    .detail-dialog {
      width: min(720px, 100%);
    }

    .detail-summary {
      margin: 0;
      color: var(--gray-700);
      font-size: 15px;
      line-height: 1.6;
    }

    .detail-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }

    .detail-meta span {
      display: inline-flex;
      align-items: center;
      height: 30px;
      padding: 0 10px;
      border-radius: 999px;
      background: var(--gray-100);
      color: var(--gray-700);
      font-size: 12px;
      font-weight: 800;
    }

    .detail-grid {
      display: grid;
      gap: 12px;
    }

    .detail-card {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      padding: 16px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .detail-card-title {
      margin: 0;
      font-size: 15px;
      font-weight: 800;
    }

    .detail-card-desc {
      margin: 7px 0 0;
      color: var(--gray-500);
      font-size: 13px;
      line-height: 1.5;
    }

    .detail-card-value {
      display: grid;
      justify-items: end;
      gap: 7px;
      min-width: 96px;
    }

    .detail-value {
      color: var(--gray-900);
      font-size: 15px;
      font-weight: 900;
      white-space: nowrap;
    }

    .detail-badge {
      display: inline-flex;
      align-items: center;
      height: 28px;
      padding: 0 10px;
      border-radius: 999px;
      background: var(--gray-100);
      color: var(--gray-700);
      font-size: 12px;
      font-weight: 900;
    }

    .detail-card.normal .detail-badge {
      background: var(--green-50);
      color: #008a59;
    }

    .detail-card.caution .detail-badge {
      background: var(--yellow-50);
      color: #ad6800;
    }

    .detail-card.risk .detail-badge {
      background: var(--red-50);
      color: var(--red-500);
    }

    .empty-state {
      padding: 20px;
      border-radius: 8px;
      background: var(--gray-50);
      color: var(--gray-500);
      font-size: 14px;
      line-height: 1.5;
      border: 1px dashed var(--gray-300);
    }

    .loader {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      height: 16px;
    }

    .loader span,
    .loader-mini span {
      display: block;
      width: 5px;
      height: 5px;
      border-radius: 50%;
      background: currentColor;
      animation: bounce 900ms ease-in-out infinite;
    }

    .loader span:nth-child(2),
    .loader-mini span:nth-child(2) {
      animation-delay: 120ms;
    }

    .loader span:nth-child(3),
    .loader-mini span:nth-child(3) {
      animation-delay: 240ms;
    }

    .loader-mini {
      display: inline-flex;
      gap: 4px;
      color: currentColor;
    }

    .error {
      margin-top: 14px;
      padding: 12px;
      border-radius: 8px;
      background: var(--red-50);
      color: var(--red-500);
      font-size: 13px;
      font-weight: 700;
      line-height: 1.45;
      display: none;
    }

    .guide-modal {
      position: fixed;
      inset: 0;
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: rgba(25, 31, 40, 0.38);
      opacity: 0;
      visibility: hidden;
      pointer-events: none;
      transition: opacity 220ms ease, visibility 220ms ease;
    }

    .guide-modal.open {
      opacity: 1;
      visibility: visible;
      pointer-events: auto;
    }

    body.server-error .page,
    body.server-error .bottom-info {
      opacity: 0.12;
      filter: blur(2px);
      pointer-events: none;
      user-select: none;
    }

    .server-result {
      position: fixed;
      inset: 0;
      z-index: 200;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 24px;
      background: rgba(247, 248, 250, 0.78);
    }

    .server-result.open {
      display: flex;
    }

    .server-result-box {
      width: min(420px, 100%);
      display: grid;
      justify-items: center;
      text-align: center;
      padding: 34px 24px;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.96);
      box-shadow: 0 24px 80px rgba(25, 31, 40, 0.16);
    }

    .server-result-figure {
      width: 56px;
      height: 56px;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background: var(--blue-50);
      color: var(--blue-500);
      margin-bottom: 18px;
    }

    .server-result-figure svg {
      width: 28px;
      height: 28px;
    }

    .server-result-title {
      margin: 0;
      color: var(--gray-900);
      font-size: 23px;
      line-height: 1.35;
      font-weight: 800;
    }

    .server-result-desc {
      margin: 10px 0 0;
      color: var(--gray-500);
      font-size: 15px;
      line-height: 1.6;
    }

    .server-result-button {
      margin-top: 22px;
      height: 48px;
      min-width: 132px;
      padding: 0 18px;
      border: 0;
      border-radius: 8px;
      background: var(--blue-500);
      color: var(--white);
      cursor: pointer;
      font-size: 15px;
      font-weight: 800;
    }

    .server-result-button:hover,
    .server-result-button:focus-visible {
      background: var(--blue-600);
      outline: none;
    }

    .guide-dialog {
      width: min(900px, 100%);
      max-height: min(760px, calc(100vh - 48px));
      overflow: auto;
      border-radius: 8px;
      background: var(--white);
      box-shadow: 0 24px 80px rgba(25, 31, 40, 0.24);
      opacity: 0;
      transform: translateY(14px) scale(0.98);
      transition: opacity 240ms cubic-bezier(0.22, 1, 0.36, 1), transform 240ms cubic-bezier(0.22, 1, 0.36, 1);
    }

    .guide-modal.open .guide-dialog {
      opacity: 1;
      transform: translateY(0) scale(1);
    }

    .guide-head {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 24px 26px 18px;
      border-bottom: 1px solid var(--gray-200);
    }

    .guide-title {
      margin: 0;
      font-size: 22px;
      line-height: 1.3;
      font-weight: 800;
    }

    .guide-copy {
      margin: 8px 0 0;
      color: var(--gray-500);
      font-size: 14px;
      line-height: 1.6;
    }

    .guide-close {
      width: 34px;
      height: 34px;
      display: grid;
      place-items: center;
      border: 0;
      border-radius: 50%;
      background: var(--gray-100);
      color: var(--gray-700);
      cursor: pointer;
      font-size: 20px;
      line-height: 1;
      flex: 0 0 auto;
    }

    .guide-close:hover,
    .guide-close:focus-visible {
      background: var(--gray-200);
      outline: none;
    }

    .guide-body {
      padding: 22px 26px 26px;
      display: grid;
      gap: 22px;
    }

    .guide-section {
      display: grid;
      gap: 14px;
      padding-bottom: 22px;
      border-bottom: 1px solid var(--gray-200);
    }

    .guide-section:last-child {
      border-bottom: 0;
      padding-bottom: 0;
    }

    .guide-section-title {
      margin: 0 0 12px;
      font-size: 16px;
      font-weight: 800;
      line-height: 1.35;
    }

    .guide-intro {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 190px;
      gap: 22px;
      align-items: center;
    }

    .guide-kicker {
      margin: 0 0 10px;
      color: var(--blue-600);
      font-size: 13px;
      font-weight: 900;
    }

    .guide-main-title {
      margin: 0;
      color: var(--gray-900);
      font-size: 30px;
      line-height: 1.22;
      font-weight: 900;
    }

    .guide-lead {
      margin: 14px 0 0;
      color: var(--gray-700);
      font-size: 15px;
      line-height: 1.7;
    }

    .guide-shield-stage {
      min-height: 178px;
      display: grid;
      place-items: center;
      position: relative;
      border: 1px solid rgba(49, 130, 246, 0.22);
      border-radius: 8px;
      background: linear-gradient(180deg, var(--blue-50), var(--gray-50));
      overflow: hidden;
    }

    .guide-shield-stage::before,
    .guide-shield-stage::after {
      content: "";
      position: absolute;
      border-radius: 50%;
      border: 2px solid rgba(49, 130, 246, 0.28);
      opacity: 0;
      animation: guideRipple 2.8s ease-out infinite;
    }

    .guide-shield-stage::before {
      width: 74px;
      height: 74px;
    }

    .guide-shield-stage::after {
      width: 74px;
      height: 74px;
      animation-delay: 1.25s;
    }

    .guide-shield {
      width: 78px;
      height: 78px;
      display: grid;
      place-items: center;
      position: relative;
      z-index: 1;
      border-radius: 20px;
      background: var(--blue-500);
      color: #ffffff;
      box-shadow: 0 18px 44px rgba(49, 130, 246, 0.32);
      transform-style: preserve-3d;
      animation: guideShieldTurn 3.2s linear infinite;
    }

    .guide-shield svg {
      width: 44px;
      height: 44px;
    }

    .guide-divider {
      width: 100%;
      height: 1px;
      background: var(--gray-200);
      margin: 4px 0;
    }

    .guide-link-card {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      padding: 16px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-link-card p {
      margin: 0;
      color: var(--gray-700);
      font-size: 14px;
      line-height: 1.55;
    }

    .guide-link-card a {
      flex: 0 0 auto;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 38px;
      padding: 0 14px;
      border-radius: 8px;
      background: var(--blue-500);
      color: #ffffff;
      text-decoration: none;
      font-size: 13px;
      font-weight: 900;
    }

    .guide-screen-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .guide-screen-card {
      min-height: 136px;
      padding: 16px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-screen-card h4 {
      margin: 0;
      font-size: 15px;
      line-height: 1.35;
      font-weight: 900;
    }

    .guide-screen-card p {
      margin: 9px 0 0;
      color: var(--gray-700);
      font-size: 13px;
      line-height: 1.6;
    }

    .guide-button-sample {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
      pointer-events: none;
    }

    .guide-button-sample .button {
      min-width: 112px;
      height: 44px;
      font-size: 14px;
    }

    .guide-card-preview {
      margin-bottom: 12px;
      pointer-events: none;
    }

    .guide-card-preview .guide-mini-status,
    .guide-card-preview .guide-mini-analysis {
      padding: 12px;
    }

    .guide-card-preview .guide-mini-status-title {
      font-size: 18px;
    }

    .guide-mini-metrics {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }

    .guide-mini-metric {
      min-height: 66px;
      padding: 11px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--white);
    }

    .guide-mini-metric span {
      display: block;
      color: var(--gray-500);
      font-size: 11px;
      font-weight: 800;
    }

    .guide-mini-metric strong {
      display: block;
      margin-top: 7px;
      color: var(--gray-900);
      font-size: 20px;
      line-height: 1;
      font-weight: 900;
    }

    .guide-mini-metric.normal strong {
      color: var(--green-500);
    }

    .guide-mini-metric.attack strong {
      color: var(--red-500);
    }

    .guide-mini-history {
      display: grid;
      grid-template-columns: 9px minmax(0, 1fr) auto;
      align-items: center;
      gap: 10px;
      min-height: 58px;
      padding: 12px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--white);
    }

    .guide-mini-history-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--red-500);
    }

    .guide-mini-history strong {
      display: block;
      color: var(--gray-900);
      font-size: 13px;
      line-height: 1.2;
      font-weight: 900;
    }

    .guide-mini-history span {
      display: block;
      margin-top: 4px;
      color: var(--gray-500);
      font-size: 11px;
      line-height: 1.3;
      font-weight: 700;
    }

    .guide-mini-history button {
      height: 30px;
      padding: 0 10px;
      border: 0;
      border-radius: 8px;
      background: var(--blue-50);
      color: var(--blue-600);
      font-size: 11px;
      font-weight: 900;
    }

    .guide-mini-theme {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      flex-wrap: wrap;
    }

    .guide-mini-theme-toggle {
      height: 38px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 0 14px;
      border: 1px solid var(--gray-200);
      border-radius: 999px;
      background: var(--white);
      color: var(--gray-900);
      font-size: 13px;
      font-weight: 900;
    }

    .guide-mini-theme-menu {
      width: 148px;
      padding: 8px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--white);
      box-shadow: var(--shadow);
    }

    .guide-mini-theme-menu span {
      display: flex;
      align-items: center;
      height: 32px;
      padding: 0 9px;
      border-radius: 8px;
      color: var(--gray-700);
      font-size: 12px;
      font-weight: 800;
    }

    .guide-mini-theme-menu span:first-child {
      background: var(--blue-50);
      color: var(--blue-600);
    }

    .guide-preview-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .guide-preview-panel {
      padding: 16px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-preview-panel h4 {
      margin: 0 0 12px;
      font-size: 15px;
      font-weight: 900;
    }

    .guide-mini-status {
      display: grid;
      gap: 12px;
      padding: 16px;
      border: 1px solid rgba(240, 68, 82, 0.28);
      border-radius: 8px;
      background: var(--red-50);
    }

    .guide-mini-status-bar {
      width: 100%;
      height: 5px;
      border-radius: 999px;
      background: var(--red-500);
      opacity: 0.82;
    }

    .guide-mini-status-title {
      margin: 0;
      color: var(--gray-900);
      font-size: 22px;
      line-height: 1.25;
      font-weight: 900;
    }

    .guide-mini-status-copy {
      margin: 0;
      color: var(--gray-700);
      font-size: 13px;
      line-height: 1.55;
    }

    .guide-mini-highlight {
      width: fit-content;
      display: inline-flex;
      align-items: center;
      height: 32px;
      padding: 0 12px;
      border-radius: 8px;
      background: var(--red-50);
      color: var(--red-500);
      font-size: 13px;
      font-weight: 900;
      border: 1px solid rgba(240, 68, 82, 0.18);
    }

    .guide-mini-analysis {
      display: grid;
      gap: 12px;
      padding: 16px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-mini-step-track {
      height: 6px;
      border-radius: 999px;
      background: linear-gradient(90deg, var(--blue-500), var(--red-500));
    }

    .guide-mini-steps {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }

    .guide-mini-step {
      display: grid;
      justify-items: center;
      gap: 8px;
      text-align: center;
    }

    .guide-mini-step-num {
      width: 38px;
      height: 38px;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background: var(--blue-500);
      color: #ffffff;
      font-size: 14px;
      font-weight: 900;
    }

    .guide-mini-step.attack .guide-mini-step-num {
      background: var(--red-500);
    }

    .guide-mini-step strong {
      font-size: 13px;
      line-height: 1.35;
    }

    .guide-mini-step span {
      display: inline-flex;
      align-items: center;
      height: 26px;
      padding: 0 9px;
      border-radius: 999px;
      background: var(--green-50);
      color: #008a59;
      font-size: 11px;
      font-weight: 900;
    }

    .guide-mini-step.attack span {
      background: var(--red-50);
      color: var(--red-500);
    }

    .guide-status-list {
      display: grid;
      gap: 10px;
    }

    .guide-status-row {
      display: grid;
      grid-template-columns: 96px minmax(0, 1fr);
      gap: 12px;
      align-items: center;
      padding: 13px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-status-label {
      display: inline-flex;
      justify-content: center;
      align-items: center;
      height: 32px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 900;
    }

    .guide-status-label.idle {
      background: var(--blue-50);
      color: var(--blue-600);
    }

    .guide-status-label.loading {
      background: var(--yellow-50);
      color: #ad6800;
    }

    .guide-status-label.normal {
      background: var(--green-50);
      color: #008a59;
    }

    .guide-status-label.attack {
      background: var(--red-50);
      color: var(--red-500);
    }

    .guide-status-row p {
      margin: 0;
      color: var(--gray-700);
      font-size: 13px;
      line-height: 1.5;
    }

    .guide-status-preview {
      padding: 18px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-status-preview h4 {
      margin: 0;
      font-size: 24px;
      line-height: 1.25;
      font-weight: 800;
    }

    .guide-status-preview p {
      margin: 10px 0 0;
      color: var(--gray-700);
      font-size: 14px;
      line-height: 1.55;
    }

    .guide-status-chip {
      display: inline-flex;
      align-items: center;
      margin-top: 14px;
      height: 34px;
      padding: 0 12px;
      border-radius: 8px;
      background: var(--green-50);
      color: #008a59;
      font-size: 13px;
      font-weight: 800;
    }

    .guide-button-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    .guide-button-card {
      min-height: 148px;
      padding: 14px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-demo-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 42px;
      min-width: 104px;
      padding: 0 16px;
      border: 0;
      border-radius: 8px;
      cursor: default;
      font-size: 14px;
      font-weight: 800;
      pointer-events: none;
    }

    .guide-demo-button.primary {
      background: var(--blue-500);
      color: var(--white);
    }

    .guide-demo-button.weak {
      background: var(--blue-50);
      color: var(--blue-600);
    }

    .guide-demo-button.danger {
      background: var(--red-50);
      color: var(--red-500);
    }

    .guide-desc {
      margin: 12px 0 0;
      color: var(--gray-700);
      font-size: 13px;
      line-height: 1.55;
    }

    .guide-result-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    .guide-result-card {
      min-height: 112px;
      padding: 14px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-result-head {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      font-weight: 800;
    }

    .guide-result-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--gray-300);
      flex: 0 0 auto;
    }

    .guide-result-card.normal .guide-result-dot {
      background: var(--green-500);
    }

    .guide-result-card.attack .guide-result-dot {
      background: var(--red-500);
    }

    .guide-result-card.loading .guide-result-dot {
      background: var(--yellow-500);
    }

    .guide-dashboard {
      display: grid;
      gap: 12px;
      padding: 14px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }

    .guide-metric {
      min-height: 74px;
      padding: 12px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--white);
    }

    .guide-metric span {
      display: block;
      color: var(--gray-500);
      font-size: 12px;
      font-weight: 700;
    }

    .guide-metric strong {
      display: block;
      margin-top: 7px;
      color: var(--gray-900);
      font-size: 22px;
      line-height: 1.1;
      font-weight: 800;
    }

    .guide-process {
      padding: 16px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--white);
    }

    .guide-process h4 {
      margin: 0 0 12px;
      font-size: 15px;
      font-weight: 800;
    }

    .guide-process-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .guide-process-item {
      padding: 12px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-process-name {
      margin: 0;
      font-size: 13px;
      font-weight: 800;
    }

    .guide-process-sub {
      margin: 5px 0 0;
      color: var(--gray-500);
      font-size: 12px;
    }

    .guide-note {
      margin: 0;
      color: var(--gray-500);
      font-size: 13px;
      line-height: 1.55;
    }

    .guide-step-list {
      display: grid;
      gap: 10px;
    }

    .guide-step-row {
      display: grid;
      grid-template-columns: 34px minmax(0, 1fr);
      gap: 12px;
      align-items: start;
      padding: 12px;
      border: 1px solid var(--gray-200);
      border-radius: 8px;
      background: var(--gray-50);
    }

    .guide-step-num {
      width: 34px;
      height: 34px;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background: var(--blue-50);
      color: var(--blue-600);
      font-size: 13px;
      font-weight: 800;
    }

    .guide-step-title {
      margin: 0;
      font-size: 14px;
      font-weight: 800;
    }

    .guide-step-desc {
      margin: 4px 0 0;
      color: var(--gray-500);
      font-size: 13px;
      line-height: 1.5;
    }

    .bottom-info {
      width: min(1180px, calc(100% - 40px));
      margin: 22px auto 0;
      padding: 18px 0 24px;
      border-top: 1px solid rgba(209, 214, 219, 0.72);
      color: var(--gray-500);
      font-size: 11px;
      line-height: 1.5;
      flex: 0 0 auto;
    }

    .bottom-info p {
      margin: 0;
    }

    .bottom-info a {
      color: var(--gray-500);
      text-decoration: none;
      font-weight: 700;
    }

    .bottom-info a:hover {
      color: var(--gray-700);
      text-decoration: underline;
    }

    .bottom-info-row {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      flex-wrap: wrap;
      text-align: center;
    }

    .bottom-info-mark {
      width: 16px;
      height: 16px;
      color: var(--gray-500);
      flex: 0 0 auto;
    }

    @keyframes stepPulse {
      0%, 100% {
        box-shadow: 0 10px 22px rgba(245, 158, 11, 0.16);
      }
      50% {
        box-shadow: 0 14px 30px rgba(245, 158, 11, 0.3);
      }
    }

    @keyframes stepRing {
      0% {
        opacity: 0.72;
        transform: scale(0.82);
      }
      100% {
        opacity: 0;
        transform: scale(1.26);
      }
    }

    @keyframes guideShieldTurn {
      0% {
        transform: perspective(700px) rotateY(0deg);
      }
      100% {
        transform: perspective(700px) rotateY(360deg);
      }
    }

    @keyframes guideRipple {
      0% {
        opacity: 0.5;
        transform: scale(0.72);
      }
      70% {
        opacity: 0.14;
      }
      100% {
        opacity: 0;
        transform: scale(2.35);
      }
    }

    @keyframes bounce {
      0%, 80%, 100% {
        transform: translateY(0);
        opacity: 0.45;
      }
      40% {
        transform: translateY(-5px);
        opacity: 1;
      }
    }

    @keyframes pulse {
      0% {
        transform: scale(0.82);
        opacity: 0.9;
      }
      100% {
        transform: scale(1.08);
        opacity: 0.15;
      }
    }

    @keyframes scan {
      from {
        transform: rotate(0deg);
      }
      to {
        transform: rotate(360deg);
      }
    }

    @media (max-width: 920px) {
      .layout,
      .hero {
        grid-template-columns: 1fr;
      }

      .signal-visual {
        justify-self: stretch;
        width: 100%;
      }

      .metrics {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }

      .guide-button-grid,
      .guide-metrics,
      .guide-process-grid,
      .guide-result-grid,
      .guide-preview-grid,
      .guide-screen-grid {
        grid-template-columns: 1fr;
      }

      .guide-intro {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 560px) {
      .page {
        width: min(100% - 24px, 1180px);
        padding-top: 20px;
      }

      .topbar {
        align-items: flex-start;
        flex-direction: column;
      }

      .panel {
        padding: 18px;
      }

      .hero-title {
        font-size: 30px;
        white-space: normal;
      }

      .button {
        width: 100%;
      }

      .metrics {
        grid-template-columns: 1fr;
      }

      .stepper {
        overflow-x: auto;
        padding-bottom: 12px;
      }

      .analysis-track {
        left: 16.666%;
        right: 16.666%;
      }

      .analysis-steps {
        min-width: 420px;
      }
    }
  </style>
</head>
<body>
  <main class="page">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none">
            <path d="M12 3l7 3v5c0 4.6-2.9 8.7-7 10-4.1-1.3-7-5.4-7-10V6l7-3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
            <path d="M8.5 12.2l2.2 2.2 4.8-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div>
          <div class="brand-title-row">
            <h1>TwinGuard</h1>
            <button id="openGuideButton" class="top-menu-button" type="button">도움말</button>
          </div>
          <p>Local Evil Twin Detection Dashboard</p>
        </div>
      </div>
      <div class="top-actions">
        <div id="themeMenu" class="theme-menu">
          <button id="themeToggle" class="theme-toggle" type="button" aria-haspopup="menu" aria-expanded="false">
            <span id="themeIcon" class="theme-icon" aria-hidden="true">T</span>
            <span id="themeText">테마 변경</span>
          </button>
          <div id="themePanel" class="theme-panel" role="menu" aria-label="테마 선택">
            <button id="lightThemeButton" class="theme-option" type="button" role="menuitemradio" aria-checked="false">라이트모드</button>
            <button id="darkThemeButton" class="theme-option" type="button" role="menuitemradio" aria-checked="true">다크모드</button>
          </div>
        </div>
        <div id="modePill" class="mode-pill">
          <span class="mode-dot"></span>
          <span id="modeText">대기</span>
        </div>
      </div>
    </header>

    <section class="layout">
      <div>
        <section class="panel hero">
          <div class="hero-status-bar" aria-label="실시간 상태">
            <p class="hero-status-label">실시간 상태</p>
            <div class="hero-status-track"><span id="heroStatusFill" class="hero-status-fill"></span></div>
          </div>
          <div>
            <h2 id="verdictTitle" class="hero-title">보호 시작을 누르세요</h2>
            <p id="verdictMessage" class="hero-copy">보호 시작을 누르세요</p>
            <div id="highlight" class="highlight">
              <span id="highlightLoader" class="loader" aria-hidden="true">
                <span></span><span></span><span></span>
              </span>
              <span id="highlightText">모델 대기 중</span>
            </div>
            <div class="hero-actions">
              <button id="startButton" class="button primary" type="button">
                <span class="button-label">보호 시작</span>
                <span class="loader-mini" aria-hidden="true"><span></span><span></span><span></span></span>
              </button>
              <button id="restartButton" class="button weak" type="button">
                <span class="button-label">재시작</span>
                <span class="loader-mini" aria-hidden="true"><span></span><span></span><span></span></span>
              </button>
              <button id="stopButton" class="button danger" type="button">
                <span class="button-label">중지</span>
                <span class="loader-mini" aria-hidden="true"><span></span><span></span><span></span></span>
              </button>
            </div>
            <div id="errorBox" class="error"></div>
          </div>

          <div class="signal-visual" aria-hidden="true">
            <div id="radar" class="radar">
              <div class="ring"></div>
              <div class="ring"></div>
              <div class="ring"></div>
              <div class="scanner"></div>
              <div class="node one"></div>
              <div class="node two"></div>
              <div class="node three"></div>
            </div>
          </div>
        </section>

        <section class="metrics" aria-label="탐지 지표">
          <article class="metric">
            <div class="metric-label">총 측정</div>
            <div id="totalCount" class="metric-value">0</div>
          </article>
          <article class="metric">
            <div class="metric-label">정상</div>
            <div id="normalCount" class="metric-value normal">0</div>
          </article>
          <article class="metric">
            <div class="metric-label">위험</div>
            <div id="attackCount" class="metric-value attack">0</div>
          </article>
          <article class="metric">
            <div class="metric-label">실행 시간</div>
            <div id="uptime" class="metric-value">00:00</div>
          </article>
        </section>

      </div>

      <aside>
        <section class="panel">
          <h2 class="section-title">분석 단계</h2>
          <div id="stepper" class="stepper"></div>
        </section>

        <section class="panel" style="margin-top:18px;">
          <h2 class="section-title">최근 탐지 결과</h2>
          <div id="history" class="history"></div>
        </section>
      </aside>
    </section>

  </main>

  <footer class="bottom-info" aria-label="프로젝트 정보">
    <div class="bottom-info-row">
      <svg class="bottom-info-mark" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M8 0C3.58 0 0 3.67 0 8.2c0 3.62 2.29 6.69 5.47 7.78.4.08.55-.18.55-.4v-1.39c-2.23.5-2.7-1.1-2.7-1.1-.36-.95-.89-1.2-.89-1.2-.73-.51.05-.5.05-.5.81.06 1.24.86 1.24.86.72 1.27 1.88.9 2.34.69.07-.53.28-.9.51-1.1-1.78-.21-3.64-.91-3.64-4.04 0-.9.31-1.63.83-2.2-.08-.21-.36-1.05.08-2.17 0 0 .68-.22 2.2.84A7.45 7.45 0 0 1 8 4c.68 0 1.36.09 2 .27 1.53-1.06 2.2-.84 2.2-.84.44 1.12.16 1.96.08 2.17.52.57.83 1.3.83 2.2 0 3.14-1.87 3.83-3.65 4.03.29.26.55.76.55 1.53v2.22c0 .22.14.48.55.4A8.12 8.12 0 0 0 16 8.2C16 3.67 12.42 0 8 0Z"/>
      </svg>
      <span>GitHub</span>
      <span>·</span>
      <a href="https://github.com/DeceptiveRat/TwinGuard" target="_blank" rel="noopener noreferrer">DeceptiveRat/TwinGuard</a>
    </div>
  </footer>

  <div id="guideModal" class="guide-modal" role="dialog" aria-modal="true" aria-labelledby="guideTitle">
    <section class="guide-dialog">
      <header class="guide-head">
        <div>
          <h2 id="guideTitle" class="guide-title">TwinGuard란 무엇인가요?</h2>
          <p class="guide-copy">TwinGuard 화면을 처음 보는 사용자를 위한 간단한 안내입니다.</p>
        </div>
        <button id="closeGuideButton" class="guide-close" type="button" aria-label="도움말 닫기">×</button>
      </header>
      <div class="guide-body">
        <section class="guide-section">
          <div class="guide-intro">
            <div>
              <p class="guide-kicker">Local Evil Twin Detection Dashboard</p>
              <h3 class="guide-main-title">여러분의 Wi-Fi가 안전한지 확인해주는 로컬 보안 도구입니다.</h3>
              <p class="guide-lead">
                TwinGuard는 현재 네트워크 통신 흐름을 분석하고, AI 탐지 결과를 함께 확인해서
                Evil Twin처럼 의심스러운 Wi-Fi 공격 신호가 있는지 알려줍니다.
              </p>
            </div>
            <div class="guide-shield-stage" aria-hidden="true">
              <div class="guide-shield">
                <svg viewBox="0 0 24 24" fill="none">
                  <path d="M12 3l7 3v5c0 4.6-2.9 8.7-7 10-4.1-1.3-7-5.4-7-10V6l7-3z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                  <path d="M8.5 12.2l2.2 2.2 4.8-5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
              </div>
            </div>
          </div>
        </section>

        <section class="guide-section">
          <div>
            <h3 class="guide-section-title">트윈가드는 어떤 프로그램인가요?</h3>
            <p class="guide-note">
              TwinGuard는 복잡한 보안 지식이 없어도 사용할 수 있게 만든 Wi-Fi 보호 대시보드입니다.
              사용자는 보호 시작 버튼만 누르면 되고, 화면은 현재 네트워크가 정상인지 위험한지만 쉽게 보여줍니다.
            </p>
          </div>
          <div class="guide-link-card">
            <p>프로젝트 구조, 실행 방법, 탐지 흐름이 궁금하다면 GitHub 저장소에서 자세히 확인할 수 있습니다.</p>
            <a href="https://github.com/DeceptiveRat/TwinGuard" target="_blank" rel="noopener noreferrer">GitHub 보기</a>
          </div>
        </section>

        <section class="guide-section">
          <div>
            <h3 class="guide-section-title">메인화면 소개</h3>
            <p class="guide-note">메인화면은 보호 모드 제어, 실시간 상태, 탐지 결과, 분석 단계로 나뉩니다. 아래 예시는 실제 탐지에는 영향을 주지 않는 안내용 화면입니다.</p>
          </div>
          <div class="guide-screen-grid">
            <article class="guide-screen-card">
              <div class="guide-button-sample">
                <button class="button primary" type="button" tabindex="-1">보호 시작</button>
              </div>
              <h4>보호 시작</h4>
              <p>처음 사용할 때 누르는 버튼입니다. 누르면 패킷 수집, 분석, 결과 수신이 순서대로 시작되고, 화면은 대기 상태에서 측정 중 상태로 바뀝니다. 모델 결과가 도착하면 정상 또는 위험 상태가 표시됩니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-button-sample">
                <button class="button weak" type="button" tabindex="-1">재시작</button>
              </div>
              <h4>재시작</h4>
              <p>탐지가 멈춘 것처럼 보이거나, 네트워크를 바꾼 뒤 다시 측정하고 싶을 때 사용합니다. 현재 실행 중인 보호 흐름을 정리한 뒤 처음부터 다시 시작합니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-button-sample">
                <button class="button danger" type="button" tabindex="-1">중지</button>
              </div>
              <h4>중지</h4>
              <p>실시간 보호 모드를 멈춥니다. 중지하면 패킷 수집과 분석이 종료되고, 분석 단계와 탐지 결과는 대기 상태로 돌아갑니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-card-preview">
                <div class="guide-mini-status">
                  <div class="guide-mini-status-bar"></div>
                  <p class="guide-mini-status-title">위험 신호가 감지됐어요</p>
                  <p class="guide-mini-status-copy">공격 또는 고위험 신호가 감지되었습니다.</p>
                  <span class="guide-mini-highlight">위험</span>
                </div>
              </div>
              <h4>실시간 상태</h4>
              <p>화면 왼쪽의 가장 큰 영역입니다. 보호 시작 전에는 대기 문구가 보이고, 측정 중에는 모델 결과를 기다린다고 표시됩니다. 공격이 의심되면 빨간색 위험 상태로 바뀝니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-card-preview">
                <div class="guide-mini-metrics">
                  <div class="guide-mini-metric">
                    <span>총 측정</span>
                    <strong>128</strong>
                  </div>
                  <div class="guide-mini-metric normal">
                    <span>정상</span>
                    <strong>124</strong>
                  </div>
                  <div class="guide-mini-metric attack">
                    <span>위험</span>
                    <strong>4</strong>
                  </div>
                </div>
              </div>
              <h4>총 측정 / 정상 / 위험</h4>
              <p>모델이 받은 전체 판단 수, 정상으로 나온 횟수, 위험으로 나온 횟수를 숫자로 보여줍니다. 위험 숫자가 올라가면 최근 탐지 결과와 세부 내용을 함께 확인하면 됩니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-card-preview">
                <div class="guide-mini-history">
                  <span class="guide-mini-history-dot"></span>
                  <div>
                    <strong>HIGH RISK</strong>
                    <span>Evil Twin 의심 신호가 감지되었습니다.</span>
                  </div>
                  <button type="button" tabindex="-1">세부 내용 보기</button>
                </div>
              </div>
              <h4>최근 탐지 결과</h4>
              <p>가장 최근에 받은 판단 1개만 표시합니다. NORMAL이면 정상 패턴, HIGH RISK이면 공격 의심 패턴입니다. 세부 내용 보기를 누르면 RSSI, RTT, BSSID, AI 분석 상태를 간단히 확인할 수 있습니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-card-preview">
                <div class="guide-mini-analysis">
                  <div class="guide-mini-step-track"></div>
                  <div class="guide-mini-steps">
                    <div class="guide-mini-step">
                      <div class="guide-mini-step-num">1</div>
                      <strong>패킷 수집</strong>
                      <span>완료</span>
                    </div>
                    <div class="guide-mini-step">
                      <div class="guide-mini-step-num">2</div>
                      <strong>분석</strong>
                      <span>완료</span>
                    </div>
                    <div class="guide-mini-step attack">
                      <div class="guide-mini-step-num">3</div>
                      <strong>결과 수신</strong>
                      <span>위험</span>
                    </div>
                  </div>
                </div>
              </div>
              <h4>분석 단계</h4>
              <p>오른쪽의 단계 표시입니다. 패킷 수집, 분석, 결과 수신 순서로 진행되며, 현재 탐지 흐름이 어디까지 도달했는지 색상과 단계 번호로 보여줍니다.</p>
            </article>
            <article class="guide-screen-card">
              <div class="guide-card-preview">
                <div class="guide-mini-theme">
                  <div class="guide-mini-theme-toggle"><span>T</span><span>테마 변경</span></div>
                  <div class="guide-mini-theme-menu">
                    <span>다크모드</span>
                    <span>라이트모드</span>
                  </div>
                </div>
              </div>
              <h4>테마 변경</h4>
              <p>오른쪽 위에서 다크모드와 라이트모드를 바꿀 수 있습니다. 밝은 환경에서는 라이트모드, 어두운 화면에서는 다크모드를 사용하면 보기 편합니다.</p>
            </article>
          </div>
        </section>

        <section class="guide-section">
          <div>
            <h3 class="guide-section-title">상태가 바뀌면 어떻게 보이나요?</h3>
            <p class="guide-note">TwinGuard는 복잡한 로그 대신 색상과 짧은 문장으로 현재 상황을 알려줍니다.</p>
          </div>
          <div class="guide-status-list">
            <div class="guide-status-row">
              <span class="guide-status-label idle">대기</span>
              <p>아직 보호 모드를 시작하지 않은 상태입니다. 보호 시작을 누르면 탐지를 시작합니다.</p>
            </div>
            <div class="guide-status-row">
              <span class="guide-status-label loading">측정 중</span>
              <p>패킷을 모으고 모델 결과를 기다리는 상태입니다. 첫 결과가 도착하면 정상 또는 위험으로 바뀝니다.</p>
            </div>
            <div class="guide-status-row">
              <span class="guide-status-label normal">정상</span>
              <p>최근 결과가 정상 네트워크 패턴으로 판단된 상태입니다.</p>
            </div>
            <div class="guide-status-row">
              <span class="guide-status-label attack">위험</span>
              <p>Evil Twin 의심 신호가 감지된 상태입니다. 최근 탐지 결과와 세부 내용을 확인해 주세요.</p>
            </div>
          </div>
        </section>
      </div>
    </section>
  </div>

  <div id="detailModal" class="guide-modal" role="dialog" aria-modal="true" aria-labelledby="detailTitle">
    <section class="guide-dialog detail-dialog">
      <header class="guide-head">
        <div>
          <h2 id="detailTitle" class="guide-title">탐지 세부 내용</h2>
          <p id="detailSummary" class="detail-summary">가장 최근 판단 기록을 기준으로 표시합니다.</p>
          <div id="detailMeta" class="detail-meta"></div>
        </div>
        <button id="closeDetailButton" class="guide-close" type="button" aria-label="세부 내용 닫기">×</button>
      </header>
      <div class="guide-body">
        <div id="detailRows" class="detail-grid"></div>
      </div>
    </section>
  </div>

  <div id="serverResult" class="server-result" role="alertdialog" aria-modal="true" aria-labelledby="serverResultTitle" aria-describedby="serverResultDesc">
    <div class="server-result-box">
      <div class="server-result-figure" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M12 8v5" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          <path d="M12 16.8v.2" stroke="currentColor" stroke-width="2.8" stroke-linecap="round"/>
          <path d="M12 3.5 21 20H3L12 3.5Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
        </svg>
      </div>
      <h2 id="serverResultTitle" class="server-result-title">다시 접속해주세요</h2>
      <p id="serverResultDesc" class="server-result-desc">TwinGuard UI 서버와 연결이 끊어졌습니다.<br>프로그램을 다시 실행한 뒤 화면을 새로고침해 주세요.</p>
      <button id="reloadPageButton" class="server-result-button" type="button">새로고침</button>
    </div>
  </div>

  <script>
    const startButton = document.getElementById("startButton");
    const restartButton = document.getElementById("restartButton");
    const stopButton = document.getElementById("stopButton");
    const modePill = document.getElementById("modePill");
    const modeText = document.getElementById("modeText");
    const verdictTitle = document.getElementById("verdictTitle");
    const verdictMessage = document.getElementById("verdictMessage");
    const heroStatusFill = document.getElementById("heroStatusFill");
    const highlight = document.getElementById("highlight");
    const highlightText = document.getElementById("highlightText");
    const highlightLoader = document.getElementById("highlightLoader");
    const errorBox = document.getElementById("errorBox");
    const totalCount = document.getElementById("totalCount");
    const normalCount = document.getElementById("normalCount");
    const attackCount = document.getElementById("attackCount");
    const uptime = document.getElementById("uptime");
    const stepper = document.getElementById("stepper");
    const history = document.getElementById("history");
    const radar = document.getElementById("radar");
    const openGuideButton = document.getElementById("openGuideButton");
    const closeGuideButton = document.getElementById("closeGuideButton");
    const guideModal = document.getElementById("guideModal");
    const detailModal = document.getElementById("detailModal");
    const closeDetailButton = document.getElementById("closeDetailButton");
    const detailTitle = document.getElementById("detailTitle");
    const detailSummary = document.getElementById("detailSummary");
    const detailMeta = document.getElementById("detailMeta");
    const detailRows = document.getElementById("detailRows");
    const serverResult = document.getElementById("serverResult");
    const reloadPageButton = document.getElementById("reloadPageButton");
    const themeMenu = document.getElementById("themeMenu");
    const themeToggle = document.getElementById("themeToggle");
    const themeIcon = document.getElementById("themeIcon");
    const themeText = document.getElementById("themeText");
    const lightThemeButton = document.getElementById("lightThemeButton");
    const darkThemeButton = document.getElementById("darkThemeButton");
    let lastStepsSignature = "";
    let visualActiveCount = 0;
    let targetActiveCount = 0;
    let stepAdvanceTimer = null;
    let latestSteps = [];
    let latestEvents = [];
    const STEP_ADVANCE_DELAY_MS = 500;

    const labels = {
      running: "실행 중",
      degraded: "일부 실행",
      stopped: "중지됨",
      exited: "종료됨",
      normal: "정상",
      attack: "위험",
      loading: "측정 중",
      idle: "대기",
      unknown: "확인 필요"
    };

    function applyTheme(theme) {
      const isDark = theme === "dark";
      document.body.classList.toggle("dark-theme", isDark);
      themeIcon.textContent = "T";
      themeText.textContent = "테마 변경";
      lightThemeButton.classList.toggle("active", !isDark);
      darkThemeButton.classList.toggle("active", isDark);
      lightThemeButton.setAttribute("aria-checked", String(!isDark));
      darkThemeButton.setAttribute("aria-checked", String(isDark));
      localStorage.setItem("twinguard-theme-v2", isDark ? "dark" : "light");
    }

    function closeThemeMenu() {
      themeMenu.classList.remove("open");
      themeToggle.setAttribute("aria-expanded", "false");
    }

    function setButtonLoading(button, isLoading) {
      button.classList.toggle("loading", isLoading);
      button.disabled = isLoading;
    }

    async function postAction(path, button) {
      setButtonLoading(button, true);
      try {
        const response = await fetch(path, { method: "POST" });
        if (!response.ok) {
          throw new Error("server unavailable");
        }
        const payload = await response.json();
        hideServerResult();
        resetStepAnimation();
        render(payload);
      } catch (error) {
        showServerResult();
      } finally {
        setButtonLoading(button, false);
        refresh();
      }
    }

    function showError(message) {
      if (!message) {
        errorBox.style.display = "none";
        errorBox.textContent = "";
        return;
      }
      errorBox.textContent = message;
      errorBox.style.display = "block";
    }

    function showServerResult() {
      document.body.classList.add("server-error");
      serverResult.classList.add("open");
      reloadPageButton.focus();
    }

    function hideServerResult() {
      document.body.classList.remove("server-error");
      serverResult.classList.remove("open");
    }

    function chipClass(state) {
      if (state === "running") return "running";
      if (state === "normal") return "normal";
      if (state === "attack") return "attack";
      if (state === "loading") return "loading";
      return "";
    }

    function isActiveStep(state) {
      return ["running", "normal", "attack", "loading"].includes(state);
    }

    function activeCountForSteps(steps) {
      let count = 0;
      for (const step of steps) {
        if (!isActiveStep(step.state)) {
          break;
        }
        count += 1;
      }
      return count;
    }

    function progressForActiveCount(activeCount, stepCount) {
      if (!activeCount) return 0;
      if (stepCount <= 1) return 100;
      return Math.min(100, Math.max(0, ((activeCount - 1) / (stepCount - 1)) * 100));
    }

    function resetStepAnimation() {
      if (stepAdvanceTimer) {
        clearTimeout(stepAdvanceTimer);
        stepAdvanceTimer = null;
      }
      lastStepsSignature = "";
      visualActiveCount = 0;
      targetActiveCount = 0;
    }

    function ensureStepperStructure(steps) {
      const structureSignature = steps.map((step) => `${step.number}:${step.title}`).join("|");
      if (stepper.dataset.structure === structureSignature) {
        return false;
      }

      stepper.dataset.structure = structureSignature;
      stepper.innerHTML = `
        <div class="analysis-track" aria-hidden="true"><div class="analysis-fill"></div></div>
        <div class="analysis-steps">
          ${steps.map((step, index) => `
            <div class="step" data-step-index="${index}">
              <div class="step-badge">${step.number}</div>
              <p class="step-title">${step.title}</p>
              <span class="state-chip">대기</span>
            </div>
          `).join("")}
        </div>
      `;
      resetStepAnimation();
      return true;
    }

    function paintSteps(steps, activeCount) {
      const progress = progressForActiveCount(activeCount, steps.length);
      const currentIndex = activeCount ? activeCount - 1 : -1;
      const fill = stepper.querySelector(".analysis-fill");

      steps.forEach((step, index) => {
        const item = stepper.querySelector(`[data-step-index="${index}"]`);
        const isVisibleActive = index < activeCount;
        let visibleState = isVisibleActive ? step.state : "idle";
        if (isVisibleActive && !chipClass(visibleState)) {
          visibleState = "running";
        }

        const stateClass = chipClass(visibleState);
        const currentClass = index === currentIndex ? " current" : "";
        item.className = `step ${stateClass}${currentClass}`.trim();
        item.querySelector(".state-chip").className = `state-chip ${stateClass}`.trim();
        item.querySelector(".state-chip").textContent = labels[visibleState] || labels.idle;
      });

      requestAnimationFrame(() => {
        fill.style.width = `${progress}%`;
      });
    }

    function scheduleStepAdvance() {
      if (stepAdvanceTimer || visualActiveCount >= targetActiveCount) {
        return;
      }

      stepAdvanceTimer = setTimeout(() => {
        stepAdvanceTimer = null;
        visualActiveCount = Math.min(targetActiveCount, visualActiveCount + 1);
        paintSteps(latestSteps, visualActiveCount);
        scheduleStepAdvance();
      }, STEP_ADVANCE_DELAY_MS);
    }

    function renderSteps(steps, mode) {
      ensureStepperStructure(steps);
      latestSteps = steps;
      const measuredTarget = activeCountForSteps(steps);
      const signature = steps.map((step) => `${step.number}:${step.title}:${step.state}`).join("|");

      if (mode === "stopped") {
        if (stepAdvanceTimer) {
          clearTimeout(stepAdvanceTimer);
          stepAdvanceTimer = null;
        }
        targetActiveCount = measuredTarget;
        visualActiveCount = measuredTarget;
        lastStepsSignature = signature;
        paintSteps(steps, visualActiveCount);
        return;
      }

      targetActiveCount = Math.max(measuredTarget, targetActiveCount, visualActiveCount, 1);
      if (visualActiveCount === 0 && targetActiveCount > 0) {
        visualActiveCount = 1;
      }

      if (signature !== lastStepsSignature || visualActiveCount < targetActiveCount) {
        lastStepsSignature = signature;
        paintSteps(steps, visualActiveCount);
      }
      scheduleStepAdvance();
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      }[char]));
    }

    function renderHistory(events) {
      latestEvents = events || [];
      if (!events.length) {
        history.innerHTML = `<div class="empty-state">아직 수신된 탐지 결과가 없습니다. 모델이 첫 결과를 보내면 이곳에 표시됩니다.</div>`;
        return;
      }

      history.innerHTML = events.slice(0, 1).map((event) => `
        <article class="history-row ${event.status}">
          <span class="history-dot"></span>
          <div>
            <p class="history-title">${escapeHtml(event.title)}</p>
            <p class="history-message">${escapeHtml(event.message)}</p>
          </div>
          <div class="history-actions">
            <time class="history-time">${escapeHtml(event.time)}</time>
            <button class="detail-open-button" type="button" data-detail-index="0">세부 내용 보기</button>
          </div>
        </article>
      `).join("");
    }

    function openDetail(index = 0) {
      const event = latestEvents[index];
      if (!event) {
        return;
      }

      const detail = event.detail || { summary: "세부 판단 근거를 아직 확인하지 못했습니다.", protocol: "-", rows: [] };
      detailTitle.textContent = `${event.title} 세부 내용`;
      detailSummary.textContent = detail.summary || "가장 최근 판단 기록을 기준으로 표시합니다.";
      detailMeta.innerHTML = `
        <span>수신 시간 ${escapeHtml(event.time || "-")}</span>
      `;

      if (!detail.rows || !detail.rows.length) {
        detailRows.innerHTML = `<div class="empty-state">표시할 세부 근거가 없습니다.</div>`;
      } else {
        detailRows.innerHTML = detail.rows.map((row) => `
          <article class="detail-card ${escapeHtml(row.status || "unknown")}">
            <div>
              <p class="detail-card-title">${escapeHtml(row.title)}</p>
            </div>
            <div class="detail-card-value">
              <span class="detail-badge">${escapeHtml(row.label)}</span>
            </div>
          </article>
        `).join("");
      }

      detailModal.classList.add("open");
      closeDetailButton.focus();
    }

    function closeDetail() {
      detailModal.classList.remove("open");
      const detailButton = history.querySelector(".detail-open-button");
      if (detailButton) {
        detailButton.focus();
      }
    }

    function render(data) {
      modePill.className = `mode-pill ${data.mode}`;
      modeText.textContent = labels[data.mode] || data.mode;
      const statusClass = data.verdict === "idle" ? data.mode : data.verdict;
      heroStatusFill.className = `hero-status-fill ${statusClass}`;
      radar.classList.toggle("active", data.mode === "running" || data.mode === "degraded");

      startButton.disabled = data.mode === "running";
      restartButton.disabled = data.mode === "stopped";
      stopButton.disabled = data.mode === "stopped";

      totalCount.textContent = data.total_count;
      normalCount.textContent = data.normal_count;
      attackCount.textContent = data.attack_count;
      uptime.textContent = data.uptime;

      highlight.className = `highlight ${data.verdict}`;
      highlightText.textContent = data.verdict_label;
      highlightLoader.style.display = data.verdict === "loading" ? "inline-flex" : "none";

      if (data.verdict === "attack") {
        verdictTitle.textContent = "위험 신호가 감지됐어요";
      } else if (data.verdict === "normal") {
        verdictTitle.textContent = "현재 네트워크는 정상이에요 :)";
      } else if (data.verdict === "loading") {
        verdictTitle.textContent = "모델이 측정 중이에요";
      } else {
        verdictTitle.textContent = "보호 시작을 누르세요";
      }
      verdictMessage.textContent = data.verdict_message;

      const errorMessage = data.listener_error || data.last_error;
      showError(errorMessage);
      renderSteps(data.steps, data.mode);
      renderHistory(data.events);
    }

    async function refresh() {
      try {
        const response = await fetch("/api/status");
        if (!response.ok) {
          throw new Error("server unavailable");
        }
        hideServerResult();
        render(await response.json());
      } catch (error) {
        showServerResult();
      }
    }

    startButton.addEventListener("click", () => postAction("/api/start", startButton));
    restartButton.addEventListener("click", () => postAction("/api/restart", restartButton));
    stopButton.addEventListener("click", () => postAction("/api/stop", stopButton));
    reloadPageButton.addEventListener("click", () => window.location.reload());
    themeToggle.addEventListener("click", (event) => {
      event.stopPropagation();
      const isOpen = themeMenu.classList.toggle("open");
      themeToggle.setAttribute("aria-expanded", String(isOpen));
    });

    lightThemeButton.addEventListener("click", () => {
      applyTheme("light");
      closeThemeMenu();
    });

    darkThemeButton.addEventListener("click", () => {
      applyTheme("dark");
      closeThemeMenu();
    });

    function openGuide() {
      guideModal.classList.add("open");
      closeGuideButton.focus();
    }

    function closeGuide() {
      guideModal.classList.remove("open");
      openGuideButton.focus();
    }

    openGuideButton.addEventListener("click", openGuide);
    closeGuideButton.addEventListener("click", closeGuide);
    guideModal.addEventListener("click", (event) => {
      if (event.target === guideModal) {
        closeGuide();
      }
    });
    history.addEventListener("click", (event) => {
      const button = event.target.closest(".detail-open-button");
      if (!button) {
        return;
      }
      openDetail(Number(button.dataset.detailIndex || 0));
    });
    closeDetailButton.addEventListener("click", closeDetail);
    detailModal.addEventListener("click", (event) => {
      if (event.target === detailModal) {
        closeDetail();
      }
    });

    document.addEventListener("click", (event) => {
      if (!themeMenu.contains(event.target)) {
        closeThemeMenu();
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeThemeMenu();
        if (guideModal.classList.contains("open")) {
          closeGuide();
        }
        if (detailModal.classList.contains("open")) {
          closeDetail();
        }
      }
    });

    applyTheme(localStorage.getItem("twinguard-theme-v2") || "dark");
    refresh();
    setInterval(refresh, 900);
  </script>
</body>
</html>
"""


def main():
    global WEB_PORT

    WEB_PORT = find_available_port(WEB_HOST, WEB_PORT)
    if AUTO_START:
        ok, message = start_pipeline()
        if not ok:
            print(f"Failed to start protection mode: {message}")

    browser_url = f"http://127.0.0.1:{WEB_PORT}"
    print(f"TwinGuard UI: {browser_url}")
    open_browser_later(browser_url)
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False, threaded=True)


atexit.register(shutdown)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        shutdown()
