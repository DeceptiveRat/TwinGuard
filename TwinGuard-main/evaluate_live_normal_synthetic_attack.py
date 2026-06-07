import argparse
import json
import os
import random
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


BASE_DIR = Path(__file__).resolve().parent
IP = "127.0.0.1"
FEATURE_PORT = 5002
MODEL_PATH = BASE_DIR / "evil_twin_detector.pkl"
SCALER_PATH = BASE_DIR / "feature_scaler.pkl"
SSID_CACHE = BASE_DIR / "SSID.json"


def subprocess_kwargs(log_file):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    kwargs = {
        "stdout": log_file,
        "stderr": log_file,
        "stdin": subprocess.DEVNULL,
        "cwd": str(BASE_DIR),
        "env": env,
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


def backup_ssid_cache():
    if not SSID_CACHE.exists():
        return None
    backup = BASE_DIR / f"SSID.eval_backup.{int(time.time())}.json"
    SSID_CACHE.replace(backup)
    return backup


def restore_ssid_cache(backup):
    try:
        if SSID_CACHE.exists():
            SSID_CACHE.unlink()
        if backup is not None and backup.exists():
            backup.replace(SSID_CACHE)
    except OSError:
        pass


def collect_live_normal_samples(count, interface, timeout_seconds, isolate_ssid_cache=True):
    samples = []
    backup = backup_ssid_cache() if isolate_ssid_cache else None
    preprocessor = None
    capturer = None
    logs = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    try:
        sock.bind((IP, FEATURE_PORT))

        pre_log = open(BASE_DIR / "eval_preprocessor.log", "w", encoding="utf-8")
        cap_log = open(BASE_DIR / "eval_capturer.log", "w", encoding="utf-8")
        logs.extend([pre_log, cap_log])

        preprocessor = subprocess.Popen(
            [sys.executable, "-u", "Preprocessor.py"],
            **subprocess_kwargs(pre_log),
        )
        time.sleep(0.8)
        capturer = subprocess.Popen(
            [sys.executable, "-u", "PacketCapture.py", "-i", interface],
            **subprocess_kwargs(cap_log),
        )

        started_at = time.time()
        print(f"Collecting {count} live normal samples from interface '{interface}'...")

        while len(samples) < count and time.time() - started_at < timeout_seconds:
            if preprocessor.poll() is not None:
                raise RuntimeError("Preprocessor.py exited early. Check eval_preprocessor.log.")
            if capturer.poll() is not None:
                raise RuntimeError("PacketCapture.py exited early. Check eval_capturer.log.")

            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue

            try:
                parsed = json.loads(data.decode("utf-8", errors="replace").strip())
            except json.JSONDecodeError:
                continue

            if not all(key in parsed for key in ("Protocol", "RSSI", "RTT", "new_BSSID")):
                continue

            samples.append(
                {
                    "Protocol": parsed["Protocol"],
                    "RSSI": parsed["RSSI"],
                    "RTT": parsed["RTT"],
                    "new_BSSID": parsed["new_BSSID"],
                    "is_attack": 0,
                    "scenario": "live_normal",
                }
            )

            if len(samples) % 25 == 0 or len(samples) == count:
                print(f"  collected {len(samples)}/{count}")

    finally:
        stop_process(capturer)
        stop_process(preprocessor)
        sock.close()
        for log_file in logs:
            try:
                log_file.close()
            except Exception:
                pass
        if isolate_ssid_cache:
            restore_ssid_cache(backup)

    if len(samples) < count:
        raise RuntimeError(
            f"Only collected {len(samples)}/{count} live normal samples within {timeout_seconds}s."
        )

    return samples


def tcp_attack_sample(rng, rssi_range, rtt_range, scenario):
    return {
        "Protocol": "TCP",
        "RSSI": round(rng.uniform(*rssi_range), 2),
        "RTT": round(rng.uniform(*rtt_range), 6),
        "new_BSSID": True,
        "is_attack": 1,
        "scenario": scenario,
    }


def udp_attack_sample(rng, rssi_range, scenario):
    return {
        "Protocol": "UDP",
        "RSSI": round(rng.uniform(*rssi_range), 2),
        "RTT": -1.0,
        "new_BSSID": True,
        "is_attack": 1,
        "scenario": scenario,
    }


def build_synthetic_attack_samples(count, seed):
    rng = random.Random(seed)
    rows = []
    clear_count = int(count * 2 / 3)
    ambiguous_count = count - clear_count

    clear_tcp = int(clear_count * 0.8)
    clear_udp = clear_count - clear_tcp
    ambiguous_tcp = int(ambiguous_count * 0.8)
    ambiguous_udp = ambiguous_count - ambiguous_tcp

    for _ in range(clear_tcp):
        rows.append(tcp_attack_sample(rng, (-95, -80), (0.3, 1.2), "synthetic_attack_clear"))
    for _ in range(clear_udp):
        rows.append(udp_attack_sample(rng, (-95, -80), "synthetic_attack_clear"))
    for _ in range(ambiguous_tcp):
        rows.append(tcp_attack_sample(rng, (-78, -65), (0.1, 0.3), "synthetic_attack_ambiguous"))
    for _ in range(ambiguous_udp):
        rows.append(udp_attack_sample(rng, (-78, -65), "synthetic_attack_ambiguous"))

    rng.shuffle(rows)
    return rows


def preprocess_like_deploy(df):
    prepared = df.copy()
    protocol_map = {"UDP": 0, "TCP": 1}
    prepared["Protocol"] = prepared["Protocol"].map(protocol_map)
    prepared["new_BSSID"] = prepared["new_BSSID"].astype(int)
    return prepared[["Protocol", "RSSI", "new_BSSID", "RTT"]]


def evaluate(df):
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    x = preprocess_like_deploy(df)
    y_true = df["is_attack"]
    y_pred = model.predict(scaler.transform(x))

    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    print()
    print("Live Normal + Synthetic Attack Evaluation")
    print("=" * 48)
    print(f"Dataset size: {len(df)}")
    print("Normal label: 0")
    print("Attack label: 1")
    print()
    print("Dataset composition")
    print(df.groupby(["scenario", "is_attack"]).size().to_string())
    print()
    print("Confusion Matrix")
    print("Rows = actual, columns = predicted")
    print("Labels: [0 Normal, 1 Evil Twin]")
    print(matrix)
    print()
    print(f"TN(normal->normal): {tn}")
    print(f"FP(normal->attack): {fp}")
    print(f"FN(attack->normal): {fn}")
    print(f"TP(attack->attack): {tp}")
    print()
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print()
    print("Classification Report")
    print(classification_report(y_true, y_pred, labels=[0, 1], target_names=["Normal", "Evil Twin"]))
    print("Scenario Accuracy")
    result_df = df.copy()
    result_df["predicted"] = y_pred
    result_df["correct"] = result_df["is_attack"] == result_df["predicted"]
    for scenario, score in result_df.groupby("scenario")["correct"].mean().sort_index().items():
        print(f"{scenario}: {score:.4f}")


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate TwinGuard with live captured normal samples and synthetic attack samples."
    )
    parser.add_argument("--normal-count", type=int, default=150)
    parser.add_argument("--attack-count", type=int, default=150)
    parser.add_argument("--interface", default="Wi-Fi")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--keep-ssid-cache",
        action="store_true",
        help="Do not isolate SSID.json during normal-data collection.",
    )
    args = parser.parse_args()

    normal_rows = collect_live_normal_samples(
        count=args.normal_count,
        interface=args.interface,
        timeout_seconds=args.timeout,
        isolate_ssid_cache=not args.keep_ssid_cache,
    )
    attack_rows = build_synthetic_attack_samples(args.attack_count, args.seed)

    df = pd.DataFrame(normal_rows + attack_rows)
    evaluate(df)


if __name__ == "__main__":
    main()
