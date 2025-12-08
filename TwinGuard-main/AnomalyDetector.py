#!/usr/bin/env python3

import socket
import json
import time
import statistics

IP = "127.0.0.1"

RECV_PORT = 5002   # extract.py
SEND_PORT = 5003   # ui.py

# Baseline 초기 수집 설정
BASELINE_SECONDS = 10          # 최소 학습 시간
BASELINE_MIN_SAMPLES = 50      # 최소 학습 샘플 수

# RSSI 관련 기본값
FALLBACK_RSSI_MIN = -90
FALLBACK_RSSI_MAX = -40

baseline = {
    "RSSI_mean": None,
    "RSSI_std": None,
    "RSSI_min": None,
    "RSSI_max": None,
    "RTT_mean": None,
    "learned": False
}

baseline_rssi_samples = []
baseline_rtt_samples = []

prev_RSSI = None  # 직전 패킷의 RSSI (RSSI 급변 감지용)


# ------------------ Baseline 학습 ------------------ #

def update_baseline_samples(packet: dict):
    rssi = packet.get("RSSI", None)
    if isinstance(rssi, (int, float)):
        baseline_rssi_samples.append(rssi)

    # TCP 이고 RTT가 유효할 때
    if packet.get("Protocol") == "TCP":
        rtt = packet.get("RTT", 0.0)
        if isinstance(rtt, (int, float)) and rtt > 0:
            baseline_rtt_samples.append(rtt)


def finalize_baseline():
    # RSSI
    if len(baseline_rssi_samples) >= 5:
        mean_rssi = statistics.mean(baseline_rssi_samples)
        std_rssi = statistics.pstdev(baseline_rssi_samples) or 1.0

        baseline["RSSI_mean"] = mean_rssi
        baseline["RSSI_std"] = std_rssi
        baseline["RSSI_min"] = mean_rssi - 2 * std_rssi
        baseline["RSSI_max"] = mean_rssi + 2 * std_rssi
    else:
        baseline["RSSI_mean"] = (FALLBACK_RSSI_MIN + FALLBACK_RSSI_MAX) / 2
        baseline["RSSI_std"] = (FALLBACK_RSSI_MAX - FALLBACK_RSSI_MIN) / 4
        baseline["RSSI_min"] = FALLBACK_RSSI_MIN
        baseline["RSSI_max"] = FALLBACK_RSSI_MAX

    # RTT
    if len(baseline_rtt_samples) >= 5:
        baseline["RTT_mean"] = statistics.mean(baseline_rtt_samples)
    else:
        baseline["RTT_mean"] = None

    baseline["learned"] = True

    print("\n=== Baseline Learned ===")
    print(f"RSSI_mean: {baseline['RSSI_mean']:.2f}")
    print(f"RSSI_std : {baseline['RSSI_std']:.2f}")
    print(f"RSSI_min : {baseline['RSSI_min']:.2f}")
    print(f"RSSI_max : {baseline['RSSI_max']:.2f}")
    print(f"RTT_mean : {baseline['RTT_mean']}")
    print("========================\n")


# ------------------ 스코어 계산 ------------------ #

def calculate_score(packet: dict) -> int:
    global prev_RSSI

    score = 0

    # 1) new_BSSID
    if packet.get("new_BSSID", False):
        score += 3

    # 2) RSSI 범위 이상
    rssi = packet.get("RSSI", None)
    if isinstance(rssi, (int, float)):
        if baseline["RSSI_min"] is not None and baseline["RSSI_max"] is not None:
            if rssi < baseline["RSSI_min"] or rssi > baseline["RSSI_max"]:
                score += 2

        # 3) RSSI 급변 감지
        if prev_RSSI is not None and baseline["RSSI_std"] is not None:
            # 기준: max(10, 1.5 * std)
            jump_threshold = max(10.0, 1.5 * baseline["RSSI_std"])
            if abs(rssi - prev_RSSI) > jump_threshold:
                score += 1

        prev_RSSI = rssi

    # 4) RTT 이상
    if packet.get("Protocol") == "TCP" and baseline["RTT_mean"] is not None:
        rtt = packet.get("RTT", 0.0)
        if isinstance(rtt, (int, float)) and rtt > 0:
            # RTT가 평균의 2배 이상이면서 어느 정도 이상이면 이상치로 가정
            if rtt > 2 * baseline["RTT_mean"] and rtt > 0.05:
                score += 1

    return score


def classify(score: int) -> str:
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "SUSPICIOUS"
    else:
        return "NORMAL"


# ------------------ 메인 루프 ------------------ #

def main():
    print("TwinGuard Anomaly Detector started.")
    print(f"Listening on {IP}:{RECV_PORT}, sending results to {SEND_PORT}...")

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((IP, RECV_PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    start_time = time.time()
    sample_count = 0

    print(f"\n[Baseline] Learning for at least {BASELINE_SECONDS} seconds "
          f"and {BASELINE_MIN_SAMPLES} samples...")
    print("[Baseline] Assuming current environment is NORMAL.\n")

    while True:
        data, addr = recv_sock.recvfrom(1024)
        try:
            packet = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            print("[Baseline] JSON decode error, skipping...")
            continue

        update_baseline_samples(packet)
        sample_count += 1

        elapsed = time.time() - start_time
        if elapsed >= BASELINE_SECONDS and sample_count >= BASELINE_MIN_SAMPLES:
            break

    finalize_baseline()

    print("Entering detection mode...\n")

    while True:
        data, addr = recv_sock.recvfrom(1024)
        try:
            packet = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            print("[Detect] JSON decode error, skipping...")
            continue

        score = calculate_score(packet)
        state = classify(score)

        result = {
            "status": state,
            "score": score,
            "RSSI": packet.get("RSSI"),
            "Protocol": packet.get("Protocol"),
            "new_BSSID": packet.get("new_BSSID"),
            "timestamp": time.time()
        }

        # 결과 전송
        try:
            send_sock.sendto(json.dumps(result).encode("utf-8"),
                             (IP, SEND_PORT))
        except Exception as e:
            print(f"[Detect] send error: {e}")

        print(f"[DETECT] {result}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnomalyDetector stopped by user.")
