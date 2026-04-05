#!/usr/bin/env python3

import socket
import json
import time
import statistics
import numpy as np
from sklearn.ensemble import IsolationForest

IP = "127.0.0.1"

RECV_PORT = 5002   # extract.py
SEND_PORT = 5003   # ui.py

# Baseline 초기 수집 설정
BASELINE_SECONDS = 10
BASELINE_MIN_SAMPLES = 50

# RSSI 관련 기본값
FALLBACK_RSSI_MIN = -90
FALLBACK_RSSI_MAX = -40

# Isolation Forest 설정
IF_CONTAMINATION = 0.05
IF_N_ESTIMATORS = 100

# 최종 분류 임계값
THRESH_HIGH = 5
THRESH_SUSPICIOUS = 3

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
baseline_feature_vectors = []

prev_RSSI = None
iso_forest_model = None


# ------------------ Feature Vector 생성 ------------------ #

#       → make_feature_vector()는 prev_RSSI를 절대 수정하지 않음
def make_feature_vector(packet: dict, prev_rssi) -> list:
    rssi = packet.get("RSSI", -100)
    rtt = packet.get("RTT", 0.0)
    if not isinstance(rtt, (int, float)):
        rtt = 0.0
    new_bssid = 1 if packet.get("new_BSSID", False) else 0
    protocol_tcp = 1 if packet.get("Protocol") == "TCP" else 0
    rssi_change = abs(rssi - prev_rssi) if prev_rssi is not None else 0.0
    return [rssi, rtt, new_bssid, protocol_tcp, rssi_change]


# ------------------ Baseline 학습 ------------------ #

def update_baseline_samples(packet: dict):
    global prev_RSSI

    rssi = packet.get("RSSI", None)
    if isinstance(rssi, (int, float)):
        baseline_rssi_samples.append(rssi)

    if packet.get("Protocol") == "TCP":
        rtt = packet.get("RTT", 0.0)
        if isinstance(rtt, (int, float)) and rtt > 0:
            baseline_rtt_samples.append(rtt)

    feature_vector = make_feature_vector(packet, prev_RSSI)
    baseline_feature_vectors.append(feature_vector)

    if isinstance(rssi, (int, float)):
        prev_RSSI = rssi


def finalize_baseline():
    global iso_forest_model

    # RSSI 통계
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

    # RTT 통계
    if len(baseline_rtt_samples) >= 5:
        baseline["RTT_mean"] = statistics.mean(baseline_rtt_samples)
    else:
        baseline["RTT_mean"] = None

    baseline["learned"] = True

    # Isolation Forest 학습
    if len(baseline_feature_vectors) >= 10:
        X = np.array(baseline_feature_vectors)
        iso_forest_model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=42
        )
        iso_forest_model.fit(X)

    print("\n=== Baseline Learned ===")
    print(f"RSSI_mean: {baseline['RSSI_mean']:.2f}")
    print(f"RSSI_std : {baseline['RSSI_std']:.2f}")
    print(f"RSSI_min : {baseline['RSSI_min']:.2f}")
    print(f"RSSI_max : {baseline['RSSI_max']:.2f}")
    print(f"RTT_mean : {baseline['RTT_mean']}")
    print(f"IF trained: {iso_forest_model is not None} ({len(baseline_feature_vectors)} samples)")
    print("========================\n")


# ------------------ Rule 기반 스코어 계산 ------------------ #

def calculate_rule_score(packet: dict, prev_rssi) -> tuple[int, list]:
    score = 0
    reasons = []

    # 1) new_BSSID
    if packet.get("new_BSSID", False):
        score += 3
        reasons.append("new_BSSID")

    rssi = packet.get("RSSI", None)
    if isinstance(rssi, (int, float)):
        # 2) RSSI 범위 이상
        if baseline["RSSI_min"] is not None and baseline["RSSI_max"] is not None:
            if rssi < baseline["RSSI_min"] or rssi > baseline["RSSI_max"]:
                score += 2
                reasons.append("RSSI_out_of_range")

        # 3) RSSI 급변 감지
        if prev_rssi is not None and baseline["RSSI_std"] is not None:
            jump_threshold = max(10.0, 1.5 * baseline["RSSI_std"])
            if abs(rssi - prev_rssi) > jump_threshold:
                score += 1
                reasons.append("RSSI_jump")

    # 4) RTT 이상
    if packet.get("Protocol") == "TCP" and baseline["RTT_mean"] is not None:
        rtt = packet.get("RTT", 0.0)
        if isinstance(rtt, (int, float)) and rtt > 0:
            if rtt > 2 * baseline["RTT_mean"] and rtt > 0.05:
                score += 1
                reasons.append("RTT_abnormal")

    return score, reasons


# ------------------ ML 예측 ------------------ #

def calculate_ml_result(packet: dict, prev_rssi) -> tuple[int, float]:
    """
    return:
      ml_flag: 0(normal), 1(anomaly)
      ml_score: decision_function 값 (클수록 정상, 작을수록 이상)
    """
    if iso_forest_model is None:
        return 0, 0.0

    feature_vector = make_feature_vector(packet, prev_rssi)
    X = np.array([feature_vector])

    prediction = iso_forest_model.predict(X)[0]          # 1 or -1
    decision_score = iso_forest_model.decision_function(X)[0]

    ml_flag = 1 if prediction == -1 else 0
    return ml_flag, float(decision_score)


# ------------------ 최종 분류 ------------------ #

def classify_final(rule_score: int, ml_flag: int) -> str:
    ML_WEIGHT = 2
    final_score = rule_score + (ML_WEIGHT if ml_flag == 1 else 0)

    if final_score >= THRESH_HIGH:
        return "HIGH"
    elif final_score >= THRESH_SUSPICIOUS:
        return "SUSPICIOUS"
    else:
        return "NORMAL"


# ------------------ 메인 루프 ------------------ #

def main():
    global prev_RSSI

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

    # -------- Baseline 학습 --------
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

    prev_RSSI = None
    print("Entering detection mode...\n")

    # -------- Detection 모드 --------
    while True:
        data, addr = recv_sock.recvfrom(1024)
        try:
            packet = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            print("[Detect] JSON decode error, skipping...")
            continue

        rule_score, reasons = calculate_rule_score(packet, prev_RSSI)
        ml_flag, ml_score = calculate_ml_result(packet, prev_RSSI)

        if ml_flag == 1:
            reasons.append("IsolationForest_anomaly")

        state = classify_final(rule_score, ml_flag)

        rssi = packet.get("RSSI")
        if isinstance(rssi, (int, float)):
            prev_RSSI = rssi

        result = {
            "status": state,
            "rule_score": rule_score,
            "ml_flag": ml_flag,
            "ml_score": round(ml_score, 4),
            "RSSI": rssi,
            "Protocol": packet.get("Protocol"),
            "new_BSSID": packet.get("new_BSSID"),
            "reasons": reasons,
            "timestamp": time.time()
        }

        try:
            send_sock.sendto(json.dumps(result).encode("utf-8"), (IP, SEND_PORT))
        except Exception as e:
            print(f"[Detect] send error: {e}")

        print(f"[DETECT] {result}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnomalyDetector stopped by user.")