#!/usr/bin/env python3

import socket
import json
import time
import statistics
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime

IP = "127.0.0.1"

RECV_PORT = 5002   # Preprocessor
SEND_PORT = 5003   # UI

# ------------------ Baseline 설정 ------------------

BASELINE_SECONDS = 10
BASELINE_MIN_SAMPLES = 50

FALLBACK_RSSI_MIN = -90
FALLBACK_RSSI_MAX = -40

# ------------------ Isolation Forest 설정 ------------------

IF_CONTAMINATION = 0.05
IF_N_ESTIMATORS = 100

# ------------------ 최종 분류 기준 ------------------

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


# ------------------ Feature Vector ------------------

def make_feature_vector(packet: dict, prev_rssi):

    protocol_tcp = 1 if packet.get("Protocol") == "TCP" else 0

    rssi = packet.get("RSSI", -100)

    rtt = packet.get("RTT", 0.0)
    if not isinstance(rtt, (int, float)):
        rtt = 0.0

    new_bssid = 1 if packet.get("new_BSSID", False) else 0

    duplicate_mac = 1 if packet.get("is_duplicate_mac", False) else 0

    if prev_rssi is not None:
        rssi_change = abs(rssi - prev_rssi)
    else:
        rssi_change = 0.0

    return [
        protocol_tcp,
        rssi,
        rtt,
        new_bssid,
        duplicate_mac,
        rssi_change
    ]


# ------------------ Baseline 수집 ------------------

def update_baseline_samples(packet: dict):

    global prev_RSSI

    rssi = packet.get("RSSI")

    if isinstance(rssi, (int, float)):
        baseline_rssi_samples.append(rssi)

    if packet.get("Protocol") == "TCP":

        rtt = packet.get("RTT")

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

        std_rssi = statistics.pstdev(baseline_rssi_samples)

        if std_rssi == 0:
            std_rssi = 1.0

        baseline["RSSI_mean"] = mean_rssi
        baseline["RSSI_std"] = std_rssi

        baseline["RSSI_min"] = mean_rssi - 2 * std_rssi
        baseline["RSSI_max"] = mean_rssi + 2 * std_rssi

    else:

        baseline["RSSI_mean"] = (
            FALLBACK_RSSI_MIN + FALLBACK_RSSI_MAX
        ) / 2

        baseline["RSSI_std"] = (
            FALLBACK_RSSI_MAX - FALLBACK_RSSI_MIN
        ) / 4

        baseline["RSSI_min"] = FALLBACK_RSSI_MIN
        baseline["RSSI_max"] = FALLBACK_RSSI_MAX

    # RTT

    if len(baseline_rtt_samples) >= 5:

        baseline["RTT_mean"] = statistics.mean(
            baseline_rtt_samples
        )

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

    print("RSSI_mean:", baseline["RSSI_mean"])
    print("RSSI_std :", baseline["RSSI_std"])
    print("RSSI_min :", baseline["RSSI_min"])
    print("RSSI_max :", baseline["RSSI_max"])
    print("RTT_mean :", baseline["RTT_mean"])

    print(
        "IsolationForest trained:",
        iso_forest_model is not None
    )

    print("========================\n")


# ------------------ Rule Score ------------------

def calculate_rule_score(packet: dict, prev_rssi):

    score = 0

    reasons = []

    # duplicate MAC

    if packet.get("is_duplicate_mac", False):

        score += 4

        reasons.append("duplicate_MAC")

    # new BSSID (warning)

    if packet.get("new_BSSID", False):

        score += 1

        reasons.append("new_BSSID")

    rssi = packet.get("RSSI")

    if isinstance(rssi, (int, float)):

        if (
            baseline["RSSI_min"] is not None
            and baseline["RSSI_max"] is not None
        ):

            if (
                rssi < baseline["RSSI_min"]
                or rssi > baseline["RSSI_max"]
            ):

                score += 2

                reasons.append("RSSI_out_of_range")

        if prev_rssi is not None:

            jump_threshold = max(
                10.0,
                1.5 * baseline["RSSI_std"]
            )

            if abs(rssi - prev_rssi) > jump_threshold:

                score += 1

                reasons.append("RSSI_jump")

    # RTT

    if packet.get("Protocol") == "TCP":

        if baseline["RTT_mean"] is not None:

            rtt = packet.get("RTT")

            if isinstance(rtt, (int, float)):

                if rtt > 2 * baseline["RTT_mean"]:

                    score += 1

                    reasons.append("RTT_abnormal")

    return score, reasons


# ------------------ ML 결과 ------------------

def calculate_ml_result(packet: dict, prev_rssi):

    if iso_forest_model is None:

        return 0, 0.0

    feature_vector = make_feature_vector(
        packet,
        prev_rssi
    )

    X = np.array([feature_vector])

    prediction = iso_forest_model.predict(X)[0]

    decision_score = iso_forest_model.decision_function(
        X
    )[0]

    ml_flag = 1 if prediction == -1 else 0

    return ml_flag, float(decision_score)


# ------------------ Final 판단 ------------------

def classify_final(rule_score, ml_flag):

    ML_WEIGHT = 2

    final_score = rule_score

    if ml_flag == 1:

        final_score += ML_WEIGHT

    if final_score >= THRESH_HIGH:

        return "HIGH"

    elif final_score >= THRESH_SUSPICIOUS:

        return "SUSPICIOUS"

    else:

        return "NORMAL"


# ------------------ Main ------------------

def main():

    global prev_RSSI

    print("TwinGuard Anomaly Detector started.")

    recv_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    recv_sock.bind((IP, RECV_PORT))

    send_sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    start_time = time.time()

    sample_count = 0

    print("\n[Baseline] Learning...")

    # ------------------ Baseline ------------------

    while True:

        data, addr = recv_sock.recvfrom(1024)

        try:

            packet = json.loads(
                data.decode("utf-8")
            )

        except:

            continue

        update_baseline_samples(packet)

        sample_count += 1

        elapsed = time.time() - start_time

        if (
            elapsed >= BASELINE_SECONDS
            and sample_count >= BASELINE_MIN_SAMPLES
        ):

            break

    finalize_baseline()

    prev_RSSI = None

    print("Entering detection mode...\n")

    # ------------------ Detection ------------------

    while True:

        data, addr = recv_sock.recvfrom(1024)

        try:

            packet = json.loads(
                data.decode("utf-8")
            )

        except:

            continue

        rule_score, reasons = calculate_rule_score(
            packet,
            prev_RSSI
        )

        ml_flag, ml_score = calculate_ml_result(
            packet,
            prev_RSSI
        )

        if ml_flag == 1:

            reasons.append(
                "IsolationForest_anomaly"
            )

        state = classify_final(
            rule_score,
            ml_flag
        )

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

            "duplicate_MAC": packet.get(
                "is_duplicate_mac"
            ),

            "reasons": reasons,

            "timestamp": datetime.now().strftime(
                "%H:%M:%S"
            )

        }

        try:

            send_sock.sendto(
                json.dumps(result).encode("utf-8"),
                (IP, SEND_PORT)
            )

        except Exception as e:

            print("Send error:", e)

        print(result)


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("Stopped by user")