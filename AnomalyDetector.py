#!/bin/python3

import socket
import json
import time

# 데이터포트
IP = "127.0.0.1"
RECV_PORT = 5002
SEND_PORT = 5003  # ui.py 로 결과 보내기

# 초기버전
baseline = {
    "RSSI_min": -90,
    "RSSI_max": -40,
    "prev_RSSI": None,
    "BSSID_list": []
}

def calculate_score(data):
    score = 0

    # 1. BSSID
    if data.get("new_BSSID", False):
        score += 3

    # 2. RSSI 이상치
    RSSI = data.get("RSSI", -100)

    # 평균 범위 벗어나면 1점
    if RSSI < baseline["RSSI_min"] or RSSI > baseline["RSSI_max"]:
        score += 1

    # 3. RSSI 이전값 기준 급변 감지
    if baseline["prev_RSSI"] is not None:
        if abs(RSSI - baseline["prev_RSSI"]) > 15:
            score += 2

    baseline["prev_RSSI"] = RSSI

    # 4. RTT (TCP 한정)
    if data.get("Protocol") == "TCP":
        rtt = data.get("RTT", 0)
        if rtt > 0.1:  # 대부분 0이므로 거의 안 쓰지만 구조만 포함
            score += 1

    return score


def classify(score):
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "SUSPICIOUS"
    else:
        return "NORMAL"


def main():
    print("Anomaly Detector Running...")

    # 소켓 준비
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    recv_sock.bind((IP, RECV_PORT))

    while True:
        data, addr = recv_sock.recvfrom(1024)
        parsed = json.loads(data.decode("utf-8"))

        score = calculate_score(parsed)
        state = classify(score)

        result = {
            "status": state,
            "score": score,
            "RSSI": parsed.get("RSSI"),
            "new_BSSID": parsed.get("new_BSSID"),
            "Protocol": parsed.get("Protocol")
        }

        # ui로 전송
        send_sock.sendto(json.dumps(result).encode("utf-8"), (IP, SEND_PORT))

        print(f"[DETECT] {result}")


if __name__ == "__main__":
    main()
