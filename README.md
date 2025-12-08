# 🛡️ TwinGuard: Your Personal Wi-Fi Bodyguard

> **"Cafes, Airports, Schools... Is the Wi-Fi you are connected to right now actually safe?"**
>
> **TwinGuard** is a user-friendly, Windows-based security solution designed to detect **Evil Twin attacks** (fake Wi-Fi hotspots) and protect your personal data in real-time.

---

## 1. 💡 Motivation

**"Hacking tools are everywhere, but why are defense tools so difficult to use?"**

The **Evil Twin attack**—where a hacker creates a fake Wi-Fi access point to intercept data—is a well-known threat. However, detecting it has traditionally remained in the realm of experts. Average users cannot be expected to open a terminal and analyze network packets manually.

We aimed to bridge this gap by taking a **'User-Friendly'** approach. Our goal was to create a practical application that allows anyone, regardless of technical background, to verify the safety of their surrounding Wi-Fi networks with a single click.

---

## 2. 🏗️ Workflow & Architecture
TwinGuard visualizes invisible network threats through a **3-stage pipeline**. It captures packets, analyzes them for anomalies, and alerts the user.

## 단계,역할 모듈,주요 작동 내용
1. 데이터 수집,Collector (PacketCapture.py),"**실시간 패킷(TCP/UDP)**을 캡처하고, 현재 연결된 AP의 **물리 주소(BSSID)**와 신호 강도(RSSI) 정보를 1개씩 추출하여 Port 5001로 전송합니다."
2. 특징 추출 및 분석,Preprocessor (extract.py),"Port 5001에서 데이터를 수신합니다. 수신된 패킷의 BSSID를 **기존 데이터베이스(SSID.json)**와 비교하여 BSSID 변경 유무를 확인하고, 점수 계산에 필요한 핵심 특징(RSSI, BSSID 변경 플래그)을 Port 5002로 전달합니다."
3. 위험도 탐지,Detector (AnomalyDetector.py),"Port 5002에서 분석 데이터를 수신합니다. 학습된 **정상 범위(Baseline)**를 기준으로 RSSI, RTT, BSSID 변경 등의 항목에 **벌점(Score)**을 매기고, 위험 등급(NORMAL, SUSPICIOUS, HIGH)을 결정하여 Port 5003으로 보냅니다."
4. 결과 표시,UI (win_ui.py),Port 5003에서 최종 탐지 결과를 수신하여 사용자에게 실시간으로 출력합니다.

---

## 3. ⚙️ 필수 준비 사항 (Prerequisites)
### 💻 필수 설치 도구

1.  **Python 3.x**
    * 설치 시 **`Add Python to PATH`** 옵션을 반드시 체크해야 합니다.

2.  **Wireshark (TShark 포함)**
    * **Wireshark**를 설치할 때, 패킷 캡처 엔진인 **TShark**와 **Npcap**이 함께 설치되도록 옵션을 체크해야 합니다. (TwinGuard는 `pyshark`를 통해 TShark 엔진을 사용합니다.)

### 📥 Python 라이브러리 설치

터미널을 열고 다음 명령어를 실행하여 필수 라이브러리를 설치합니다.

```bash
pip install pyshark
