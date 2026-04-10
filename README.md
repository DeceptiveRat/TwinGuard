# 🛡️ TwinGuard: Your Personal Wi-Fi Bodyguard

> **"Cafes, Airports, Schools... Is the Wi-Fi you are connected to right now actually safe?"**
>
> **TwinGuard** is a user-friendly, Windows-based security solution designed to detect **Evil Twin attacks** (fake Wi-Fi hotspots) and protect your personal data in real-time.

---

## 1. 동기 (Motivation)

**"Hacking tools are everywhere, but why are defense tools so difficult to use?"**

The **Evil Twin attack**—where a hacker creates a fake Wi-Fi access point to intercept data—is a well-known threat. However, detecting it has traditionally remained in the realm of experts. Average users cannot be expected to open a terminal and analyze network packets manually.

We aimed to bridge this gap by taking a **'User-Friendly'** approach. Our goal was to create a practical application that allows anyone, regardless of technical background, to verify the safety of their surrounding Wi-Fi networks with a single click.

---

## 2.📂 Module Descriptions

| 단계 | 파일명 | 주요 역할 | 포트 |
| :--- | : :--- | :--- | :--- |
| 1 | PacketCapture.py | 실시간 패킷 캡처 및 Wi-Fi 정보(RSSI, BSSID 등) 추출 | 5001 |
| 2 | extract.py* | BSSID 화이트리스트 대조 및 ML용 피쳐(Feature) 정제 | 5002 |
| 3 | AnomalyDetector.py | Baseline 학습, Rule 기반 스코어링 및 Isolation Forest 탐지 | 5003 |
| 4 | ui.py | 최종 탐지 결과 수신 및 사용자 경고 알림 출력 | - |
| - | SVM.py / CreateTrainingData.py | 오프라인 학습 데이터 생성 및 SVM 모델 훈련 | - |
### 1. PacketCapture.py (Data Collection)
* `Pyshark`를 이용해 공중의 무선 패킷을 실시간으로 스니핑합니다.
* 현재 연결된 AP의 SSID, BSSID, RSSI 정보와 패킷별 RTT 정보를 추출하여 **Port 5001**로 전송합니다.

### 2. CreateTrainingData.py (Data Labeling)
* 머신러닝 학습을 위한 **정답지(Label)**를 생성하는 모듈입니다.
* 특정 공격자 BSSID를 기준으로 `is_attack` 플래그(0 또는 1)를 부여하여 `packets.log`를 생성합니다.

### 3. SVM.py (Off-line Learning)
* 수집된 로그 데이터를 바탕으로 **SVM(Support Vector Machine)** 모델을 학습시킵니다.
* RSSI, RTT, Protocol, new_BSSID 등의 특징점 간 상관관계를 분석하여 공격과 정상을 가르는 최적의 경계선을 형성합니다.

### 4. AnomalyDetector.py (Intelligence Engine)
* **Hybrid Detection 기술**이 집약된 핵심 엔진입니다.
    * **Baseline Learning**: 실행 초기 10초간의 네트워크 환경을 정상으로 학습합니다.
    * **Rule-based Score**: RSSI 급변, 신규 BSSID 등장 시 벌점을 부여합니다.
    * **Isolation Forest**: 통계적으로 튀는 이상 데이터를 실시간으로 감지합니다.
* 합산된 위험도를 바탕으로 `NORMAL`, `SUSPICIOUS`, `HIGH` 등급을 **Port 5003**으로 보냅니다.

### 5. ui.py (Control Tower)
* 모든 서브 프로세스(`Capture`, `Preprocessor`, `Detector`)를 관리하는 **통합 실행기**입니다.
* 탐지된 위험 등급에 따라 "가짜 Wi-Fi 감지" 등 직관적인 경고 메시지와 대응 가이드를 사용자에게 출력합니다.

---

## 3. 필수 준비 사항 (Prerequisites)
### 💻 Prerequisites

1.  **Python 3.x**
    * 설치 시 **`Add Python to PATH`** 옵션을 반드시 체크해야 합니다.

2.  **Wireshark (TShark 포함)**
    * **Wireshark**를 설치할 때, 패킷 캡처 엔진인 **TShark**와 **Npcap**이 함께 설치되도록 옵션을 체크해야 합니다. (TwinGuard는 `pyshark`를 통해 TShark 엔진을 사용합니다.)

### Python 라이브러리 설치

터미널을 열고 다음 명령어를 실행하면 됩니다.(vscode 에서 하는 것을 추천)

```bash
pip install pyshark
```

---

## 4. 테스트 결과 및 현황 (Results & Current Status)

* **실험:**  **ESP32 모듈**을 사용하여 가짜 Wi-Fi 환경을 구축했습니다. 프로그램은 이 환경에서 정상 AP와 가짜 AP를 명확히 구분하고 사용자에게 **적절한 위험 경고**를 표시하는 것을 확인했습니다.
* **최적화:** 현재 실시간 패킷 분석 파이프라인(Capture, Preprocessor, Detector)은 완성되었으나, 코드 최적화를 한 것은 아닙니다.
* **한계점:** 현재 버전은 **Evil Twin 공격 탐지**에 특화되어 있습니다. 고도화된 ARP Spoofing과 같이 보다 복잡하고 고도화된 변칙 공격에 대한 대응 로직은 향후 연구 과제로 남아 있습니다.

---

## 5. 향후 연구 및 발전 방향 (Future Roadmap)

* **AI-Based Detection (탐지 고도화):** 현재의 규칙 기반(Rule-based) 탐지를 넘어, 사용자의 평소 네트워크 패턴을 학습하는 **딥러닝 모델**을 도입하여 미세한 변칙 공격까지 탐지.
* **Mobile App Expansion (모바일 확장):** 노트북뿐만 아니라 스마트폰에서도 백그라운드에서 작동하며 공공 Wi-Fi 연결 시 자동으로 안전을 진단하는 앱을 개발.
* **Automated Defense System (자동 방어 시스템):** 위험(HIGH) 단계가 감지되면 사용자 개입 없이 **즉시 Wi-Fi 연결을 강제로 차단**하여 데이터 유출을 원천 봉쇄하는 기능 추가.

## 6. 소개 영상
https://www.youtube.com/watch?v=pgGWMVlFoi8&feature=youtu.be
