# 🛡️ TwinGuard: Your Personal Wi-Fi Bodyguard

> **"Cafes, Airports, Schools... Is the Wi-Fi you are connected to right now actually safe?"**
>
> **TwinGuard** is a user-friendly security solution designed to detect **Evil Twin attacks** (fake Wi-Fi hotspots) and protect your personal data in real-time.

---

## 1. 동기 (Motivation)

**"Hacking tools are everywhere, but why are defense tools so difficult to use?"**

The **Evil Twin attack**—where a hacker creates a fake Wi-Fi access point to intercept data—is a well-known threat. However, detecting it has traditionally remained in the realm of experts. Average users cannot be expected to open a terminal and analyze network packets manually.

We aimed to bridge this gap by taking a **'User-Friendly'** approach. Our goal was to create a practical application that allows anyone, regardless of technical background, to verify the safety of their surrounding Wi-Fi networks with a single click.

---

## 2.📂 모듈 구조 (Module Arichitecture)
| 단계 | 파일명 | 주요 역할 | 포트 |
| :--- | :--- | :--- | :--- |
| **1** | `PacketCapture.py` | 실시간 패킷 캡처 및 Wi-Fi 정보(RSSI, BSSID 등) 추출 | **5001** |
| **2** | `extract.py` | BSSID 화이트리스트 대조 및 ML용 특징(Feature) 정제 | **5002** |
| **3** | `AnomalyDetector.py` | 실제 공격 탐지 로직 | **5003** |
| **4** | `ui.py` | 메인 실행 코드, 최종 탐지 결과 수신 및 사용자 경고 알림 출력 | - |
| **-** | `SVM.py` / `CreateTrainingData.py` | 오프라인 학습 데이터 생성 및 SVM 모델 훈련 | - |

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
* **한계점:** 현재 버전은 **Evil Twin 공격 탐지**에 특화되어 있습니다. 고도화된 ARP Spoofing과 같이 보다 복잡하고 고도화된 변칙 공격에 대한 대응 로직은 향후 집중 개발 사항으로 진행중입니다.

---

## 5. 주요 고도화 및 집중 개발 사항 (~ing)

이번 프로젝트에서는 기존의 단순한 탐지 방식을 넘어, 실제 환경에서 작동 가능한 지능형 보안 시스템을 구축하기 위해 다음 4가지 사항에 집중하였습니다.

* **머신러닝 알고리즘 적용 (ML Integration)**:
  - 단순 Rule-based 탐지의 한계를 극복하기 위해 **SVM**(지도 학습)을 결합한 하이브리드 탐지 체계를 구축했습니다. 이를 통해 복합적인 네트워크 이상 징후를 지능적으로 판별합니다.

* **정밀한 훈련 데이터셋 생성 (Dataset Engineering)**:
  - 실제 공격 상황을 시뮬레이션하여 **실시간 라벨링(Labeling) 파이프라인**을 구현했습니다. 이를 통해 가짜 AP(Evil Twin)와 정상 AP 접속 데이터를 확보하고, 모델의 탐지 신뢰도를 확보하였습니다.

* **신규 보안 피쳐 발굴 및 적용 (Feature Engineering)**:
  - 단순히 SSID/BSSID만 보는 것이 아니라 **RSSI(신호 강도) 변화량, RTT(응답 속도) 지연 패턴** 등 네트워크 물리 계층의 특징을 신규 피쳐로 도입하여 로밍과 공격 상황의 변별력을 높였습니다. 또한, 대학교 처럼 여러 AP가 있어서 SSID는 같지만 BSSID가 지속적으로 달라지는 상황을 극복할 로직을 구성 중입니다.

* **사용자 중심 UI/UX 개선 (UI Enhancement)**:
  - 백그라운드에서 분석되는 복잡한 보안 수치를 사용자에게 그대로 보여주지 않고, **NORMAL** / **SUSPICIOUS** / **HIGH**의 3단계 위험 등급과 직관적인 징후를 제공하여 비전문가도 손쉽게 사용할 수 있도록 개선 중입니다.
 
---

## 6. 데모 영상
https://www.youtube.com/watch?v=pgGWMVlFoi8&feature=youtu.be
