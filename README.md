# TwinGuard
# 🛡️ Evil Twin 공격 탐지 및 데이터 수집 자동화 시스템

## 1. 프로젝트 개요 및 목표

* **주제:** 지능형 무선 네트워크 위협 탐지 자동화 시스템 설계
* **목표:** 사용자 데이터 보호를 위한 Evil Twin Attack 실시간 감지 및 방어 데이터셋 구축.

---

## 2. 필수 라이브러리 및 설치 (VScode와 python, pip 등은 기본적으로 깔려있다고 가정하겠습니다) 

* **1.WireShark:** 인터넷에서 다운해야됨 -> 여기에서 Tshark(터미널 기반 패킷 처리)가 자연스럽게 다운받아짐 
* **2.Pyshark:** python에서 사용하는 패킷 캡처 및 분석 라이브러리(Tshark에서 가져오는 데이터) vscode 터미널에서- pip install pyshark

---

## 3. 코드 구조 및 역할


---

## 4. 추출 데이터 필드 정의

* **id**: 패킷 넘버 
* **rssi**: 수신 신호 강도 (AP의 세기).
* **timestamp**: 패킷이 캡처된 시간.
*  **protocol**:프로토콜 타입(TCP, UDP)
* **src_ip / dst_ip**:
* **src_mac / dst_mac**:
* * **src_port / dst_port**:
* **tcp_flags**: TCP 통신 상태 플래그 (SYN, ACK, PSH 등의 상태).
* **i_rtt_sec**: Initial RTT (초기 왕복 시간).
* **rtt_continuous_sec**: 연속 RTT (연결 유지 중 왕복 시간).
* **dns_query**: DNS 서버에 요청한 웹 도메인 주소.
---

## 5. 예상 공격 탐지 기준 (출처:Gemini)
