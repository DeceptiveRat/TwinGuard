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
| 함수/모듈 | 역할 및 기능 |
| :--- | :--- |
| **`get_wifi_info()`** | Windows `netsh` 명령어를 실행하여 현재 연결된 AP의 **SSID, BSSID, RSSI(신호 강도)**를 실시간으로 파싱합니다. (CP949 인코딩 처리 포함) |
| **`capture_and_merge()`** | **Pyshark**를 이용해 패킷을 실시간 캡처하고, Wi-Fi 환경 정보와 패킷별 상세 데이터(RTT, TCP Flags, DNS Query 등)를 병합합니다. |
| **`send_to_socket()`** | 수집된 패킷 데이터를 **JSON 포맷**으로 직렬화하여 로컬 소켓(`127.0.0.1:5001`)을 통해 분석 서버(AI 모델)로 전송합니다. |
| **`Asyncio Fix`** | Python 3.11+ 및 Windows 환경에서 발생하는 `Pyshark`의 비동기 이벤트 루프 오류(`RuntimeError`)를 방지하는 호환성 코드가 포함되어 있습니다. |

### 작동 프로세스 (Operational Logic)

1.  **초기화 (Initialization):** Windows 비동기 루프 정책 설정 및 사용자 로컬 디바이스 정보(IP/MAC)를 식별합니다.
2.  **컨텍스트 수집 (Context Awareness):** 주기적으로 `netsh`를 호출하여 현재 AP의 물리적 상태(RSSI, BSSID)를 갱신합니다.
3.  **패킷 캡처 및 배치 (Batch Capture):** * TCP/UDP 패킷을 실시간으로 감지합니다.
    * **5개의 패킷**이 모일 때까지 메모리에 버퍼링합니다.
4.  **데이터 병합 (Data Merging):** * 각 패킷에 `i_rtt`, `ack_rtt`, `tcp_flags` 등의 보안 Feature를 추출하여 매핑합니다.
    * UDP 패킷의 경우 RTT 값을 `-1.0`으로 마킹하여 데이터 정합성을 유지합니다.
5.  **전송 및 저장 (Export):**
    * 완성된 배치를 `Packet_data.json` 파일로 저장(백업)합니다.
    * 동시에 소켓을 통해 실시간 분석 엔진으로 데이터를 전송합니다.

---

## 4. 추출 데이터 필드 정의

* **id**: 패킷 넘버
* **timestamp**: 패킷이 캡처된 시간.
* 
*  **protocol**:프로토콜 타입(TCP, UDP)
*  **ap_rssi**: 수신 신호 강도 (AP의 세기).
*  **ap_bssid**: AP의 MAC 주소
* **src_ip / dst_ip**:
* **src_mac / dst_mac**:
* * **src_port / dst_port**:
* **tcp_flags**: TCP 통신 상태 플래그 (ACK(0x0010):수신 확인, SYN(0x0002):새로운 TCP연결 시작, FIN(0x0001):연결 정상 종료)
* **i_rtt_sec**: Initial RTT (초기 왕복 시간, 최초 TCP통신 handshake에서만 있어서 보통 0일것임).
* **rtt_continuous_sec**: 연속 RTT (연결 유지 중 왕복 시간).
* **dns_query**: DNS 서버에 요청한 웹 도메인 주소. (실제로 뜸 ex:"mobile.events.data.microsoft.com")
---
