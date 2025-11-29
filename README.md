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

* **get_wifi_context()**: CoreLocation 권한 요청 후 CoreWLAN으로 RSSI, BSSID, SSID 등 Wi-Fi 환경 정보를 수집합니다.
* **capture_and_merge()**: Pyshark로 실시간 IP 패킷을 캡처하고, 캡처된 모든 패킷에 Wi-Fi 정보를 병합하여 데이터셋을 완성합니다.
* **if __name__ == "__main__":**: 두 함수를 호출하여 데이터를 수집하고, 최종적으로 JSON 파일로 저장합니다. **(실행 시 반드시 sudo 권한 필요)**

---

## 4. 추출 데이터 필드 정의
(예시)
        "id": 5,
        "timestamp": 1764422058.941997,
        "protocol": "TCP",
        "length": 54,
        "src_ip": "51.116.253.170",
        "dst_ip": "192.168.0.33",
        "src_mac": "70:5d:cc:9d:cb:53",
        "dst_mac": "5c:b4:7e:17:9d:8c",
        "src_port": 443,
        "dst_port": 62517,
        "tcp_flags": "0x0010",
        "i_rtt": 0.268209,
        "ack_rtt": 0.218069,
        "dns_query": "N/A"
* **ssid**: Wi-Fi 네트워크 이름.
* **bssid**: AP의 MAC 주소 (AP 고유 식별자).
* **rssi**: 수신 신호 강도 (AP의 세기).
* **frame_number**: 캡처된 패킷의 순서 번호.
* **packet_timestamp**: 패킷이 캡처된 시간 (유닉스 타임스탬프).
* **src_ip / dst_ip**: 출발지 및 목적지 IP 주소.
* **src_port / dst_port**: 출발지 및 목적지 포트 번호.
* **protocol_type**: IP 레이어의 프로토콜 번호 (예: 6=TCP, 17=UDP).
* **protocol**: 상위 프로토콜 이름 (TCP, UDP, DNS 등).
* **tcp_flags**: TCP 통신 상태 플래그 (SYN, ACK, PSH 등의 상태).
* **i_rtt_sec**: Initial RTT (초기 왕복 시간).
* **rtt_continuous_sec**: 연속 RTT (연결 유지 중 왕복 시간).
* **dns_query**: DNS 서버에 요청한 웹 도메인 주소.
* **tls_version**: TLS/SSL 암호화 버전.
* **(dns_query와 tls_version은 보통 N/A로 나오는데, 값이 한번이라도 나오면 분석해볼 필요가 있는 패킷일 것으로 예상됨).**
---

## 5. 예상 공격 탐지 기준 (출처:Gemini)

* **BSSID:** 동일 SSID에 대해 평소와 다른 BSSID가 관찰될 때.
    [공격 시나리오] Evil Twin 확정. 가장 확실한 공격 징후입니다.
* **RSSI:** 평소보다 비정상적으로 강한 신호 (예: -20 dBm에 가까운 값).
    [공격 시나리오] 유인 공격. 공격자가 사용자를 가짜 AP로 유인하는 행위입니다.
* **i_rtt_sec / rtt_continuous_sec:** 평소 평균 RTT보다 3배 이상 높은 값 (예: 평소 20ms인데 갑자기 100ms 이상).
    [공격 시나리오] 성능 저하 징후. 악성 AP에 연결되었거나 트래픽 감시로 지연이 유발됩니다.
* **DST_IP:** DNS 쿼리에 대한 응답 IP가 평소 DNS 서버가 아닌 사설 IP 또는 알 수 없는 외부 IP일 때.
    [공격 시나리오] DNS 하이재킹. 공격자가 가짜 응답을 보내 피싱 사이트로 유도합니다.
* **TCP_FLAGS:** 연결 수립/종료 없이 RST (강제 종료) 플래그가 반복적으로 관찰될 때.
    [공격 시나리오] 연결 끊김 유도 또는 포트 스캐닝.
