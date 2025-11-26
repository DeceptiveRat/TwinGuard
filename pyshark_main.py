import time
import sys
import json
import os
from datetime import datetime
import pyshark

# macOS Native Libraries (PyObjC) - 설치가 되어 있어야 작동합니다.
from CoreWLAN import CWWiFiClient
from CoreLocation import CLLocationManager

# --- 설정 ---
INTERFACE = 'en0'       # 캡처할 인터페이스 (맥북 기본 와이파이)
PACKET_COUNT = 30       # 수집할 패킷 수
OUTPUT_FILE = 'evil_twin_dataset.json' # 저장할 최종 파일명
MAX_WAIT = 10           # 위치 권한 대기 시간(초)

def get_wifi_context():
    """
    CoreLocation으로 권한을 획득하고, CoreWLAN으로 정확한 Wi-Fi 정보를 가져옵니다.
    """
    wifi_data = {
        "ssid": "Unknown",
        "bssid": "Unknown",
        "rssi": None, 
        "wifi_status": "ERROR_INIT"
    }

    try:
        # 1. 권한 요청 (팝업 발생 유도)
        location_manager = CLLocationManager.alloc().init()
        location_manager.requestWhenInUseAuthorization()
        location_manager.startUpdatingLocation() # 위치 정보 업데이트 시작

        # 2. Wi-Fi 정보 추출
        client = CWWiFiClient.sharedWiFiClient()
        iface = client.interface()

        if iface:
            # 3. 정보 추출 (권한이 부여되어야 SSID/BSSID가 나옵니다)
            wifi_data["ssid"] = iface.ssid() or "Hidden"
            wifi_data["bssid"] = iface.bssid() or "None"
            wifi_data["rssi"] = int(iface.rssiValue())
            wifi_data["wifi_status"] = "OK"
        else:
            wifi_data["wifi_status"] = "ERROR_NO_INTERFACE"

    except Exception as e:
        wifi_data["wifi_status"] = f"ERROR: {e.__class__.__name__}"
        
    return wifi_data

def capture_and_merge(wifi_info):
    """
    Wi-Fi 정보를 기반으로 패킷을 캡처하고 데이터를 병합합니다.
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 패킷 {PACKET_COUNT}개 수집 시작...")

    extracted_list = []

    try:
        capture = pyshark.LiveCapture(interface=INTERFACE, bpf_filter='ip')
        packets = capture.sniff_continuously(packet_count=PACKET_COUNT)

        for i, packet in enumerate(packets):
            # Wi-Fi 정보 복사 (AP Context)
            data = wifi_info.copy()
            
            # 메타데이터 초기화
            data['frame_number'] = i + 1
            data['packet_timestamp'] = float(packet.sniff_timestamp)
            data['src_ip'] = "N/A"
            data['dst_ip'] = "N/A"
            data['protocol_type'] = "N/A"
            data['protocol'] = "N/A"
            data['src_port'] = "N/A"
            data['dst_port'] = "N/A"
            data['tcp_flags'] = "N/A"
            data['i_rtt_sec'] = None
            data['rtt_continuous_sec'] = None # <--- 연속 RTT 초기화
            data['dns_query'] = "N/A"
            data['tls_version'] = "N/A"

            # IP 레이어 추출
            if 'IP' in packet:
                data['src_ip'] = packet.ip.src
                data['dst_ip'] = packet.ip.dst
                data['protocol_type'] = packet.ip.proto # 6:TCP, 17:UDP

                # TCP 분석 (iRTT, Continuous RTT 포함)
                if 'TCP' in packet:
                    data['protocol'] = 'TCP'
                    data['src_port'] = getattr(packet.tcp, 'srcport', data['src_port'])
                    data['dst_port'] = getattr(packet.tcp, 'dstport', data['dst_port'])
                    data['tcp_flags'] = getattr(packet.tcp, 'flags', data['tcp_flags'])
                    
                    # 1. 초기 RTT (i_rtt_sec)
                    rtt_initial = getattr(packet.tcp, 'analysis_initial_rtt', None)
                    if rtt_initial is not None:
                        data['i_rtt_sec'] = float(rtt_initial)

                    # 2. 연속 RTT (rtt_continuous_sec) - ACK RTT
                    rtt_ack = getattr(packet.tcp, 'analysis_ack_rtt', None)
                    if rtt_ack is not None:
                        data['rtt_continuous_sec'] = float(rtt_ack)
                
                # UDP / DNS 분석 
                elif 'UDP' in packet:
                     data['protocol'] = 'UDP'
                     data['src_port'] = getattr(packet.udp, 'srcport', data['src_port'])
                     data['dst_port'] = getattr(packet.udp, 'dstport', data['dst_port'])
                     
                     if 'DNS' in packet:
                        data['dns_query'] = getattr(packet.dns, 'qry_name', data['dns_query'])

                # TLS 분석
                if 'TLS' in packet:
                    data['tls_version'] = getattr(packet.tls, 'version', data['tls_version'])

            extracted_list.append(data)
            
            if (i + 1) % 10 == 0:
                print(f"   ... {i + 1}개 수집 완료")

    except Exception as e:
        print(f"❌ 캡처 중 오류 발생: {e}")
        return []

    return extracted_list

if __name__ == "__main__":
    
    # 1. Wi-Fi 정보 가져오기 (권한 팝업 유도)
    current_wifi = get_wifi_context()

    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 📡 현재 AP 상태:")
    print(f"   - SSID: {current_wifi['ssid']}")
    print(f"   - BSSID: {current_wifi['bssid']}")
    print(f"   - RSSI: {current_wifi['rssi']} dBm")

    # 2. 패킷 캡처 및 데이터 병합
    final_data = capture_and_merge(current_wifi)

    # 3. 결과 저장
    if final_data:
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, ensure_ascii=False, indent=4)
            print(f"\n✅ [성공] 총 {len(final_data)}개의 데이터가 '{OUTPUT_FILE}'에 저장되었습니다.")
        except Exception as e:
            print(f"\n❌ [오류] 파일 저장 중 실패: {e}")
    else:
        print("\n❌ 데이터 수집에 실패했거나 수집된 패킷이 없습니다.")