import time
import sys
import json
import os
from datetime import datetime
import pyshark

# macOS Native Libraries (PyObjC)
from CoreWLAN import CWWiFiClient
from CoreLocation import CLLocationManager

# --- 설정 ---
INTERFACE = 'en0'       # 캡처할 인터페이스
PACKET_COUNT = 30      # 수집할 패킷 수
OUTPUT_FILE = 'packets.json' # 저장할 파일명
MAX_WAIT = 10           # 위치 권한 대기 시간(초)

def get_wifi_context():
    """
    CoreWLAN으로 정확한 Wi-Fi 정보를 가져옵니다.
    """
    wifi_data = {
        "ssid": "Unknown",
        "bssid": "Unknown",
        "rssi": None, # 초기값 None 설정
        "wifi_status": "OK"
    }

    try:
        # 권한 요청 및 대기 로직 (생략)
        location_manager = CLLocationManager.alloc().init()
        location_manager.requestWhenInUseAuthorization()
        
        client = CWWiFiClient.sharedWiFiClient()
        iface = client.interface()

        if iface:
            # RSSI는 Int형이므로 그대로 사용합니다.
            wifi_data["ssid"] = iface.ssid() or "Hidden"
            wifi_data["bssid"] = iface.bssid() or "None"
            wifi_data["rssi"] = int(iface.rssiValue())
    except Exception as e:
        wifi_data["wifi_status"] = f"Error: {e}"
        
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
            # Wi-Fi 정보 복사
            data = wifi_info.copy()
            
            # 기본 메타데이터
            data['frame_number'] = i + 1
            data['packet_timestamp'] = float(packet.sniff_timestamp)
            
            # 통신 메타데이터 (일관성을 위해 필드 초기화)
            data['src_ip'] = "N/A"
            data['dst_ip'] = "N/A"
            data['protocol_type'] = "N/A"
            data['protocol'] = "N/A"
            data['src_port'] = "N/A"
            data['dst_port'] = "N/A"
            data['tcp_flags'] = "N/A"
            data['i_rtt_sec'] = None  # 숫자형: None으로 초기화
            data['dns_query'] = "N/A"
            data['tls_version'] = "N/A"

            # IP 레이어 추출
            if 'IP' in packet:
                data['src_ip'] = packet.ip.src
                data['dst_ip'] = packet.ip.dst
                data['protocol_type'] = packet.ip.proto # 6:TCP, 17:UDP

                # TCP 분석 (iRTT 포함)
                if 'TCP' in packet:
                    data['protocol'] = 'TCP'
                    data['src_port'] = getattr(packet.tcp, 'srcport', data['src_port'])
                    data['dst_port'] = getattr(packet.tcp, 'dstport', data['dst_port'])
                    data['tcp_flags'] = getattr(packet.tcp, 'flags', data['tcp_flags'])
                    
                    # RTT 추출 및 float 변환
                    rtt_value = getattr(packet.tcp, 'analysis_initial_rtt', None)
                    if rtt_value is not None:
                        data['i_rtt_sec'] = float(rtt_value)

                # UDP / DNS 분석 
                elif 'UDP' in packet:
                     data['protocol'] = 'UDP'
                     data['src_port'] = getattr(packet.udp, 'srcport', data['src_port'])
                     data['dst_port'] = getattr(packet.udp, 'dstport', data['dst_port'])
                     
                     if 'DNS' in packet:
                        data['dns_query'] = getattr(packet.dns, 'qry_name', data['dns_query'])

                # TLS 분석
                if 'TLS' in packet:
                    # TLS는 버전이 없어도 레이어가 존재하는 경우도 있어, N/A를 유지하거나 버전을 추출합니다.
                    data['tls_version'] = getattr(packet.tls, 'version', data['tls_version'])

            extracted_list.append(data)
            
            if (i + 1) % 10 == 0:
                print(f"   ... {i + 1}개 수집 완료")

    except Exception as e:
        print(f"❌ 캡처 중 오류 발생: {e}")
        return []

    return extracted_list

if __name__ == "__main__":
    
    # 1. Wi-Fi 정보 가져오기
    # 실제 실행 시 이전 답변의 'CoreWLAN' 로직을 사용하여 정보를 가져와야 합니다.
    current_wifi = get_wifi_context()

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