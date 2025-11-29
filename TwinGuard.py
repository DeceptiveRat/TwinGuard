import pyshark
import asyncio
import sys
import json
import os
import time  
import socket     # 내 IP 확인용
import uuid       # 내 MAC 확인용

# ------------------------------------------------------------------
# 💡 [Windows 필수] Pyshark 비동기 오류 해결
if sys.platform == 'win32':
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
# ------------------------------------------------------------------

# --- 설정 ---
INTERFACE = 'Wi-Fi'
BATCH_SIZE = 5          # 5개씩 묶음
OUTPUT_FILE = 'Packet_data.json' 
SLEEP_TIME = 0.5        # 💡 저장 후 대기 시간 (초)

# --- [NEW] 내 컴퓨터 정보 가져오기 함수 ---
def get_my_device_info():
    """ 
    현재 인터넷에 연결된 나의 IP와 MAC 주소를 가져옵니다. 
    """
    device_info = {"ip": "Unknown", "mac": "Unknown"}
    
    try:
        # 1. 내 IP 찾기
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) 
        device_info['ip'] = s.getsockname()[0]
        s.close()
        
        # 2. 내 MAC 찾기
        mac_int = uuid.getnode()
        mac_hex = '{:012x}'.format(mac_int)
        device_info['mac'] = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
        
    except Exception as e:
        print(f"⚠️ 내 정보 가져오기 실패: {e}")
        
    return device_info

# 1. 내 정보 출력 (시작할 때 딱 한 번)
print(f"[{INTERFACE}] 실시간 감시 시작... 인터넷 접속을 활발하게 해줄 수록 도움이 됩니다!")
my_device = get_my_device_info()
print(f"✅ [내 정보] IP : {my_device['ip']}")
print(f"✅ [내 정보] MAC: {my_device['mac']}")
print("-"*40)

try:
    # 캡처 객체 생성
    capture = pyshark.LiveCapture(interface=INTERFACE, display_filter="tcp || udp")

    packet_batch = []

    # 무한 루프
    for i, packet in enumerate(capture.sniff_continuously()):
        
        # 1. 데이터 가공
        packet_data = {
            "id": (i % BATCH_SIZE) + 1,
            "timestamp": float(packet.sniff_timestamp),
            "protocol": packet.transport_layer,
            "length": int(packet.length), 
            
            # 💡 [요청하신 추가 부분] IP 및 MAC 주소 (없을 경우 N/A 처리)
            "src_ip": getattr(packet.ip, 'src', "N/A"),
            "dst_ip": getattr(packet.ip, 'dst', "N/A"),
            "src_mac": getattr(packet.eth, 'src', "N/A"),
            "dst_mac": getattr(packet.eth, 'dst', "N/A"),
            
            "src_port": int(packet[packet.transport_layer].srcport),
            "dst_port": int(packet[packet.transport_layer].dstport),
        }

        if 'TCP' in packet:
            packet_data.update({
                "tcp_flags": str(packet.tcp.flags),
                "i_rtt": float(getattr(packet.tcp, 'analysis_initial_rtt', 0.0)),
                "ack_rtt": float(getattr(packet.tcp, 'analysis_ack_rtt', 0.0)),
                "dns_query": "N/A"
            })
        elif 'UDP' in packet:
            dns_q = "N/A"
            if 'DNS' in packet:
                dns_q = getattr(packet.dns, 'qry_name', "N/A")
            
            packet_data.update({
                "tcp_flags": "N/A",
                "i_rtt": -1.0,
                "ack_rtt": -1.0,
                "dns_query": dns_q
            })

        # 2. 리스트에 추가
        packet_batch.append(packet_data)

        # 3. 5개가 모이면 저장 및 대기
        if len(packet_batch) >= BATCH_SIZE:
            # 파일 덮어쓰기
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                json.dump(packet_batch, f, indent=4, ensure_ascii=False)
            
            print("[Saved] 패킷 5개 저장 완료.")
            
            # 💡 0.5초 대기
            time.sleep(SLEEP_TIME)
            
            # 리스트 비우기
            packet_batch = []

except KeyboardInterrupt:
    print("\n🛑 사용자에 의해 중단되었습니다.")
except Exception as e:
    print(f"❌ 오류 발생: {e}")