import socket
import json
import sys

# --- 설정 ---
IP = "127.0.0.1"
capturer_port = 5001  # Capture(수집기)에서 받는 포트
ML_port = 5002        # Detector(탐지기)로 보내는 포트

# 변수 초기화
SSID_file = "SSID.json"
SSID_dictionary = {}
new_BSSID = False

# ------------------------------------------------------------------
# [핵심 수정] 파일이 없으면 빈 딕셔너리로 시작 (이모지 제거됨)
try:
    with open(SSID_file, "r") as file:
        SSID_dictionary = json.load(file)
    print(f"[OK] Loaded SSID DB: {len(SSID_dictionary)} entries.")
except (FileNotFoundError, json.JSONDecodeError):
    # 윈도우 호환성을 위해 이모지 대신 [WARNING] 사용
    print("[WARNING] SSID.json not found. Starting with empty DB.")
    SSID_dictionary = {}
# ------------------------------------------------------------------

# 소켓 생성
try: 
    capturer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    ML_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 윈도우에서 "주소 이미 사용 중" 오류 방지
    capturer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    capturer_socket.bind((IP, capturer_port))
    print(f"[OK] Preprocessor Listening on {IP}:{capturer_port}")
    
except socket.error as err: 
    print(f"[ERROR] Socket Error: {err}")
    sys.exit()

try:
    while True:
        # 1. 데이터 수신 (Capture -> Preprocessor)
        # 윈도우는 버퍼 크기를 넉넉하게(4096) 잡는 게 안전합니다.
        data, addr = capturer_socket.recvfrom(4096)
        
        new_BSSID = False
        
        # JSON 리스트 파싱
        try:
            # 리스트 안의 딕셔너리를 꺼냄 (예: [{...}])
            parsed_list = json.loads(data.decode('utf-8'))
            parsed_data = parsed_list[0]
        except (json.JSONDecodeError, IndexError, Exception) as e:
            print(f"[ERROR] Data parsing error: {e}")
            continue

        # 데이터 추출
        protocol = parsed_data.get('protocol', 'N/A')
        RSSI = parsed_data.get('ap_rssi', -100)
        SSID = parsed_data.get('ap_ssid', 'Unknown')
        BSSID = parsed_data.get('ap_bssid', 'Unknown')
        
        # TCP RTT 값 추출 (없으면 0)
        i_rtt = parsed_data.get('i_rtt_sec')
        if i_rtt is None: i_rtt = 0
        
        rtt = parsed_data.get('rtt_continuous_sec')
        if rtt is None: rtt = 0

        # --- BSSID 검증 로직 ---
        if SSID != "Unknown" and BSSID != "Unknown":
            # 1. 처음 보는 SSID면 등록
            if SSID not in SSID_dictionary:
                SSID_dictionary[SSID] = [BSSID]
                print(f"[INFO] New Network Added: {SSID}")
                
            # 2. 아는 SSID인데 BSSID가 다르면? (Evil Twin 의심)
            elif BSSID not in SSID_dictionary[SSID]:
                SSID_dictionary[SSID].append(BSSID)
                print(f"[ALERT] New BSSID for {SSID} detected: {BSSID}")
                new_BSSID = True

        # --- 데이터 전달 (To AnomalyDetector) ---
        data_to_send = {
            "Protocol": protocol,
            "RSSI": RSSI,
            "new_BSSID": new_BSSID
        }
        
        if protocol == "TCP":
            data_to_send["RTT"] = rtt

        # JSON 변환 후 전송 (UDP 5002)
        json_payload = json.dumps(data_to_send).encode('utf-8')
        ML_socket.sendto(json_payload, (IP, ML_port))

        print(f"-> Forwarded: {data_to_send}")

except KeyboardInterrupt:
    print("\n[INFO] Saving SSID Database...")
    with open(SSID_file, "w") as file:
        file.write(json.dumps(SSID_dictionary))
    print("Done. Exiting.")
    sys.exit()