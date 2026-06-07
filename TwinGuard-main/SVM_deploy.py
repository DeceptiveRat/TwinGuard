import pandas as pd
import joblib
import socket
import json

# network variables
IP = "127.0.0.1"
preprocessor_port = 5002
UI_port = 5003

print("모델 로딩 중...")

try:
	svm_model = joblib.load('evil_twin_detector.pkl')
	scaler = joblib.load('feature_scaler.pkl')
	print("모델 로딩 완료")
except FileNotFoundError:
	print("에러: 모델 파일 없음... SVM_train.py 실행 후 재시도")
	exit()

# 실시간 탐지 
def check_for_evil_twin(live_packet):
	df_live = pd.DataFrame([live_packet])
	
	protocol_map = {'UDP': 0, 'TCP': 1}
	df_live['Protocol'] = df_live['Protocol'].map(protocol_map)
	df_live['new_BSSID'] = df_live['new_BSSID'].astype(int)
		
	X_live = df_live[['Protocol', 'RSSI', 'new_BSSID', 'RTT']]
	print(X_live.columns)
	X_live_scaled = scaler.transform(X_live)
	prediction = svm_model.predict(X_live_scaled)[0]
	
	if prediction == 1:
		print(f"공격 탐지: {live_packet}")
		UI_socket.sendto(b"0", (IP, UI_port))
	else:
		print(f"정상 트래픽 감지")
		UI_socket.sendto(b"1", (IP, UI_port))

# recv 소킷 생성 
try: 
	preprocessor_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
	UI_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print("소켓 생성 완료")
except socket.error as err: 
	print("소켓 생성 실패: %s" %(err))

preprocessor_socket.bind((IP, preprocessor_port))
data, addr = preprocessor_socket.recvfrom(1024)

# preprocess로부터 패킷 데이터 받음
while True:
	parsed_data = json.loads(data)

	protocol = parsed_data['Protocol']
	RSSI = parsed_data['RSSI']
	rtt = parsed_data['RTT']
	new_BSSID = parsed_data['new_BSSID']
	
	check_for_evil_twin({"Protocol":protocol, "RSSI":RSSI, "new_BSSID":new_BSSID, "RTT":rtt})
