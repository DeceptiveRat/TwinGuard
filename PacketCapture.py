import pyshark
import asyncio
import sys
import json
import os
import time  
import socket	 
import uuid	   
import subprocess 
import re		 
import getopt

# ------------------------------------------------------------------
# [Windows 필수] Pyshark 비동기 오류 해결
if sys.platform == 'win32':
	try:
		asyncio.get_event_loop()
	except RuntimeError:
		asyncio.set_event_loop(asyncio.new_event_loop())
# ------------------------------------------------------------------

# --- 설정 ---
INTERFACE = 'Wi-Fi'
BATCH_SIZE = 1
OUTPUT_FILE = 'Packet_data.json' 
SLEEP_TIME = 0.1
DISPLAY_FILTER = "tcp || udp"

#소켓
TARGET_IP = '127.0.0.1'  
TARGET_PORT = 5001	   

def usage():
	print("usage:", sys.argv[0])
	print("options:")
	print("-h: display this help screen")
	print("-o <output file>: set name of output file. Default: Packet_data.json")
	print("-i <interface>: set interface. Default: Wi-Fi")
	print("-t: set display filter to only TCP")
	print("-u: set display filter to only UDP")

try:
	opts, args = getopt.getopt(sys.argv[1:], "ho:i:tu")
except getopt.GetoptError as err:
	print(err)
	usage()
	sys.exit(2)

for option, argument in opts:
	if option == "-h":
		usage()
		sys.exit()
	elif option == "-o":
		OUTPUT_FILE = argument 
	elif option == "-i":
		INTERFACE = argument
	elif option == "-t":
		DISPLAY_FILTER="tcp"
	elif option == "-u":
		DISPLAY_FILTER="udp"
	else:
		assert False, "unhandled option"

# create socket
def create_socket():
	return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# --- 데이터 전송 함수 ---
def send_to_socket(json_data, sock):
	""" 수집된 데이터를 내 컴퓨터의 5001번 포트로 쏩니다. """
	try:
		message = json.dumps(json_data, ensure_ascii=False) + "\n"
		sock.sendto(message.encode('utf-8'), (TARGET_IP, TARGET_PORT))
		print(f"🚀 [Socket] 내부 전송 완료! ({len(json_data)}개)")
			
	except ConnectionRefusedError:
		print("⚠️ [Socket] 받는 프로그램(서버)이 아직 안 켜져 있습니다.")
	except Exception as e:
		print(f"⚠️ [Socket] 오류: {e}")

# --- Wi-Fi 정보 가져오기 ---
def get_wifi_info():
	wifi_data = {"ssid": "Unknown", "bssid": "Unknown", "rssi": -100}
	if sys.platform == 'win32':
		try:
			result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
									capture_output=True, text=True, encoding='cp949', errors='replace', check=False)
			output = result.stdout
			parser = {}
			for line in output.split('\n'):
				line = line.strip()
				if "SSID" in line and "BSSID" not in line:
					parts = line.split(':', 1)
					if len(parts) > 1: wifi_data["ssid"] = parts[1].strip()
				elif "BSSID" in line:
					parts = line.split(':', 1)
					if len(parts) > 1: wifi_data["bssid"] = parts[1].strip()
				elif "Rssi" in line or "RSSI" in line:
					parts = line.split(':', 1)
					if len(parts) > 1:
						try: wifi_data["rssi"] = int(parts[1].strip())
						except: pass
		except Exception: pass
	elif sys.platform == 'linux':
		# execute command
		cmd = ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL", "dev", "wifi"]
		result = subprocess.check_output(cmd).decode().strip().split("\n")

		# get network info
		for line in result:
			parts = line.split(":")
			if parts[0] == "yes":
				wifi_data["ssid"] = parts[1]
				wifi_data["bssid"] = str(parts[2]+parts[3]+parts[4]+parts[5]+parts[6]+parts[7]).replace("\\", ':')
				wifi_data["rssi"] = int(parts[8])
				break
	else:
		print("error!: " + sys.platform + " not supported yet!")
		sys.exit()

	return wifi_data

# --- 내 정보 가져오기 ---
def get_my_device_info():
	device_info = {"ip": "Unknown", "mac": "Unknown"}
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80)) 
		device_info['ip'] = s.getsockname()[0]
		s.close()
		mac_int = uuid.getnode()
		mac_hex = '{:012x}'.format(mac_int)
		device_info['mac'] = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
	except Exception: pass
	return device_info

# --- 메인 실행 ---
print(f"[{INTERFACE}] 데이터 수집 -> 내부 포트({TARGET_PORT})로 전송 시작...")
my_device = get_my_device_info()
print(f"✅ [내 정보] IP : {my_device['ip']}")
print(f"✅ [내 정보] MAC: {my_device['mac']}")
print("-"*40)

try:
	sock = create_socket()
	capture = pyshark.LiveCapture(interface=INTERFACE, display_filter=DISPLAY_FILTER)
	packet_batch = []
	current_wifi = get_wifi_info()

	for i, packet in enumerate(capture.sniff_continuously()):
		
		packet_data = {
			"id": (i % BATCH_SIZE) + 1,
			"timestamp": float(packet.sniff_timestamp),
			"protocol": packet.transport_layer,
			"length": int(packet.length),
			"ap_rssi": current_wifi['rssi'],
			"ap_ssid": current_wifi['ssid'],
			"ap_bssid": current_wifi['bssid'],
			"src_ip": getattr(packet.ip, 'src', "N/A") if 'IP' in packet else "N/A",
			"dst_ip": getattr(packet.ip, 'dst', "N/A") if 'IP' in packet else "N/A",
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

			#UDP는 rtt가 없어서 -1로 놓겠습니다
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

		packet_batch.append(packet_data)

		if len(packet_batch) >= BATCH_SIZE:
			
			# 1. 파일 저장 (백업용)
			with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
				json.dump(packet_batch, f, indent=4, ensure_ascii=False)
			
			#DEBUG
			print("sending to socket")
			# 2. 소켓 전송 (핵심)
			send_to_socket(packet_batch, sock)
			
			time.sleep(SLEEP_TIME)
			#DEBUG
			print("getting wifi info")
			current_wifi = get_wifi_info() 
			packet_batch = []

except KeyboardInterrupt:
	print("\n🛑 중단됨.")
except Exception as e:
	print(f"❌ 오류 발생: {e}")
