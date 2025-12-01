#!/bin/python3 

import socket
import json

IP = "127.0.0.1"
capturer_port = 5001
ML_port = "5002"

try: 
    capturer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    print ("Socket successfully created")
except socket.error as err: 
    print ("socket creation failed with error %s" %(err))

capturer_socket.bind((IP, capturer_port))
data, addr = capturer_socket.recvfrom(1024)
while data:
	parsed_data = json.loads(data)[0]
	if parsed_data['protocol'] == "UDP":
		continue
	
	print("Packet captured...")
	print("Protocol: ", end="")
	print(parsed_data['protocol'])
	print("RSSI: ", end="")
	print(parsed_data['ap_rssi'])
	print("SSID: ", end="")
	print(parsed_data['ap_ssid'])
	print("BSSID: ", end="")
	print(parsed_data['ap_bssid'])
	print("initial RTT: ", end="")
	print(parsed_data['i_rtt'])
	print("RTT: ", end="")
	print(parsed_data['ack_rtt'])
	data, addr = capturer_socket.recvfrom(1024)
