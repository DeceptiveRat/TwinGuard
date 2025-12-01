#!/bin/python3 

import socket
import json
import sys

# network variables
IP = "127.0.0.1"
capturer_port = 5001
ML_port = 5002

# etc variables
SSID_file = "SSID.json"
SSID_dictionary = {}
new_BSSID = False

with open(SSID_file, "r") as file:
	SSID_dictionary = json.load(file)

# create receiving socket
try: 
	capturer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
	ML_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print ("Sockets successfully created")
except socket.error as err: 
	print ("socket creation failed with error %s" %(err))

capturer_socket.bind((IP, capturer_port))
data, addr = capturer_socket.recvfrom(1024)
try:
	while True:
		new_BSSID=False
		parsed_data = json.loads(data)[0]

		protocol = parsed_data['protocol']
		RSSI = parsed_data['ap_rssi']
		SSID = parsed_data['ap_ssid']
		BSSID = parsed_data['ap_bssid']
		i_rtt = parsed_data['i_rtt']
		rtt = parsed_data['ack_rtt']
		print(type(SSID_dictionary[SSID]))

		# new SSID
		if SSID not in SSID_dictionary.keys():
			SSID_dictionary.update({SSID:[BSSID]})
		# new BSSID for SSID
		elif BSSID not in SSID_dictionary[SSID]:
			SSID_dictionary[SSID].append(BSSID)
			print(SSID_dictionary)
			new_BSSID = True

		if protocol == "UDP":
			data_to_send = json.dumps({"Protocol":protocol, "RSSI":RSSI, "new_BSSID":new_BSSID})
			ML_socket.sendto(data_to_send.encode('utf-8'), (IP, ML_port))
		elif protocol == "TCP":
			data_to_send = json.dumps({"Protocol":protocol, "RSSI":RSSI, "RTT":rtt, "new_BSSID":new_BSSID})
			ML_socket.sendto(data_to_send.encode('utf-8'), (IP, ML_port))
		else:
			print("Error! Unsupported protocol")
			sys.exit()

		print("data sent")
		print(data_to_send)
		data, addr = capturer_socket.recvfrom(1024)
except KeyboardInterrupt:
	with open(SSID_file, "w") as file:
		file.write(json.dumps(SSID_dictionary))
	sys.exit()
