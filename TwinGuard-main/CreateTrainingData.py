#!/bin/python3 

import socket
import json
import sys

# network variables
IP = "127.0.0.1"
capturer_port = 5001
# create receiving socket
try: 
	capturer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
	print ("Sockets successfully created")
except socket.error as err: 
	print ("socket creation failed with error %s" %(err))

capturer_socket.bind((IP, capturer_port))
# read data from socket
data, addr = capturer_socket.recvfrom(1024)
try:
	while True:
		# parse data
		parsed_data = json.loads(data)[0]
		protocol = parsed_data['protocol']
		rssi = parsed_data['ap_rssi']
		ssid = parsed_data['ap_ssid']
		bssid = parsed_data['ap_bssid']
		i_rtt = parsed_data['i_rtt']
		rtt = parsed_data['ack_rtt']

		# use hardcoded malicious AP bssid to check attack
		if bssid == "5C:01:3B:33:26:41":
			parsed_data['is_attack'] = 1
		else:
			parsed_data['is_attack'] = 0

		# save data
		with open("packets.log", "a") as file:
			file.write(json.dumps(parsed_data))

		data, addr = capturer_socket.recvfrom(1024)

except KeyboardInterrupt:
	sys.exit()
