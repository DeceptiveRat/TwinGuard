import subprocess
import ctypes
import signal
import sys
import socket
import getopt
import json

# only Linux supported for now
if sys.platform != 'linux':
	print("OS not supported")
	sys.exit()

def usage():
	print("usage:", sys.argv[0])
	print("options:")
	print("-h: display this help screen")
	print("-i <interface>: set interface. Default: Wi-Fi")

try:
	opts, args = getopt.getopt(sys.argv[1:], "hi:")
except getopt.GetoptError as err:
	print(err)
	usage()
	sys.exit(2)

INTERFACE = "Wi-Fi"

for option, argument in opts:
	if option == "-h":
		usage()
		sys.exit()
	elif option == "-i":
		INTERFACE = argument
	else:
		assert False, "unhandled option"

# network variables
IP = "127.0.0.1"
port = 5003

# etc variables
libc = ctypes.CDLL("libc.so.6")

# functions
def preexec_fn():
	libc.prctl(1, signal.SIGTERM)

def socket_listen(socket):
	try:
		while True:
			data, addr = input_sock.recvfrom(1024)
			loaded_data = json.loads(data)
			if loaded_data['status'] == "NORMAL":
				continue
			
			# set alert level
			alert_level = loaded_data['status']
			if alert_level == "SUSPICIOUS":
				print("Suspicious change detected.")
			elif alert_level == "HIGH":
				print("Attack detected!")
			print("Score: ", loaded_data['score'])

			# advise action based on cause
			if loaded_data['new_BSSID'] == True:
				print("New BSSID detected! Disconnect from AP immediately!")
			elif loaded_data['RSSI'] >60:
				print("Network suddenly got stronger. Unless you moved closer to AP, should be cautious")

	except KeyboardInterrupt:
		return

print("Starting TwinGuard UI....")

# create log files
capturer_log = open("capturer.log", "w")
preprocessor_log = open("preprocessor.log", "w")
detector_log = open("detector.log", "w")

print("Starting subprocesses...")
# create subprocesses
preprocess_ans = subprocess.Popen(["python3", "-u", "Preprocessor.py"], preexec_fn = preexec_fn, stdout=preprocessor_log, stderr=preprocessor_log)
capture_ans = subprocess.Popen(["python3", "-u", "PacketCapture.py", "-i", INTERFACE], preexec_fn = preexec_fn, stdout=capturer_log, stderr=capturer_log)
detector_ans = subprocess.Popen(["python3", "-u", "AnomalyDetector.py"], preexec_fn = preexec_fn, stdout=detector_log, stderr=detector_log)

# create input socket
input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
input_sock.bind((IP, port))

while True:
	print("Choose action:")
	print("0. exit program")
	print("1. listen for anomalies")
	x = input()
	if x == "0":
		# close log files
		capturer_log.close()
		preprocessor_log.close()
		detector_log.close()

		# exit
		sys.exit()
	elif x == "1":
		socket_listen(input_sock)
	else:
		print("Invalid action!")
