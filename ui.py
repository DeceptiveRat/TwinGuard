import subprocess
import ctypes
import signal
import sys
import socket

# only Linux supported for now
if sys.platform != 'linux':
	print("OS not supported")
	sys.exit()

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
			print(data)
	except KeyboardInterrupt:
		# close log files
		capturer_log.close()
		preprocessor_log.close()
	return

print("Starting TwinGuard UI....")

# create log files
capturer_log = open("capturer.log", "w")
preprocessor_log = open("preprocessor.log", "w")

print("Starting subprocesses...")
# create subprocesses
preprocess_ans = subprocess.Popen(["python3", "-u", "extract.py"], preexec_fn = preexec_fn, stdout=preprocessor_log, stderr=preprocessor_log)
capture_ans = subprocess.Popen(["python3", "-u", "PacketCapture.py", "-i", "wlx00ada7025523"], preexec_fn = preexec_fn, stdout=capturer_log, stderr=capturer_log)

# create input socket
input_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
input_sock.bind((IP, port))

while True:
	print("Choose action:")
	print("0. exit program")
	print("1. listen for anomalies")
	x = input()
	if x == "0":
		sys.exit()
	elif x == "1":
		socket_listen(input_sock)
	else:
		print("Invalid action!")
