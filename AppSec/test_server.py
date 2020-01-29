import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 31337))
s.listen(1)
while True:
	c, addr = s.accept()
	print("Connection Successful")
	break

