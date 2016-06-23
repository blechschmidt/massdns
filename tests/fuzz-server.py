import socket
import os
import random

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 53))

index = 0
while True:
	if index % 10000 == 0:
		print(index)
	index += 1
	data, addr = sock.recvfrom(10000)
	rand = os.urandom(random.randint(100, 600))
	transaction_id = data[0:2]
	rand = transaction_id + rand
	sock.sendto(rand, addr)
