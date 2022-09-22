#!/usr/bin/env python3

import socket

rhost = "10.10.184.23"

for port in range(1, 101):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((rhost, port))
	msg = s.recv(1024)
	print(msg.decode('utf-8'))
	s.close()