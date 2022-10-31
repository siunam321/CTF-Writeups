#!/usr/bin/env python3

from pwn import *
import base64
import string

context.log_level = 'critical' # No logging

host, port = '10.10.100.200', 35740

char = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
unb64 = base64.b64decode(char)

def get_alphabet(payload):
	with remote(host, port) as p:
		p.recvuntil(b'...\n')

		# Send the base64 decoded characters
		p.sendline(payload)

		# Retrieve their message, which is their alphabet
		their_message = p.recv().decode('utf-8')
		found_alphabet = their_message[:64] + '=' # Their alphabet has an extra '='

		# Send their alphabet
		p.send(bytes(found_alphabet, 'utf-8')) # Use send() is because it doesn't contain the new line character(\n)
 		print(p.recv().decode('utf-8'))

if __name__ == '__main__':
	get_alphabet(unb64)