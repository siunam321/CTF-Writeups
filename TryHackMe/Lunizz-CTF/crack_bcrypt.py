#!/usr/bin/env python3

import bcrypt
import base64

salt = b'your_bcrypt_salt'
bcrypt_hash = b'complete_bcrypt_hash'

with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='latin-1') as f:
	for word in f.readlines():
		passw = word.strip().encode('ascii', 'ignore')
		b64str = base64.b64encode(passw)
		hashAndSalt = bcrypt.hashpw(b64str, salt)
		print('\r', end='') # Clear previous line
		print(f'[*] Cracking hash: {hashAndSalt}', end='')

		if bcrypt_hash == hashAndSalt:
			print('\n[+] Cracked!')
			print(f'[+] Before hashed: {passw}')
			print(f'[+] After hashed: {hashAndSalt}')
			exit()