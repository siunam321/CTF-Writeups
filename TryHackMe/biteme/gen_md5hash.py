#!/usr/bin/env python3

from hashlib import md5
import random
from string import ascii_lowercase

while True:

	# Randomly select 6 lowercase characters as the password.
	random_password = ''.join([random.choice(ascii_lowercase)for char in range(1, 6)])
	md5hash = md5(random_password.encode())
	hashed = md5hash.hexdigest()

	# If the hash's last 3 characters equals to '001', then do:
	if hashed[-3:] == '001':
		print('[+] Found the last 3 MD5 characters are equals to 001!')
		print(f'[+] Before MD5 hash: {random_password}')
		print(f'[+] After MD5 hash: {hashed}')
		exit()