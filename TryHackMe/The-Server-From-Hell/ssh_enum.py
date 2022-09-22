#!/usr/bin/env python3

import os

rhost = '10.10.184.23'

for port in range(2500, 4500):
	os.system(f'ssh -i ./home/hades/.ssh/id_rsa hades@{rhost} -p {port}')