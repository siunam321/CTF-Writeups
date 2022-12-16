# Authentication bypass via information disclosure

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass), you'll learn: Authentication bypass via information disclosure! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216055028.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216055044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216055050.png)

**After using `gobuster`, we can see the admin panel is in `/admin`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-4]
└─# gobuster dir -u https://0aaf009f04cd8875c0660ff5003900a4.web-security-academy.net/ -w /usr/share/wordlists/dirb/common.txt
[...]
/Admin                (Status: 401) [Size: 2348]
/ADMIN                (Status: 401) [Size: 2348]
/admin                (Status: 401) [Size: 2348]
```

**However, when I reach there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216060253.png)

Hmm... **It only allows local users, which is using the localhost(`127.0.0.1`) IP address.**

**But, when I change the method from `GET` to `TRACE`, something interesting happend:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216060508.png)

It has a custom HTTP header called `X-Custom-IP-Authorization`, which contain my IP address!

**Now, what if I also include that custom header in my request?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216060648.png)

I'm authenticated!!

**In Burp Suite, we can add that custom header to every request I send:**

- Go to "Proxy" -> "Options":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216060844.png)

- In "Match and Replace" session, click "Add", and leave the "Match" condition blank, but in the "Replace" field, enter `X-Custom-IP-Authorization: 127.0.0.1`

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216061017.png)

**Now, let's go to `/admin` with the custom header!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216061057.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216061114.png)

**Delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-4/images/Pasted%20image%2020221216061132.png)

We did it!

# What we've learned:

1. Authentication bypass via information disclosure