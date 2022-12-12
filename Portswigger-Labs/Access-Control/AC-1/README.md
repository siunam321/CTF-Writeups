# Unprotected admin functionality

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality), you'll learn: Unprotected admin functionality! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has an unprotected admin panel.

Solve the lab by deleting the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-1/images/Pasted%20image%2020221212041157.png)

**Let's enumerate this website!**

**`robots.txt`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Access-Control/AC-1]
└─# curl https://0a4e00f2031a5e0fc2357d45006100d2.web-security-academy.net/robots.txt            
User-agent: *
Disallow: /administrator-panel
```

**In `robots.txt`, we can see that it's disallowing all bots to index `/administrator-panel`!**

**How about we can directly access to that admin panel??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-1/images/Pasted%20image%2020221212041432.png)

**Hmm... Looks like we can! Let's delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-1/images/Pasted%20image%2020221212041459.png)

# What we've learned:

1. Unprotected admin functionality