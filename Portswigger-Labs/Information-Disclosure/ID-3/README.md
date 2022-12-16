# Source code disclosure via backup files

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files), you'll learn: Information disclosure in error messages! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab leaks its source code via backup files in a hidden directory. To solve the lab, identify and submit the database password, which is hard-coded in the leaked source code.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-3/images/Pasted%20image%2020221216053654.png)

**In `robots.txt`, I found something interesting:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-3]
└─# curl https://0a130056031f083bc036cc3700250088.web-security-academy.net/robots.txt             
User-agent: *
Disallow: /backup
```

> `robots.txt` is a plaintext file that let robots(crawlers) know which page shouldn't be indexed.

**Let's go there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-3/images/Pasted%20image%2020221216053943.png)

Found a backup file! `ProductTemplate.java.bak`.

**We can download it via `wget`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Information-Disclosure/ID-3]
└─# wget https://0a130056031f083bc036cc3700250088.web-security-academy.net/backup/ProductTemplate.java.bak
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Information-Disclosure/ID-3/images/Pasted%20image%2020221216054125.png)

**This random string looks like the password for the PostgresSQL database!**

# What we've learned:

1. Source code disclosure via backup files