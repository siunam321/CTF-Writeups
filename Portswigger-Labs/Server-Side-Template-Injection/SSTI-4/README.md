# Server-side template injection in an unknown language with a documented exploit

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit), you'll learn: Server-side template injection in an unknown language with a documented exploit! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection). To solve the lab, identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223042206.png)

First, we need to **detect** is there any Server-Side Template Injection(SSTI) vulnerability in this web application.

**After poking around, we can see this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223042335.png)

When we clicked one of those products that are out of stock, **it'll redirect us to `/`, with GET parameter `/message`.**

**Let's find out is it vulnerable:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223042810.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223043207.png)

Yes, it's vulnerable to SSTI!

**This template engine is Handlebars, which is written in JavaScript.**

However, this template engine's remote code execution is very tricky.

**In [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#handlebars---command-execution), we can get command execution via this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223044021.png)

**Let's copy and paste that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223044321.png)

> Note: The payload need to be URL encoded.

**It worked! Let's delete `morale.txt` file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-4/images/Pasted%20image%2020221223044418.png)

We did it!

# What we've learned:

1. Server-side template injection using documentation