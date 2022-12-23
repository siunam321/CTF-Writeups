# Server-side template injection with information disclosure via user-supplied objects

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects), you'll learn: Server-side template injection with information disclosure via user-supplied objects! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to the way an object is being passed into the template. This vulnerability can be exploited to access sensitive data.

To solve the lab, steal and submit the framework's secret key.

You can log in to your own account using the following credentials:

`content-manager:C0nt3ntM4n4g3r`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045047.png)

**Login as user `content-manager`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045107.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045112.png)

**In previous lab, we found that we can edit product posts' template:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045146.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045201.png)

**Let's clean that up:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045605.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223045612.png)

Hmm... Looks like we can't do that.

However, we know that **the template engine is Django, which is written in Python.**

Now, many template engines expose a "self" or "environment" object of some kind, which acts like a namespace containing all objects, methods, and attributes that are supported by the template engine.

**In some Python based template engine, we can use the following template syntax to list the secret key:** (From [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python))

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223050426.png)

> Note: You can use the `debug` mode to see all the objects and properties within this template.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-5/images/Pasted%20image%2020221223050436.png)

Found the secret key!

# What we've learned:

1. Server-side template injection with information disclosure via user-supplied objects