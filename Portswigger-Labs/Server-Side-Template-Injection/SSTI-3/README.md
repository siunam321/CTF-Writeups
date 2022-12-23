# Server-side template injection using documentation

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation), you'll learn: Server-side template injection using documentation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection). To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials:

`content-manager:C0nt3ntM4n4g3r`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035728.png)

**Login as user `content-manager`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035758.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035806.png)

First, we need to **detect** is there any Server-Side Template Injection(SSTI) vulnerability in this web application.

**After poking around this site, I found that we can edit product posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223035947.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040007.png)

As you can see, it allows us to edit product posts' template!

**Let's clean that up and figure out which template engine is using:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040112.png)

**Let's trigger an error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040136.png)

As you can see, **this web application is using FreeMarker template engine, which is written in Java.**

Let's find out how to get code execution!

**In the [FreeMarker documentation](https://freemarker.apache.org/docs/api/freemarker/template/utility/Execute.html), we can execute OS command via this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040729.png)

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040829.png)

**However, it won't work. Because the server doesn't have this setting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040903.png)

**After some googling, this [blog](https://ackcent.com/in-depth-freemarker-template-injection/) helps us:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223040939.png)

We can use the template engine to enable the OS command execution!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223041110.png)

Boom! We got code execution!

Let's delete `morale.txt` file!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223041205.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-3/images/Pasted%20image%2020221223041221.png)

We did it!

# What we've learned:

1. Server-side template injection using documentation