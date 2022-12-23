# Basic server-side template injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic), you'll learn: Basic server-side template injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to the unsafe construction of an ERB template.

To solve the lab, review the ERB documentation to find out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223001315.png)

First, we need to **detect** does the SSTI(Server-Side Template Injection) vulnerability exist.

**To do so, we can fuzz the site via `${{<%[%'"}}%\`, which might trigger an template error.**

**In the home page, I notice something interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223001635.png)

When I try to view the details in the first, it displays `Unfortunately this product is out of stock`.

**Let's check the HTTP history via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223001743.png)

**When a product is out of stock, the application will render a template, which is using the `message` parameter.**

**Let's fuzz this parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223001953.png)

**Hmm... Let's try to do some maths:**
```
{{7*7}}
${7*7}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223002533.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223002600.png)

Nope.

**After some trial and error, I found this is working:**
```
<%= 7*7 %>
<%= foobar %>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223002737.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223002902.png)

> Note: The payload is URL encoded.

According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby), **this template engine is ERB, which is written in Ruby.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223002944.png)

Let's dig deeper in ERB's documentation!

**In this [blog](https://www.rubyguides.com/2018/12/ruby-system/), we can execute OS command via `system` method:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223004012.png)

**Let's try that:**
```
<%= system("ls") %>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223004139.png)

We successfully executed an OS command!

**Let's delete that `morale.txt` file:**
```
<%= system("rm morale.txt") %>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-1/images/Pasted%20image%2020221223004241.png)

We did it!

# What we've learned:

1. Basic server-side template injection