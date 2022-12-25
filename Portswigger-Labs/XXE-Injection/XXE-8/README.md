# Exploiting XXE via image file upload

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload), you'll learn: Exploiting XXE via image file upload! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files.

To solve the lab, upload an image that displays the contents of the `/etc/hostname` file after processing. Then use the "Submit solution" button to submit the value of the server hostname.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225071153.png)

**Post page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225071227.png)

In the comment section, we can upload an avatar.

Also, in the lab's background it tells us it uses the **Apache Batik library** to process avatar image files.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225071346.png)

So, it's clear that **we can upload an SVG image, which can be used to exploit XXE injection.**

> Note: SVG(Scalable Vector Graphics) image format uses XML.

Armed with above information, **we can craft an SVG image that contains an XXE payload.**

**According to the [blog](https://insinuator.net/2015/03/xxe-injection-in-apache-batik-library-cve-2015-0250/) from the above image, we can craft an XXE payload inside an SVG image:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225072248.png)

**Let's modify the payload, so we can extract the content of `/etc/hostname` file:**
```xml
<?xml version="1.0" standalone="yes"?><!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-family="Verdana" font-size="16" x="0" y="16">&xxe;</text></svg>
```

**Then upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225072347.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225072604.png)

**Let's open that image in new tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225072631.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/XXE-Injection/XXE-8/images/Pasted%20image%2020221225072645.png)

We did it!

# What we've learned:

1. Exploiting XXE via image file upload