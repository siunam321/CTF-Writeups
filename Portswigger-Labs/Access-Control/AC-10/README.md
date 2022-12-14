# URL-based access control can be circumvented

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented), you'll learn: URL-based access control can be circumvented! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This website has an unauthenticated admin panel at `/admin`, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the `X-Original-URL` header.

To solve the lab, access the admin panel and delete the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214021404.png)

**In here, we can there is an `Admin panel`. Let's try to access it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214021442.png)

Hmm... `Access denied`.

**In the lab background, it said:**

> **The back-end application is built on a framework that supports the `X-Original-URL` header.**

**With that said, we can use Burp Suite to intercept a GET request to `/`, and add the `X-Original-URL` HTTP header!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214022604.png)

> Note: If you add the `X-Original-URL` in the second line, Burp Suite won't hang.

**Let's forward that request!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214022702.png)

**This time, we see `Not Found`, which indicates that the back-end is processing the `X-Original-URL` header!!**

**Now, let's change the `X-Original-URL` value to `/admin`, and see what will happen:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214022836.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214022851.png)

Yes!! We're successfully can see the admin panel.

Next, we need to delete user `carlos` in order to finish this lab.

However, we're not actually authenticated.

**To delete a user, we'll have to add the `X-Original-URL` header again, but with different value. And also change the request location to `/`, so we kinda spoof the front-end we're on `/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214023330.png)

**Let's forward it!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-10/images/Pasted%20image%2020221214023454.png)

We've successfully deleted user `carlos`!

# What we've learned:

1. URL-based access control can be circumvented