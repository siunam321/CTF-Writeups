# Host validation bypass via connection state attack

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-host-validation-bypass-via-connection-state-attack), you'll learn: Host validation bypass via connection state attack! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab is vulnerable to routing-based [SSRF](https://portswigger.net/web-security/ssrf) via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.

To solve the lab, exploit this behavior to access an internal admin panel located at `192.168.0.1/admin`, then delete the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228033647.png)

**Now, we can try to modify the `Host` HTTP header in Burp Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228033754.png)

However, it redirects me to the lab domain.

**What if I supply multiple `Host` header?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228033932.png)

`Duplicate header names are not allowed`.

**How about indenting HTTP headers with a space character?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228034050.png)

Hmm... Still the same.

**In the lab's background, it said:**

> This lab is vulnerable to routing-based [SSRF](https://portswigger.net/web-security/ssrf) via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.

Hmm... **What if I send a normal `Host` header on the first request, then in the second request I send a malicious `Host` header, which points to `192.168.0.1`?**

**To do so, I'll use 2 Burp Repeater tabs:**

- Tab 1: `GET /`, normal `Host` header:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228034912.png)

- Tab 2: `GET /admin`, `Host` header change to `192.168.0.1`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228034949.png)

- Add both tabs to a new group:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035048.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035107.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035156.png)

- Change the send mode to Send group in sequence (single connection):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035237.png)

- Change the `Connection` header to `keep-alive`:
 
![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035329.png)

- Click Send group (single connection):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035440.png)

As you can see, **the second request has successfully accessed the admin panel!**

Now, in order to delete user `carlos`, **we need to send a POST request to `/admin/delete`, with parameter `csrf`, and `username`.**

**Let's modify the second tab:**

- Change the location to `/admin/delete`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035720.png)

- Change the request method:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035741.png)

- Add parameter `csrf`, `username` with correct value:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228035845.png)

- Send the request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228040120.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-6/images/Pasted%20image%2020221228040127.png)

We did it!

# What we've learned:

1. Host validation bypass via connection state attack