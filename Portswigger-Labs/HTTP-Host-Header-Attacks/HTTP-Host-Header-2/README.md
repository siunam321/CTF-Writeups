# Host header authentication bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-authentication-bypass), you'll learn: Host header authentication bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

To solve the lab, access the admin panel and delete Carlos's account.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014111.png)

**Let's go to the admin panel(`/admin`):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014139.png)

it's only available to **local** users.

**In the lab's background, it said:**

> This lab makes an assumption about the privilege level of the user based on the HTTP Host header.

**Hmm... What if I intercept the GET request to `/admin`, and then modify the `Host` header to `localhost`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014515.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014525.png)

**Let's forward that request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014545.png)

Oh! I can access to the admin panel!

Let's delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014636.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-2/images/Pasted%20image%2020221228014643.png)

Nice!

# What we've learned:

1. Host header authentication bypass