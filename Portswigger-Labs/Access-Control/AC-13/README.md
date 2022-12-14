# Referer-based access control

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-referer-based-access-control), you'll learn: Referer-based access control! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed [access controls](https://portswigger.net/web-security/access-control) to promote yourself to become an administrator.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033356.png)

**Let's login as `administrator` to view the admin panel:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033541.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033551.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033602.png)

**In here, we can see an adminstrator level user can upgrade or downgrade a user's privilege.**

**Let's try to upgrade a user privilege, and intercept that request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214033804.png)

**When an administrator try to upgrade a user, it'll send a GET request to `/admin-roles`, with the parameter: `username` and `action` (`upgrade`/`downgrade`).**

**Also, it includes a `Referer` HTTP header!**

**Armed with above information, we can login as user `wiener`, and try to escalate our privilege to administrator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034022.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034031.png)

**Now, we can try to send a GET request to `/admin-roles` via Burp Suite's Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034137.png)

However, we get `Unauthorized` error.

In the above GET request, we can see that it includes a `Referer` HTTP header.

**What if I change that to `/admin`? Which is the admin panel location:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034313.png)

Nice! This time we don't have `Unauthorized` error!

**Let's refresh the page and verify we're administrator or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-13/images/Pasted%20image%2020221214034403.png)

We're administrator!!

# What we've learned:

1. Referer-based access control