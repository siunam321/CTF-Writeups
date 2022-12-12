# User role controlled by request parameter

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter), you'll learn: User role controlled by request parameter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

Solve the lab by accessing the admin panel and using it to delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212043834.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212043857.png)

**In the lab background, it said:**

> This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.

**Let's view our cookies!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044006.png)

As you can see, there is a cookie called `Admin`, and it's value is `false`.

**Hmm... What if I change the value to `true`?? Will I become an administrator??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044107.png)

**Now let's go to the admin panel at `/admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044139.png)

I'm allowed to go to the admin panel!

Let's delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-3/images/Pasted%20image%2020221212044213.png)

# What we've learned:

1. User role controlled by request parameter