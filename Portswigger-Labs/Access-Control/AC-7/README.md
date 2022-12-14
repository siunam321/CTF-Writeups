# User ID controlled by request parameter with data leakage in redirect

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect), you'll learn: User ID controlled by request parameter with data leakage in redirect! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [access control](https://portswigger.net/web-security/access-control) vulnerability where sensitive information is leaked in the body of a redirect response.

To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013220.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013323.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013353.png)

**In the previous labs, we found that the `My account` link is supplying an `id` GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013438.png)

**What if I change the `id` value to user `carlos`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013646.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013702.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013712.png)

Hmm... It's redirecting me to `/login`...

**How about I do that in Burp Suite Repeater??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-7/images/Pasted%20image%2020221214013803.png)

**Oh!! We found user `carlos` API key!**

# What we've learned:

1. User ID controlled by request parameter with data leakage in redirect