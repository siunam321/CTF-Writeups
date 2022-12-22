# Password reset poisoning via middleware

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware), you'll learn: Password reset poisoning via middleware! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050152.png)

**Let's login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050240.png)

**Now, let's try to reset our password in the forgot password link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050308.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050413.png)

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050434.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050520.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222050537.png)

When we clicked the `submit` button, **it'll send a POST request to `/forgot-password` and a token, with parameter `temp-forgot-password-token`, `new-password-1`, and `new-password-2`.**

Let's try to add a HTTP header called `X-Forwarded-Host`. If the application accepts that HTTP header, we can know that the the reset email is generated dynamically.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222051638.png)

It worked!

Armed with aboe information, the reset email function may vulnerable to **password reset poisoning**, as attackers can dynamically generated reset link to an arbitrary domain.

**To do so, I'll change parameter `username` value to `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222051937.png)

**Exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052007.png)

- Carlos password reset token: `mjTcAhTKUiFHCw1vGZnpxd5PBHhY8zXb`

**Now, we can send a POST request to `/forgot-password` with the new token!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052228.png)

In here, we should able to login as `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052255.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-11/images/Pasted%20image%2020221222052300.png)

We're user `carlos`!

# What we've learned:

1. Password reset poisoning via middleware