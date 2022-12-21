# Password reset broken logic

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic), you'll learn: Password reset broken logic! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.

- Your credentials: `wiener:peter`
- Victim's username: `carlos`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221062528.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221062804.png)

**In here, we can see that there is a forgot password link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221062839.png)

**Let's try to reset user `wiener` password:**

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221062935.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221062947.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063000.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063017.png)

**Let's click that link to reset password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063140.png)

**Hmm... Let's submit a password and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063220.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063248.png)

When we clicked the submit button, it'll send a POST request to `/forgot-password`, with parameter `temp-forgot-password-token`, **`username`**, `new-password-1`, and `new-password-2`.

**Hmm... What if I change the `username` value to `carlos`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063458.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063520.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-3/images/Pasted%20image%2020221221063530.png)

We're user `carlos`! The application doesn't check `temp-forgot-password-token` is used or not, and the `username` value is correct or not.

# What we've learned:

1. Password reset broken logic