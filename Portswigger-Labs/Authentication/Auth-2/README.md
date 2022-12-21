# 2FA simple bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass), you'll learn: 2FA simple bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.

- Your credentials: `wiener:peter`
- Victim's credentials `carlos:montoya`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061118.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061200.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061211.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061305.png)

In here, we're prompted to another login page, which requires a 4 digits security code.

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061550.png)

**Enter 4 digits security code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061602.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061617.png)

**Now let's login as user `carlos` and bypass the 2FA:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061724.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061733.png)

In here, since we're already logged in via a valid username and password, we're technically logged in!

**Why not just go to `/my-account` page?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Authentication/Auth-2/images/Pasted%20image%2020221221061810.png)

Nice! The application doesn't check we have entered a valid 2FA code or not!

# What we've learned:

1. 2FA simple bypass