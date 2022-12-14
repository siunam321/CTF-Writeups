# User ID controlled by request parameter with password disclosure

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure), you'll learn: User ID controlled by request parameter with password disclosure! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has user account page that contains the current user's existing password, prefilled in a masked input.

To solve the lab, retrieve the administrator's password, then use it to delete `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014231.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014250.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014257.png)

**In the previous labs, we found that the `My account` link is supplying an `id` GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014558.png)

This time however, we also can see we can update our own password, and **it's prefilled in a masked input**.

**Hmm... Can we inspect that password?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014659.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014713.png)

Cool, we can see our own password.

**How about using the `My account` link to view another user's password? Like `administrator`:**

**To do so, I'll use Burp Suite's Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014837.png)

**Now, we can view `administrator`' password! `bdxywccjia4y27fb9yty`. Let's login as `administrator` and delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014941.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214014955.png)

We found the `Admin panel`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214015015.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Access-Control/AC-8/images/Pasted%20image%2020221214015024.png)

# What we've learned:

1. User ID controlled by request parameter with password disclosure