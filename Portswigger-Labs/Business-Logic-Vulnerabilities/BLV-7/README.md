# Weak isolation on dual-use endpoint

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint), you'll learn: Weak isolation on dual-use endpoint! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access the `administrator` account and delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220063517.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220063534.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220063550.png)

In here, we can see that we can change our account's password!

**Let's try to change our password and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220063708.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220063732.png)

When we clicked the `Change password` button, **it'll send a POST request to `/my-account/change-password`, with parameter `csrf`, `username`, `current-password`, `new-password-1`, and `new-password-2`.**

**Hmm... What if parameter `current-password` or `new-password-1` or `new-password-2` value is missing?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064034.png)

`New passwords do not match`.

**We also see that the `username` is also included. What if I change the `username` to `administrator`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064221.png)

Now we see the username is `administrator`, however, the parameter `current-password` is incorrect.

**What if we delete that parameter?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064349.png)

We successfully changed `administrator`'s password!

**Let's login as `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064443.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064456.png)

We're `administrator` and we can use the admin panel!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064525.png)

Let's delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-7/images/Pasted%20image%2020221220064535.png)

Nice!

# What we've learned:

1. Weak isolation on dual-use endpoint