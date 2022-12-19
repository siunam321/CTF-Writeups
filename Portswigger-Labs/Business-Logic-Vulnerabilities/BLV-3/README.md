# Inconsistent security controls

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls), you'll learn: Inconsistent security controls! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete Carlos.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219061608.png)

**Let's register an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219061837.png)

In here, we can see that the `DontWannaCry` company is using `dontwannacry.com` as the email domain.

**Also, we can go to `Email client` to get a new email address:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062006.png)

- Our email: `attacker@exploit-0ae0001703bbf4a6c0e86cfd01cb0052.exploit-server.net`

**Now we can register an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062112.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062147.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062216.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062248.png)

**Let's login as user `attacker`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062331.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062406.png)

**In here, we can try to go to the admin panel at `/admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062518.png)

Hmm... It's only available to DontWannaCry user.

**Now, what if I change to email address to `attacker@dontwannacry.com`??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062934.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219062942.png)

We successfully changed the email address to `dontwannacry.com` domain!

Can we access to the admin panel?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219063026.png)

**Yes we can! Let's delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-3/images/Pasted%20image%2020221219063049.png)

# What we've learned:

1. Inconsistent security controls