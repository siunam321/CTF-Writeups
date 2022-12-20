# Authentication bypass via flawed state machine

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine), you'll learn: Authentication bypass via flawed state machine! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete Carlos.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220072840.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220072905.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220072932.png)

In here, we can choose a role: User or Content author.

**Let's select User and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073138.png)

When we clicked the `Select` button, **it'll send a POST request to `/role-selector`, with parameter `role` and `csrf`.**

Let's forward that request and click the `My account` link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073245.png)

**Now, what if we select Content author role?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073418.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220073604.png)

It seems like no difference between those roles.

**Let's try to reach to the admin panel `/admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074622.png)

It's only available to administrator.

**Now, let's try to log out and test something:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074726.png)

**Then login and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074801.png)

**We'll forward the POST `/login` request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074810.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074843.png)

**In here, what if I drop the GET `/role-selector` request?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074921.png)

**Then go to the home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220074956.png)

Hmm... We have admin access!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220075013.png)

Let's delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-9/images/Pasted%20image%2020221220075028.png)

Nice!

# What we've learned:

1. Authentication bypass via flawed state machine