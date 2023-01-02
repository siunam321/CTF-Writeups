# Multistep clickjacking

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/clickjacking/lab-multistep), you'll learn: Multistep clickjacking! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has some account functionality that is protected by a [CSRF token](https://portswigger.net/web-security/csrf/tokens) and also has a confirmation dialog to protect against [Clickjacking](https://portswigger.net/web-security/clickjacking). To solve this lab construct an attack that fools the user into clicking the delete account button and the confirmation dialog by clicking on "Click me first" and "Click me next" decoy actions. You will need to use two elements for this lab.

You can log in to the account yourself using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064500.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064508.png)

In here, we can delete our account.

**Let's craft a HTML file that fools the user into clicking the delete account button via Burp Suite's Clickbandit:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064650.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064658.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064727.png)

Click "Start":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064758.png)

Before click on the "Delete account", I'll turn on interception in Burp Suite, just in case we delete our account.

Click "Delete account" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102064945.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065001.png)

In here, we can see there is a confirmation prompt.

**Let's click "Yes" button, and drop the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065055.png)

Then click "Finish":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065313.png)

After that, turn off transparency, and click "Save":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065344.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065416.png)

**Finally, we can go to exploit server to host the clickjacking HTML payload, and deliver to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065536.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Clickjacking/Clickjacking-5/images/Pasted%20image%2020230102065542.png)

Nice! We successfully deleted victim's account.

# What we've learned:

1. Multistep clickjacking