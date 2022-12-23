# OS command injection, simple case

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/os-command-injection/lab-simple), you'll learn: OS command injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [OS command injection](https://portswigger.net/web-security/os-command-injection) vulnerability in the product stock checker.

The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

To solve the lab, execute the `whoami` command to determine the name of the current user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-1/images/Pasted%20image%2020221222223735.png)

**Product stock checker:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-1/images/Pasted%20image%2020221222223749.png)

**Let's click the `Check stock` button, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-1/images/Pasted%20image%2020221222223843.png)

When we clicked that button, **it'll send a POST request to `/product/stock`, with parameter `productId=1` and `storeId=1`.**

**Let's test for command injection:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-1/images/Pasted%20image%2020221222224217.png)

As you can see, when we provide single quote, **it triggers an `sh` shell error!**

Which indicates that **the `storeId` parameter is vulnerable to OS command injection**!

**Let's execute `whoami` command via `&&`, which tells the `sh` shell also run this command:**
```sh
&& whoami
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OS-Command-Injection/OSCI-1/images/Pasted%20image%2020221222224534.png)

> Note: The payload is URL encoded.

We successfully executed `whoami` command, and the web server user is `peter-TspwO7`!

# What we've learned:

1. OS command injection