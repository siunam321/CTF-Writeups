# SSRF with filter bypass via open redirection vulnerability

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection), you'll learn: SSRF with filter bypass via open redirection vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224031924.png)

In the previous labs, we found that **the stock check feature is vulnerable to Server-Side Request Forgery(SSRF).**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224031937.png)

**This time however, we couldn't supply our own domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224032037.png)

**URL decoded:**
```
/product/stock/check?productId=1&storeId=1
```

Let's take a step back.

**In the product page, we also can see a `New product` link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224032139.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224032158.png)

Hmm... **The `path` parameter might vulnerable to open redirect!**

**Let's test it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224032416.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224032431.png)

**It indeed redirect me to my website! Can confirm it's vulnerable to open redirect.**

**Let's chain those vulnerabilities: Open redirect -> SSRF**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224033546.png)

**Payload:**
```
/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224033703.png)

**Nice! Let's delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224033742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-4/images/Pasted%20image%2020221224033803.png)

We did it!

# What we've learned:

1. SSRF with filter bypass via open redirection vulnerability