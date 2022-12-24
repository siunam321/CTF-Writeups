# SSRF with blacklist-based input filter

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter), you'll learn: SSRF with blacklist-based input filter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224025549.png)

In the previous labs, we found that **the stock check feature has a Server-Side Request Forgery(SSRF) vulnerability:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224025641.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224025849.png)

We clicked the `Check stock` button, **it'll send a POST request to `/product/stock`, with parameter `stockApi`, and it's value is interesting:**

**URL decoded:**
```
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

**Now, what if I change the domain to `localhost`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030030.png)

It gets blocked.

**How about `127.0.0.1`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030102.png)

Same.

**To bypass this filter, we can use refer to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass#localhost):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030233.png)

**Let's use `127.1`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224030931.png)

Hmm... Still getting blocked.

**Maybe the application is checking the word `admin`?**

**If in that case, we can obfuscate that word:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031030.png)

Nice! We now can reach the admin panel.

**Let's delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031100.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031124.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-3/images/Pasted%20image%2020221224031130.png)

We did it!

# What we've learned:

1. SSRF with blacklist-based input filter