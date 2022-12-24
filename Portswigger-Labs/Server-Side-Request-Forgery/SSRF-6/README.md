# SSRF with whitelist-based input filter

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter), you'll learn: SSRF with whitelist-based input filter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

The developer has deployed an anti-SSRF defense you will need to bypass.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224034727.png)

In the previous labs, we found that **the stock check feature is vulnerable to Server-Side Request Forgery(SSRF).**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224034742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224034816.png)

When we clicked the `Check stock` button, **it'll send a POST request to `/product/stock`, with parameter `stockApi`, and it's value is interesting.**

**URL decoded:**
```
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

**Now, what if I change the domain to `localhost`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224035014.png)

Hmm... The host must be `stock.weliketoshop.net`.

**To bypass that, we can use `@`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041026.png)

The application didn't block us.

**Next, we can use the `#` to create an HTML anchor:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041209.png)

However, this time didn't work.

**Let's try to double URL encode that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041246.png)

We bypassed that!

**Now, we can try to reach the `localhost`, which is the admin interface:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041526.png)

Nice! We now can reach the admin panel!

**Let's delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041600.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041620.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-6/images/Pasted%20image%2020221224041628.png)

We did it!

# What we've learned:

1. SSRF with whitelist-based input filter