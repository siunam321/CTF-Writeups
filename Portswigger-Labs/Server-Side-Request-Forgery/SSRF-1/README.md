# Basic SSRF against the local server

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost), you'll learn: Basic SSRF against the local server! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015447.png)

**Let's view one of those products detail:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015521.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015534.png)

In here, we can see that users are allowed to check the stock.

**Let's click the `Check stock` button, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015648.png)

When we clicked the `Check stock` button, **it'll send a POST request to `/product/stock`, with parameter `stockApi` and it's value is interesting:**

**URL decoded:**
```
http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
```

As you can see, it's sending a request to an **internal** API.

**What if I change the domain to `localhost`, and forward the request?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015938.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224015953.png)

**Oh! It displays the home page, and it has an admin panel!**

Armed with above information, it's clear that this **check stock function is vulnerable to Server-Side Request Forgery(SSRF)!**

**However, when we clicked the `admin panel` link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020125.png)

It's only available to adminsitrator or **request from localhost**!

**Let's change our SSRF payload to `http://localhost/admin`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020313.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020324.png)

We can see the admin panel! Let's try to delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020355.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020412.png)

**Again, we need to do it from the SSRF payload:**
```
http://localhost/admin/delete?username=carlos
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020450.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-1/images/Pasted%20image%2020221224020501.png)

We did it!

# What we've learned:

1. Basic SSRF against the local server