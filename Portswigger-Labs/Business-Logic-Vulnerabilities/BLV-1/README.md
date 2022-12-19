# Excessive trust in client-side controls

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls), you'll learn: Excessive trust in client-side controls! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219045817.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219045909.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219045914.png)

**Let's go to the `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050159.png)

As you can see, **we only have `$100` store credit.**

**In the lab background, we need to buy the product `Lightweight l33t leather jacket`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050328.png)

**Let's click `view detail`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050347.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050355.png)

**Now, we can click the `Add to cart` button, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050511.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050532.png)

When we clicked that button, **it'll send a POST request to `/cart` with parameter: `productId=1`, `redir=PRODUCT`, `quantity=1`, and `price=133700`.**

**Let's forward that request, and go to `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050808.png)

In here, we see that the product has been added to our cart.

**Let's try to click `Place order` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219050911.png)

When we clicked the `Place order` button, **it'll send a POST request to `/cart/checkout` with a parameter `csrf`.**

**Let's forward that request and see what will happen:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051038.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051150.png)

When we don't have enough store credit to buy a product, **it'll send a GET request to `/cart` with parameter `err`, and it's value is `INSUFFICIENT_FUNDS`.**

**To exploit the application logic flaw, we need to `Remove` the product first:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051306.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051339.png)

When we clicked the `Remove` button, **it'll send a POST request to `/cart`, with parameter `productId=1`, `quantity=-1`, `redir=CART`.**

It seems like the parameter `redir` is redirecting to which page, like `/cart` for example.

**Now, let's go back to the product `Lightweight l33t leather jacket` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051658.png)

**Hmm... What if I set the price to 100($1.00)?**

**Let's modify and forward the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051729.png)

**Then go to `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051824.png)

**As we can see, that price changed from `$1337.00` to `$1.00`!!**

**Let's click the `Place order` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051913.png)

There is no error anymore!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-1/images/Pasted%20image%2020221219051959.png)

And we successfully purchased that product!

# What we've learned:

1. Excessive trust in client-side controls