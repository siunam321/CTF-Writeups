# Insufficient workflow validation

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation), you'll learn: Insufficient workflow validation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab makes flawed assumptions about the sequence of events in the purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220065924.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220065950.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220065955.png)

**Now, we can try to buy the `Lightweight l33t leather jacket`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070102.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070115.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070127.png)

When we clicked the `Add to cart` button, **it'll send a POST request to `/cart`, with parameter `productId=1`, `redir=PRODUCT` and `quantity`.**

**Then, we can go to `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070246.png)

As you can see, we have added that product to our cart.

**Let's try to click the `Place order` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070317.png)

When we clicked that button, **it'll send a POST request to `/cart/checkout`, with parameter `csrf`.**

**Let's forward that request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070358.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070446.png)

When we don't have enough store credits, **it'll send a GET request to `/cart`, with parameter `err=INSUFFICIENT_FUNDS`.**

**Let's remove that product from our cart:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070609.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220070711.png)

When we clicked the `Remove` button, **it'll send a POST request to `/cart`, with parameter `productId`, `quantity` and `redir=CART`.**

**Armed with above information, what if we successfully bought a product?**

Let's say product `Eggtastic, Fun, Food Eggcessories`

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220071816.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220071844.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220071859.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220071911.png)

When we have enough store credits, **it'll send a GET request to `/cart/order-confirmation`, with parameter `order-confirmed=true`.**

**Hmm... What if we add the leather jacket to cart, and then send a GET request to `/cart/order-confirmation` with parameter `order-confirmed=true`?**

Let's do that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220072144.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-8/images/Pasted%20image%2020221220072207.png)

We did it!

# What we've learned:

1. Insufficient workflow validation