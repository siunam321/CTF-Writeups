# High-level logic vulnerability

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level), you'll learn: High-level logic vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219052940.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219053045.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219053055.png)

As you can see, we have `$100.00` store credit.

In the previous lab, we found an application logic flaw in no validation in price value.

**Now, let's go to product `Lightweight l33t leather jacket` page, and intercept the `Add to cart` button's request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054230.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054252.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054315.png)

When we clicked the `Add to cart` button, **it'll send a POST request to `/cart`, with parameter `productId=1`, `redir=PRODUCT`, `quantity=1`.**

**Now, what if I change the `quantity` value to a negative value? Like `-1`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054458.png)

**Let's forward that request and go to `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054553.png)

**As you can see, the product's quantity is `-1`, and the price is `-$1337.00`!**

**Now, what if I click the `Place order` button?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054649.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054704.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219054737.png)

However, we see an error that says `Cart total price cannot be less than zero`.

**Hmm... To bypass that, we can buy a `-1` quantity of the leather jacket, and buy other products. By doing that, the total price should be positive, not negative.**

**Let's purchase 190 quantity of product `What Do You Meme?`:** (`7.04 * 190 = 1337.6`)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219055513.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219055603.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219055614.png)

**Let's forward that request and go to `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219055650.png)

As you can see, the total price became a positive number!

**Let's click the `Place order` button!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219055737.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219055835.png)

Hmm... Let's do that in the opposite way.

**Now, we need to buy `1` leather jacket, and that buy negative quantity of any products. That way, we can reduce the total price.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219060024.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219060410.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219060431.png)

**Let's click the `Place order` button!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-2/images/Pasted%20image%2020221219060503.png)

We finally bought the leather jacket!

# What we've learned:

1. High-level logic vulnerability