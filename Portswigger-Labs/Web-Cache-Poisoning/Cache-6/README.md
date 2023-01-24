# Web cache poisoning via an unkeyed query parameter

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-param), you'll learn: Web cache poisoning via an unkeyed query parameter! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) because it excludes a certain parameter from the cache key. A user regularly visits this site's home page using Chrome.

To solve the lab, poison the cache with a response that executes `alert(1)` in the victim's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124181918.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124182001.png)

In here, we see that the web application is using caches to cache the web content.

Also, it has a canonical `<link>` element, which pointing to a domain.

**Maybe it's generated dynamically**?

**To test that, we can add a GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124182746.png)

As you can see, we'll get a cache miss when we change the query string. 

**However, we when get a cache hit, then remove the query string, it won't get reflected to the webpage:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124183144.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124183204.png)

This indicates that it is part of the cache key (Included in the cache).

Now, we need to **find an unkeyed input** (Not uncluded in the cache).

Some websites only exclude specific query parameters that are not relevant to the back-end application, such as parameters for analytics or serving targeted advertisements. UTM parameters like `utm_content` are good candidates to check during testing.

Parameters that have been excluded from the cache key are unlikely to have a significant impact on the response. The chances are there won't be any useful gadgets that accept input from these parameters. That said, some pages handle the entire URL in a vulnerable manner, making it possible to exploit arbitrary parameters.

**Let's test the `utm_content` parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124183539.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124183626.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124183644.png)

Nice! The `utm_content` parameter is unkeyed!

**Armed with above information, we can try to inject an XSS payload by escaping the `<link>` element's `href` attribute, and poison the cache:**
```html
?utm_content='><img src=errorpls onerror=alert(1)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124183958.png)

When the victim visit the home page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124184010.png)

It'll trigger an XSS payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-6/images/Pasted%20image%2020230124184027.png)

# What we've learned:

1. Web cache poisoning via an unkeyed query parameter