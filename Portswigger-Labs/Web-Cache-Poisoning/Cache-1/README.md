# Web cache poisoning with an unkeyed header

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header), you'll learn: Web cache poisoning with an unkeyed header! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) because it handles input from an unkeyed header in an unsafe way. An unsuspecting user regularly visits the site's home page. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122173716.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122173923.png)

In here, we see that the web server is using web cache. We can try to exploit web cache poisoning.

**View source page:**
```html
<script type="text/javascript" src="//0aac000d032848eac0a590ea0070009e.web-security-academy.net/resources/js/tracking.js"></script>
```

In here, this imported JavaScript is weird to me, as **the `src` attribute is referring to a domain**.

**After some fumbling, I found that the web application accepts unkeyed `X-Forwarded-Host` HTTP header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122174709.png)

> Note: To prevent other users are being affected by our testing payload, we can use cache buster, which basically adding a random GET parameter.

We can inject anything we want to the `src` attribute is the imported `tracking.js` script file!

**Armed with above information, we can inject a JavaScript that executes `alert(document.cookie)` in our browser!**
```html
"></script><img src=errorpls onerror=alert(document.cookie)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175643.png)

Nice!

Next, we need to posion the web cache.

To do so, I'll **send the XSS payload request multiple times, until the cache is hit:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175732.png)

**Then, we can go to `/?buster=buster1` without the XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175749.png)

Cool!

**Now, we can really posion the home page by removing the cache buster, and repeat the previous step!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175916.png)

When the victim visit the home page, it'll trigger our XSS payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-1/images/Pasted%20image%2020230122175939.png)

# What we've learned:

1. Web cache poisoning with an unkeyed header