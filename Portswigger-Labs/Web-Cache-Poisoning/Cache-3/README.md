# Web cache poisoning with multiple headers

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-multiple-headers), you'll learn: Web cache poisoning with multiple headers! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) vulnerability that is only exploitable when you use multiple headers to craft a malicious request. A user visits the home page roughly once a minute. To solve this lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123184328.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123184347.png)

In here, we see that the web application is using caches to cache the web content.

**View source page:**
```html
<script type="text/javascript" src="/resources/js/tracking.js"></script>
```

**In here, we see there is a JavaScript file is loaded:**
```js
document.write('<img src="/resources/images/tracker.gif?page=post">');
```

Which is a **`document.write` sink** (Dangerous function) that writes an `<img>` element to the web page.

Now, **what if I change the scheme from HTTPS to HTTP?**

**To do so, we could use a HTTP header called `X-Forwarded-Scheme`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123190314.png)

As you can see, we're redirecting to HTTPS scheme. So, the web application enforced a secure communication using HTTPS. To enforce this, if a request that uses another protocol is received, the website dynamically generates a redirect to itself that does use HTTPS.

Armed with above information, **we can try to control the dynamically generated redirect link.**

**To do so, we could use `X-Forwarded-Host` HTTP header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123190358.png)

Nice! We can control the domain!

That being said, we can load any JavaScript file from any website!!

**Now, we can load an evil JavaScript file from our exploit server, which has a JavaScript payload `alert()`:**
```js
document.write('<script>alert(document.cookie)</script>');
```

Then host the payload on the exploit server:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123190619.png)

**After that, we can try to poison the cache:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123190724.png)

Now, who ever visit the home page, they will loaded our evil JavaScript file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123190825.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-3/images/Pasted%20image%2020230123190734.png)

Nice!

# What we've learned:

1. Web cache poisoning with multiple headers