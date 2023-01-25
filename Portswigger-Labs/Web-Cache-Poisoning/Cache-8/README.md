# Web cache poisoning via a fat GET request

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get), you'll learn: Web cache poisoning via a fat GET request! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning). It accepts `GET` requests that have a body, but does not include the body in the cache key. A user regularly visits this site's home page using Chrome.

To solve the lab, poison the cache with a response that executes `alert(1)` in the victim's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125172557.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125172636.png)

In here, we see that the web application is using caches to cache the web content.

Also, it has a canonical `<link>` element, which pointing to a domain, and an `<script>` element.

**`/js/geolocate.js`:**
```js
const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
setCountryCookie({"country":"United Kingdom"});
```

**Now, we can test the canonical `<link>` element is generated dynamically or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125172846.png)

Yes, it's dynamically generated!

**Let's test the string query is keyed or not:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125172946.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173002.png)

When we get a cache hit, then remove the query string, it won't get reflected to the web page.

That being said, query strings are keyed, and we couldn't poison the cache.

**How about the `geolocate.js`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173227.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173245.png)

Hmm... The `callback` parameter is not unkeyed...

However, **the HTTP method may not be keyed**. This might allow us to poison the cache with a `POST` request containing a malicious payload in the body. Our payload would then even be served in response to users' `GET` requests. Although this scenario is pretty rare, **we can sometimes achieve a similar effect by simply adding a body to a `GET` request to create a "fat" `GET` request!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173503.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173520.png)

As you can see, our "fat" GET request has been taken from the server-side! Hence, it's unkeyed!

**Armed with above information, we can poison the cache with an evil JavaScript function:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173804.png)

**When a victim visit the website, it'll triggered our XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173828.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-8/images/Pasted%20image%2020230125173834.png)

# What we've learned:

1. Web cache poisoning via a fat GET request