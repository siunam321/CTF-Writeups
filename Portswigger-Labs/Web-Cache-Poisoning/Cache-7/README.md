# Parameter cloaking

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking), you'll learn: Parameter cloaking! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) because it excludes a certain parameter from the cache key. There is also inconsistent parameter parsing between the cache and the back-end. A user regularly visits this site's home page using Chrome.

To solve the lab, use the parameter cloaking technique to poison the cache with a response that executes `alert(1)` in the victim's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124185751.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124185819.png)

In here, we see that the web application is using caches to cache the web content.

Also, it has a canonical `<link>` element, which pointing to a domain.

**Maybe it's generated dynamically**?

**To test that, we can add a GET parameter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124185934.png)

Can confirm it's generated dynamically.

**However, we when get a cache hit, then remove the query string, it won't get reflected to the webpage:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124190049.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124190109.png)

This indicates that it is part of the cache key (Included in the cache).

Now, we need to **find an unkeyed input** (Not uncluded in the cache).

Some websites only exclude specific query parameters that are not relevant to the back-end application, such as parameters for analytics or serving targeted advertisements. UTM parameters like `utm_content` are good candidates to check during testing.

Let's test that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124190635.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124190650.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124190710.png)

When we remove the query string after cache hit, it still reflected to the web page. Hence, we found an unkeyed input.

**Now, we can try to inject an XSS payload:**
```html
?utm_content='><img src=error onerror=alert(1)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124191012.png)

However, our payload is being HTML encoded!! Which means we couldn't execute any JavaScript by injecting the XSS payload in `utm_content` unkeyed query parameter!

Let's take a step back.

**View source page:**
```html
[...]
<script type="text/javascript" src="/js/geolocate.js?callback=setCountryCookie"></script>
[...]
```

In here, it loaded a JavaScript file from `/js/geolocate.js`, with parameter `callback`.

**`/js/geolocate.js`:**
```js
const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
setCountryCookie({"country":"United Kingdom"});
```

Hmm... This looks like it's using JSONP (JSON with Padding).

> JSONP is a method for sending JSON data without worrying about cross-domain issues.
> JSONP does not use the `XMLHttpRequest` object.
> JSONP uses the `<script>` tag instead.
>  
> - Requesting a file from another domain can cause problems, due to cross-domain policy.
> - Requesting an external *script* from another domain does not have this problem.
> - JSONP uses this advantage, and request files using the script tag instead of the `XMLHttpRequest` object.

In JSONP, it's often contain a `callback` parameter to execute a given function on the returned data.

**In our case, it's:**
```js
GET /js/geolocate.js?callback=setCountryCookie
```

Armed with above information, **we can use a technique called "parameter cloaking"** (Similar to parameter pollution) to override the `callback` function!

**Payload:**
```js
/js/geolocate.js?callback=setCountryCookie&utm_content=test?callback=evilFunctionHere
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124193215.png)

**Hmm... It seems like `?` doesn't work. Let's try `;`:**

**Final payload:**
```js
/js/geolocate.js?callback=setCountryCookie&utm_content=test;callback=evilFunctionHere
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124193301.png)

It worked!

**Let's change the evil function to `alert(1)`, and poison the cache:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124193404.png)

**When the victim visit the home page, it'll triggered an XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124193427.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-7/images/Pasted%20image%2020230124193431.png)

# What we've learned:

1. Parameter cloaking