# Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-to-exploit-a-dom-vulnerability-via-a-cache-with-strict-cacheability-criteria), you'll learn: Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab contains a DOM-based vulnerability that can be exploited as part of a [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) attack. A user visits the home page roughly once a minute. Note that the cache used by this lab has stricter criteria for deciding which responses are cacheable, so you will need to study the cache behavior closely.

To solve the lab, poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125201138.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125201248.png)

In here, we see the `/` doesn't allow cache.

**View source page:**
```html
[...]
<script>
    data = {
    "host":"0ad3008703db2f5fc1725345009d0044.web-security-academy.net",
    "path":"/",
    }
</script>
[...]
<script type="text/javascript" src="/resources/js/geolocate.js"></script>
[...]
<script>
    initGeoLocate('//' + data.host + '/resources/json/geolocate.json');
</script>
```

**As you can see, the website will load a JavaScript called `geolocate.js`:**
```js
function initGeoLocate(jsonUrl)
{
    fetch(jsonUrl)
        .then(r => r.json())
        .then(j => {
            let geoLocateContent = document.getElementById('shipping-info');

            let img = document.createElement("img");
            img.setAttribute("src", "/resources/images/localShipping.svg");
            geoLocateContent.appendChild(img)

            let div = document.createElement("div");
            div.innerHTML = 'Free shipping to ' + j.country;
            geoLocateContent.appendChild(div)
        });
}
```

It also ran a JavaScript function called `initGeoLocate()`, which parses the `data.host` JSON data.

**`geolocate.json`:**
```json
{
    "country": "United Kingdom"
}
```

Let's break `geolocate.js` down!

**When the `initGeoLocate()` function is called, it'll:**

- Send a GET request to `geolocate.json` and fetches it's JSON content
- Then it'll create an `<img>` element, and set the `src` attribute to `localShipping.svg`
- After that, create an `<div>` element, and using **`innerHTML` sink** (Dangerous function) to append the `geolocate.json`'s `country` value.

Armed with above information, **we can try to exploit DOM-based XSS via the `innerHTML` sink in `geolocate.js`!**

But first, we need to find the source (Attacker's controlled input).

**In the view source page, we found this:**
```html
<script>
    data = {
    "host":"0ad3008703db2f5fc1725345009d0044.web-security-academy.net",
    "path":"/",
    }
</script>
```

**If we can control the `data.host` value**, we can basically load any JSON file from anywhere!

**The evil JSON file can contain an XSS payload:**
```json
{
    "country": "<img src=errorpls onerror=alert(document.cookie)>"
}
```

After it fetches our evil JSON file, **it'll append our XSS payload to the `j.country` in the `geolocate.js`** JavaScript file, which will then trigger our XSS payload!!

**After some trial and error, I found that the web application accept `X-Forwarded-Host` HTTP header!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125203041.png)

That being said, we can override the `data.host` value!!

**We now can go to exploit server, and host our evil JSON file!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125203210.png)

Then, intercept the `/` GET request, and add the `X-Forwarded-Host` HTTP header with the exploit server domain:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125203358.png)

Forward the request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125204103.png)

Nope. That doesn't work.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125204217.png)

By studying the request histories, we found that **our normal request has been cached!**

**Armed with above information, we can wait for the normal request's cache dies, and poison the cache with our `X-Forwarded-Host`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125204532.png)

**Then, go to `/`, we should be able to trigger the XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125204622.png)

Nope...

Our evil JSON file didn't loaded because of the CORS (Cross-Origin Resource Sharing) Policy...

**Luckly, we can add a HTTP header called `Access-Control-Allow-Origin`!**

**That being said, go back to the exploit server, and add a HTTP header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125205116.png)

**Now poison the cache again, and we should trigger the XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125205159.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125205207.png)

Nice!!!

**When a victim visit the website, the poisoned cache will be delivered to the victim, and thus trigger our XSS payload!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-10/images/Pasted%20image%2020230125205246.png)

# What we've learned:

1. Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria