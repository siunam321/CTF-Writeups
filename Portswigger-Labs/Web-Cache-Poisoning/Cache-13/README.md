# Internal cache poisoning

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal), you'll learn: Internal cache poisoning! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning). It uses multiple layers of caching. A user regularly visits this site's home page using Chrome.

To solve the lab, poison the internal cache so that the home page executes `alert(document.cookie)` in the victim's browser.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126211934.png)

**View source page:**
```html
<link rel="canonical" href='//0a0a00a404705384c0c007fd008000da.web-security-academy.net/'/>
[...]
<script type="text/javascript" src="//0a0a00a404705384c0c007fd008000da.web-security-academy.net/resources/js/analytics.js"></script>
<script src=//0a0a00a404705384c0c007fd008000da.web-security-academy.net/js/geolocate.js?callback=loadCountry></script>
<script>
    trackingID='bRsp6pn2AnfToVhm'
</script>
```

As you can see, it has a canonical `<link>` element, and loaded 2 JavaScript files: `analytics.js`, `geolocate.js`.

**analytics.js:**
```js
function randomString(length, chars) {
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}
var id = randomString(16, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
fetch('/analytics?id=' + id)
```

**geolocate.js:**
```js
const setCountryCookie = (country) => { document.cookie = 'country=' + country; };
const setLangCookie = (lang) => { document.cookie = 'lang=' + lang; };
loadCountry({"country":"United Kingdom"});
```

Also, it seems like the `src` and `href` are dynamically generated?

**Let's use a HTTP header called `X-Forwarded-Host` to change the host value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126212722.png)

In here, **we can control the host of `analytics.js`.**

**Also, we can add a GET parameter in `/`, and the canonical `<link>` element is reflected:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126213159.png)

That being said, we can control the host of both elements, and GET parameter in canonical `<link>` element.

**Now, we can keep trying to send the request with the `X-Forwarded-Host` header, and something weird will happened:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126213600.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126213828.png)

When I changed a different GET parameter value, **the imported `geolocate.js` JavaScript host also changed!**

This indicates that this fragment is being cached separately by the **internal cache**. Notice that we've been getting a cache hit for this fragment even with the cache-buster query parameter - the query string is unkeyed by the internal cache.

**Let's get a cache hit, and try to remove the `X-Forwarded-Host` header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126214013.png)

Hmm... The internally cached fragment still reflects our exploit server URL, but the other two URLs don't. This indicates that the header is unkeyed by the internal cache but keyed by the external one.

Therefore, we can poison the internally cached fragment using this header.

**To exploit this internal cache poisoning, we can:**

- Host our own evil `/js/geolocate.js`, with payload `alert(document.cookie)`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126214309.png)

- Poison the internal cache:

**To do so, remove the cache buster, and add back the `X-Forwarded-Host`. Then keep sending the request until we hit the cache:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-13/images/Pasted%20image%2020230126214546.png)

# What we've learned:

1. Internal cache poisoning