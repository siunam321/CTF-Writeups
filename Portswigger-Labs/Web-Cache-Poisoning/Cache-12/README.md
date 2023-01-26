# Cache key injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-cache-key-injection), you'll learn: Cache key injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab contains multiple independent vulnerabilities, including cache key injection. A user regularly visits this site's home page using Chrome.

To solve the lab, combine the vulnerabilities to execute `alert(1)` in the victim's browser. Note that you will need to make use of the `Pragma: x-get-cache-key` header in order to solve this lab.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126193838.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126193851.png)

When we go to `/`, if we're not authenticated, we'll redirected to `/login` with parameter `lang=en`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126194122.png)

Also, the `/login/`'s parameter `lang` doesn't allow to be cached. 

Moreover, the `Vary` header is set to `Origin`. The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed. Hence, in this case, the `Origin` header is keyed.

**View source page:**
```html
<link rel="canonical" href='//0ad9004404e23626c2edfc4f00b100f0.web-security-academy.net/login/?lang=en'/>
[...]
<script src='/js/localize.js?lang=en&cors=0'></script>
```

As you can see, it has a canonical `<link>` element, and loaded a JavaScript called `localize.js` with parameter `lang` and `cors`.

**localize.js:**
```js
document.cookie = 'lang=en';
```

This script will set a new cookie called `lang`.

Armed with above information, it seems like the canonical `<link>` and `<script>` element is dynamically generated.

**Let's try to change it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126195227.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126195234.png)

As you can see, we can control those 2 elements!

We can try to inject a XSS payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126195436.png)

However, our payload is being HTML encoded!

**Luckly, we can still try to inject our payload in the canonical `<link>` element:**
```html
'/><script>alert(1)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126195640.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126195711.png)

Nice! We found a reflected XSS vulnerability!

However, this reflected XSS request's cache can't be poisoned.

After some testing, I found that in `/login` the parameter `utm_content` from the cache key flawed regex. This allows us append arbitrary unkeyed content to the `lang` parameter:

```
/login?lang=en?utm_content=test
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126202048.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126202105.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126203821.png)

That being said, **the import of `localize.js` is vulnerable to parameter pollution.**

**Also, we can test the `Origin` header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126203912.png)

As you can see, nothing happened when we add that header.

**However, since this JavaScript has a parameter called `cors`, we can enable it by setting it to `1`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126204029.png)

**Then, we can use the `Pragma: x-get-cache-key` header to identify that the server is vulnerable to cache key injection, meaning the header injection can be triggered via a crafted URL:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126204345.png)

By combining the above quirks, we can **exploit cache key injection and HTTP request smuggling!**

- **First, we need to smuggle `localize.js` to be our `alert(1)` payload:**

```
GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/1.1
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
```

This request will set the `cors` to 1, which allows `Origin` header. Then, we first set the `Access-Control-Allow-Origin` response header to `x` (This could be anything). After that, smuggle the "new line & carriage return" character (`\r\n` or `%0d%0a` in URL encoding), `Content-Length` to `8`, and our payload.

**The URL decoded smuggling response will be:**
```
Access-Control-Allow-Origin: x
[...]
Content-Length: 8

alert(1)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126210325.png)

- Secondly, poison `/login?lang=en`:

```
GET /login?lang=en?utm_content=x%26cors=1%26x=1$$Origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/1.1
```

This request will redirects victim to a login page with a poisoned and smuggled JavaScript, which will then execute `alert(1)`.

**Let's poison those cache!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-12/images/Pasted%20image%2020230126210638.png)

Nice!

# What we've learned:

1. Cache key injection