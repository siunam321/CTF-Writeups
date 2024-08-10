# Exploiting origin server normalization for web cache deception

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1 [Exploiting Static Directory Cache Rules](#exploiting-static-directory-cache-rules)  
    3.2 [Normalization Discrepancies](#normalization-discrepancies)  
    3.3 [Detecting Normalization By the Origin Server](#detecting-normalization-by-the-origin-server)  
    3.4 [Detecting Normalization By the Cache Server](#detecting-normalization-by-the-cache-server)  
    3.5 [Exploiting Normalization By the Origin Server](#exploiting-normalization-by-the-origin-server)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-origin-server-normalization), you'll learn: Exploiting origin server normalization for web cache deception! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

To solve the lab, find the API key for the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`.

We have provided a list of possible delimiter characters to help you solve the lab: [Web cache deception lab delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list).

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810161331.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810161351.png)

In here, we can see that some static resources were being cached.

Login page:

Let's login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810161425.png)

After logging login, we can view our API key:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810161455.png)

In this lab, our goal is to steal user `carlos`'s API key.

In previous labs, we exploited the discrepancies in the URL path mapping and path delimiters.

### Exploiting Static Directory Cache Rules

It's common practice for web servers to store static resources in specific directories. Cache rules often target these directories by matching specific URL path prefixes, like `/static`, `/assets`, `/scripts`, or `/images`. These rules can also be vulnerable to web cache deception.

### Normalization Discrepancies

Normalization involves converting various representations of URL paths into a standardized format. This sometimes includes decoding encoded characters and resolving dot-segments, but this varies significantly from parser to parser.

Discrepancies in how the cache and origin server normalize the URL can enable an attacker to construct a path traversal payload that is interpreted differently by each parser. Consider the example `/static/..%2fprofile`:

- An origin server that decodes slash characters and resolves dot-segments would normalize the path to `/profile` and return profile information.
- A cache that doesn't resolve dot-segments or decode slashes would interpret the path as `/static/..%2fprofile`. If the cache stores responses for requests with the `/static` prefix, it would cache and serve the profile information.

As shown in the above example, each dot-segment in the path traversal sequence needs to be encoded. Otherwise, the victim's browser will resolve it before forwarding the request to the cache. Therefore, an exploitable normalization discrepancy requires that either the cache or origin server decodes characters in the path traversal sequence as well as resolving dot-segments.

### Detecting Normalization By the Origin Server

To test how the origin server normalizes the URL path, send a request to a non-cacheable resource with a path traversal sequence and an arbitrary directory at the start of the path. To choose a non-cacheable resource, look for a non-idempotent method like `POST`. For example, modify `/profile` to `/aaa/..%2fprofile`:

- If the response matches the base response and returns the profile information, this indicates that the path has been interpreted as `/profile`. The origin server decodes the slash and resolves the dot-segment.
- If the response doesn't match the base response, for example returning a `404` error message, this indicates that the path has been interpreted as `/aaa/..%2fprofile`. The origin server either doesn't decode the slash or resolve the dot-segment.

> Note
>  
> When testing for normalization, start by encoding only the second slash in the dot-segment. This is important because some CDNs match the slash following the static directory prefix.
>  
> We can also try encoding the full path traversal sequence, or encoding a dot instead of the slash. This can sometimes impact whether the parser decodes the sequence.

In our case, we can try to send a **POST request** to `/anything/..%2fmy-account`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810163916.png)

As you can see, it respond to us with HTTP status code "200 OK". That being said, **the origin server decodes the slash and resolves the dot-segment**.

### Detecting Normalization By the Cache Server

We can use a few different methods to test how the cache normalizes the path. Start by identifying potential static directories. In **Proxy > HTTP history**, look for requests with common static directory prefixes and cached responses. Focus on static resources by setting the HTTP history filter to only show messages with 2xx responses and script, images, and CSS MIME types.

We can then choose a request with a cached response and resend the request with a path traversal sequence and an arbitrary directory at the start of the static path. Choose a request with a response that contains evidence of being cached. For example, `/aaa/..%2fassets/js/stockCheck.js`:

- If the response is no longer cached, this indicates that the cache isn't normalizing the path before mapping it to the endpoint. It shows that there is a cache rule based on the `/assets` prefix.
- If the response is still cached, this may indicate that the cache has normalized the path to `/assets/js/stockCheck.js`.

We can also add a path traversal sequence after the directory prefix. For example, modify `/assets/js/stockCheck.js` to `/assets/..%2fjs/stockCheck.js`:

- If the response is no longer cached, this indicates that the cache decodes the slash and resolves the dot-segment during normalization, interpreting the path as `/js/stockCheck.js`. It shows that there is a cache rule based on the `/assets` prefix.
- If the response is still cached, this may indicate that the cache hasn't decoded the slash or resolved the dot-segment, interpreting the path as `/assets/..%2fjs/stockCheck.js`.

Note that in both cases, the response may be cached due to another cache rule, such as one based on the file extension. To confirm that the cache rule is based on the static directory, replace the path after the directory prefix with an arbitrary string. For example, `/assets/aaa`. If the response is still cached, this confirms the cache rule is based on the `/assets` prefix. Note that if the response doesn't appear to be cached, this doesn't necessarily rule out a static directory cache rule as sometimes `404` responses aren't cached.

> Note
>  
> It's possible that we may not be able to definitively determine whether the cache decodes dot-segments and decodes the URL path without attempting an exploit.

In our case, we can try to **add a path traversal sequence after the directory prefix**, such as from `/anything/resources/js/tracking.js` to `/anything/..%2fresources/js/tracking.js`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164131.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164156.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164220.png)

As you can see, the response is no longer cached, which means the cache isn't normalizing the path before mapping it to the endpoint. It shows that there is a cache rule based on the `/resources/` prefix.

### Exploiting Normalization By the Origin Server

If the origin server resolves encoded dot-segments, but the cache doesn't, we can attempt to exploit the discrepancy by constructing a payload according to the following structure: `/<static-directory-prefix>/..%2f<dynamic-path>`.

For example, consider the payload `/assets/..%2fprofile`:

- The cache interprets the path as: `/assets/..%2fprofile`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache.

In our case, we can exploit the discrepancy by the following payload:

```http
GET /resources/..%2fmy-account HTTP/2
Host: 0aa1004104cb94ff80c4ee10001a0010.web-security-academy.net


```

In here, the cache interprets the path as `/resources/..%2fmy-account`, and the origin server interprets it as `/my-account`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164436.png)

## Exploitation

Armed with above information, we can steal `carlos`'s API key via the discrepancy in normalization by the origin server. To do so, we can:
1. Trick the victim to visit `/resources/..%2fmy-account`, which caches the response of the API key
2. We, attacker, visit `/resources/..%2fmy-account` to retrieve the cached response

We can also test it before exploiting it on the victim side.

Send the following request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164657.png)

Then remove the `Cookie` request header:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164734.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810164743.png)

As you can see, we successfully retrieved the cached response's API key.

Now, to get `carlos`'s API key, we can:

Modify the response header to the following:

```http
HTTP/1.1 301 Moved Permanently
Location: https://0aa1004104cb94ff80c4ee10001a0010.web-security-academy.net/resources/..%2fmy-account
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165015.png)

Then click button "Deliver exploit to victim":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165036.png)

Next, send a GET request to `/resources/..%2fmy-account`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165100.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165112.png)

We got `carlos`'s API key! Let's submit it to solve this lab!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165133.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165145.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-3/images/Pasted%20image%2020240810165151.png)

## Conclusion

What we've learned:

1. Exploiting origin server normalization for web cache deception