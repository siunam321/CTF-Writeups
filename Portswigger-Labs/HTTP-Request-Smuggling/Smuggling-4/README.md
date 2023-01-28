# HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses), you'll learn: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

To solve the lab, smuggle a request to the back-end server, so that a subsequent request for `/` (the web root) triggers a 404 Not Found response.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-4/images/Pasted%20image%2020230128183613.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-4/images/Pasted%20image%2020230128183618.png)

We can send this request to Burp Suite Repeater to test HTTP request smuggling.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-4/images/Pasted%20image%2020230128183651.png)

Then change the request method to POST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-4/images/Pasted%20image%2020230128183714.png)

Now, we want to confirm the web application is vulnerable to CL.TE HTTP request smuggling (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header).

**To do so, we can first send an attack request:**
```http
POST / HTTP/1.1
Host: 0a3b0080037a1918c3ed3938006c0073.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Foo: x
```

This request will:

- The front-end server handles the `Content-Length` header
- The back-end server handles the `Transfer-Encoding` header, which means the `GET /404 HTTP/1.1\r\nX-Foo: x` will be smuggled to the back-end

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-4/images/Pasted%20image%2020230128184343.png)

**Then, we send a normal request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-4/images/Pasted%20image%2020230128184535.png)

Nice! We successfully smuggled our 404 request! Now we can confirm it's vulnerable to CL.TE HTTP request smuggling.

# What we've learned:

1. HTTP request smuggling, confirming a CL.TE vulnerability via differential responses