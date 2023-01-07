# Forced OAuth profile linking

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking), you'll learn: Forced OAuth profile linking! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab gives you the option to attach a social media profile to your account so that you can log in via [OAuth](https://portswigger.net/web-security/oauth) instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts.

To solve the lab, use a [CSRF attack](https://portswigger.net/web-security/csrf) to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete Carlos.

The admin user will open anything you send from the exploit server and they always have an active session on the blog website.

You can log in to your own accounts using the following credentials:

- Blog website account: `wiener:peter`
- Social media profile: `peter.wiener:hotdog`

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015136.png)

In here, we can see that we can "login with social media", which is usually using **OAuth**.

Let's try to login, and intercept all the requests via Burp Suite:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015255.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015319.png)

**In here, we see there are some GET parameters:**

- `client_id`: `rnr5hb6k0q4i2jinio6ir`
- `redirect_uri`: `https://0a0d006403a89dffc05e7cff00760098.web-security-academy.net/oauth-login`
- `response_type`: `code`
- `scope`: `openid profile email`

Let's break it down:

We see the `response_type` is set to `code`, which is using the **authorization code grant type**.

However, **the `state` parameter is missing!**

`state` parameter stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of [CSRF](https://portswigger.net/web-security/csrf) token for the client application by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow.

**That being said, the `state` parameter is a CSRF protection mechanism, which helps to prevent CSRF (Cross-Site Request Forgery) attack.**

Now, let's continue our OAuth login process:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015804.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015843.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015914.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107015950.png)

Let's log out and login without OAuth:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107020408.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107020428.png)

In here, we can "attach a social profile":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107020523.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107020537.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107020937.png)

When we clicked that link, it'll redirect me to `/auth`, which is the OAuth login process.

**Parameters:**

- `client_id`: `rnr5hb6k0q4i2jinio6ir`
- `redirect_uri`: `https://0a0d006403a89dffc05e7cff00760098.web-security-academy.net/oauth-linking`
- `response_type`: `code`
- `scope`: `openid profile email`

In the above parameters, the `redirect_uri` is different. It's redirecting to `/oauth-linking`. But most importantly, it also missing the `state` parameter again.

Armed with above information, we can try to attach our social profile to a victim.

Now, what if I send the GET `/oauth-linking?code=...` request to the victim? Will it attached my social profile to the victim?

**To do so, I'll use Burp Suite to intercept the GET `/oauth-linking?code=...` request, and then drop it. By doing that, we have a valid `code`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021339.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021355.png)

**Then log out, use the exploit server to create a CSRF payload, and deliver to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021457.png)

```html
<html>
    <head>
        <title>OAuth-2</title>
    </head>
    <body>
        <iframe src="https://0a0d006403a89dffc05e7cff00760098.web-security-academy.net/oauth-linking?code=VX7aM1uLd8lfBba_jhuAKx-CA2eHXKANZawjSnUQ41k"></iframe>
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021646.png)

**Now, we should able to login as the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021731.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021744.png)

I'm administrator!

Let's go to the admin panel and delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021808.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-2/images/Pasted%20image%2020230107021814.png)

# What we've learned:

1. Forced OAuth profile linking