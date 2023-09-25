# Exploiting time-sensitive vulnerabilities

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities), you'll learn: Exploiting time-sensitive vulnerabilities! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a password reset mechanism. Although it doesn't contain a race condition, you can exploit the mechanism's broken cryptography by sending carefully timed requests.

To solve the lab:

1. Identify the vulnerability in the way the website generates password reset tokens.
2. Obtain a valid password reset token for the user `carlos`.
3. Log in as `carlos`.
4. Access the admin panel and delete the user `carlos`.

You can log into your account with the following credentials: `wiener:peter`.

> **Note:**
>  
> Solving this lab requires Burp Suite 2023.9 or higher.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925140712.png)

In this web application, we can read different blog posts.

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925140733.png)

**What's that "Forgot password?" link?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925140809.png)

We can reset a user's password!

**Let's try `wiener` first and see what will happen:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925140944.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925141006.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925141020.png)

When we clicked the "Submit" button, it'll send a POST request to `/forgot-password` with `csrf` and `username` parameter.

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925141129.png)

We can go to the reset password endpoint to enter our new password!

**Reset password endpoint `/forgot-password?user=<username_here>&token=<token_here>`.**

Let's go there!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925141224.png)

In here, we can type our new password and change the old one.

**Time-sensitive attacks:**

Sometimes you may not find race conditions, but the techniques for delivering requests with precise timing can still reveal the presence of other vulnerabilities.

One such example is when high-resolution timestamps are used instead of cryptographically secure random strings to generate security tokens.

Consider a password reset token that is only randomized using a timestamp. In this case, it might be possible to trigger two password resets for two different users, which both use the same token. All you need to do is time the requests so that they generate the same timestamp.

Hmm... I wonder what's that password reset token.

**It looks like a hashed string, we can try to identify the hash algorithm via `hashid`:**
```shell
┌[siunam♥Mercury]-(~/ctf/Portswigger-Labs)-[2023.09.25|14:15:54(HKT)]
└> hashid '38b7357daa3f78c8f607dd539a06a2a1ecdc96df'
Analyzing '38b7357daa3f78c8f607dd539a06a2a1ecdc96df'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160) 
```

Oh! It's SHA-1 hash!

I'm also curious about **what's the original string before hashed**?

Maybe it's based on **timestamp**?

To test that, we can **send the generate token request (`POST /forgot-password`) in parallel.**

**First, let's try send that request in separate connections:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925142138.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925142152.png)

As you can see, the tokens are different.

**How about send in parallel?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925142253.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925142310.png)

They're still different?

**Then, I noticed that there's a delay between the requests:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925143605.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925143624.png)

That being said, our requests are being ***processed in sequence rather than concurrently***.

Also, in our session cookie name `phpsessionid`, it's suggested that **the backend is using PHP**.

**Session-based locking mechanisms:**

Some frameworks attempt to prevent accidental data corruption by using some form of request locking. For example, PHP's native session handler module only processes one request per session at a time.

It's extremely important to spot this kind of behavior as it can otherwise mask trivially exploitable vulnerabilities. If you notice that all of your requests are being processed sequentially, try sending each of them using a different session token.

**To solve our requests are being processed one request per session at a time, we can use a different session token:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144049.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144117.png)

> Note: Remember to retrieve the CSRF token.

**Then, in our Burp Suite's Repeater tab, replace the original session token cookie and CSRF token to a request tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144224.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144233.png)

**Next, send those requests in parallel and check the password reset token in our email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144313.png)

Nice!! We got the same password reset token!!

> Note: Sometimes it may fails, you could send those requests a couple more times.

## Exploitation

Armed with above information, it's clear that **the password reset token is generated via timestamp and SHA-1 hashed.**

**To perform account takeover on user `carlos`, we can simply change the `username` POST parameter to `carlos` in one of our Repeater's requests:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144538.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144559.png)

**Then, send those requests and get the password reset token, which should be the same as the `carlos` one.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925144751.png)

**Finally, send a POST request to `/forgot-password?user=carlos&token=<token_here>` with POST parameter `csrf`, `token`, `user`, `new-password-1`, and `new-password-2` to reset `carlos`'s password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925145015.png)

**Now, we should be able to login as user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925145044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925145051.png)

**Nice! Let's go to the admin panel and delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925145113.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-6/images/Pasted%20image%2020230925145118.png)

## Conclusion

What we've learned:

1. Exploiting time-sensitive vulnerabilities