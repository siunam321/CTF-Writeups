# JWT authentication bypass via jku header injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection), you'll learn: JWT authentication bypass via jku header injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. The server supports the `jku` parameter in the [JWT](https://portswigger.net/web-security/jwt) header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226041708.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226041716.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226041734.png)

```
eyJraWQiOiIwYTA5ZDVmMC1kZGMzLTQ4MDYtODE3Ni1iYmM2NWM2YTQxMTMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA0OTgyOX0.Tv742QFe5WpfTz2bRP0QUsgti8QKWO-Z2nMVdLyG43SUtYS_dH8Fd-043tExu8qdckw1QA3XzF7YeuMET3JZxd7tC_RG9ijJN6kIMyQd3IPethI4fbZUaQoz_9xsy2DnSLJyinReZYTNJQBn88s-noNfJG_PSkSd1KI12TLYKUWCHxQ3HAUBLOh_XMlMoP2ORowmQvJq-BA0lPh89ESfYlfjZD6ZYIF-lBNneA_8sCDGrLquPaDbfYGkhm_EQIEu8c8E2WpwabdOyOjZNnSIhp3bIrsJfhkmSRdmFUOg1cm7jOyZotJI9OQ7Nm0QAbtV01cguCRtwbwwP6mxTfKRxQ
```

In the previous labs, we found that the session cookie is using JWT(JSON Web Token) to handle sessions.

**When we go to the admin panel(`/admin`), it displays it's only available to user `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226042733.png)

**Let's copy and paste that to [token.dev](https://token.dev/), which is an online tool that encodes or decodes JWT string:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226041858.png)

As you can see, in the header's `alg`, it tells us it's using RS256(RSA + SHA-256) algorithm.

**Also, in the lab's background, it said:**

> The server supports the `jku`(JWK Set URL) parameter in the [JWT](https://portswigger.net/web-security/jwt) header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

**To exploit that, we need to do 2 things:**

- Upload a malicious JWK Set:

**Send a request that's containing the JWT to Burp Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226042615.png)

**Generate a new RSA key pair:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226042900.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226042912.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226043529.png)

**Then, go to the exploit server, and create an empty JWK Set:**
```json
{
    "keys": [

    ]
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226043308.png)

**After that, copy public key value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226043602.png)

```json
{
    "kty": "RSA",
    "e": "AQAB",
    "kid": "29825d49-e167-463e-abd0-3325fe458e53",
    "n": "yCV4msBrE54NxHOcovriREH6daHhtk6VWt23bMc58_KcXzIScejwPSZcyBMEVs3Tn8H82vG2R9TIdN4CSSDXBVkdXZqrhH2I7tHFElYujq4XmOJAy4mFVcP7qlmsVYoA6_6q-F_GV8y9DfFVxGc4L5WDNYvkfks_TXkThXt5FWZogmbB8fr1CxIXsfb6bToG3p_hNKNPN8Y6ONoQyjRjVDWdB9Wv-tjAzGdKoXKJ6Qs1mecp6X0MSnabbuKWKPtBQJCc94vm9HMjpiaZbMLPACopafDX1Eet9juItYJHfs9zAQz3utHGizpZKxOZ7a0iUDco3Lggf4x3FTeN1sh6Cw"
}
```

**Paste the JWK into the `keys` array on the exploit server, then `Store` the exploit:**
```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "29825d49-e167-463e-abd0-3325fe458e53",
            "n": "yCV4msBrE54NxHOcovriREH6daHhtk6VWt23bMc58_KcXzIScejwPSZcyBMEVs3Tn8H82vG2R9TIdN4CSSDXBVkdXZqrhH2I7tHFElYujq4XmOJAy4mFVcP7qlmsVYoA6_6q-F_GV8y9DfFVxGc4L5WDNYvkfks_TXkThXt5FWZogmbB8fr1CxIXsfb6bToG3p_hNKNPN8Y6ONoQyjRjVDWdB9Wv-tjAzGdKoXKJ6Qs1mecp6X0MSnabbuKWKPtBQJCc94vm9HMjpiaZbMLPACopafDX1Eet9juItYJHfs9zAQz3utHGizpZKxOZ7a0iUDco3Lggf4x3FTeN1sh6Cw"
        }
    ]
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226043749.png)

- Modify and sign the JWT

**Go back to Burp Repeater and switch to the extension-generated JSON Web Token message editor tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226043914.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226043937.png)

**In the header of the JWT, replace the current value of the `kid` parameter with the `kid` of the JWK that you uploaded to the exploit server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044035.png)

**Add a new `jku` parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044145.png)

**In the payload, change the value of the `sub` claim to `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044201.png)

**At the bottom of the tab, click Sign, then select the RSA key that you generated in the previous section:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044239.png)

Now, we should be user `administrator`, let's send a GET request to `/my-account`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044349.png)

Nice! Let's copy the newly created JWT string and paste it to session cookie:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044438.png)

Let's delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-5/images/Pasted%20image%2020221226044455.png)

# What we've learned:

1. JWT authentication bypass via jku header injection