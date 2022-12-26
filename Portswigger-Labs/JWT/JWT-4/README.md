# JWT authentication bypass via jwk header injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection), you'll learn: JWT authentication bypass via jwk header injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. The server supports the `jwk` parameter in the [JWT](https://portswigger.net/web-security/jwt) header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

To solve the lab, modify and sign a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226030915.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226030924.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226030941.png)

```
eyJraWQiOiIyNTdjYjUxZS0xZDJlLTQ5YmEtYjMwOC1iNGJlOGY5ZjQ3NDAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA0NTc1N30.FQTmJHUrrBW4XiaFzBrtWchfKtywQzwjJsq4JHTJrdDGbCEJbZCJiG1-UbWBlV5qsYMY7-GXIxx1WCMCkUEhUQbIlOP5tqxaCJcjz4HuxerHIBPbwO-Ou4A-GxGsEM23Nou3hUh9Qp0-PZ2mZIllG3a6rRBQf--Ubz1ruMNt44_ln27Gb6MxCFlHlSn9JAkDnAxIdb1_TW2OkxwgAq2mqIdJgIyfeofliQfDZB4JZ-rA5QSHUgN8Zw0xfNcz6BQWYIdjQ1I1cGJT5wNBX3AQq9EZTHByGY3cPFEQ9v2T5BimzIzXcBfoUTYcTMBJb1TtiQgTk0SmZZjVTqXamRvgVg
```

In the previous labs, we found that the session cookie is using JWT(JSON Web Token), which is to handle sessions.

**Let's copy and paste that JWT string to [token.dev](https://token.dev/), which is an online tool to encode or decode JWT:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226031101.png)

As you can see, in the header's `alg`, it tells us **it's using RS256(RSA + SHA-256) algorithm.**

**In the lab's background, it said:**

> The server supports the `jwk`(JSON Web Key) parameter in the [JWT](https://portswigger.net/web-security/jwt) header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

To exploit that, we can sign a modified JWT using your own RSA private key, then embedding the matching public key in the `jwk` header.

Also, to make things simple, I'll use Burp Suite's extension `JWT Editor` and `JSON Web Tokens`, which are available for Burp Suite Commerical.

- Generate a new RSA key pair:

Go to **JWT Editor Keys** tab -> click **New RSA Key**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226035544.png)

Then click **Generate** (Default 2048 bits length, JWK key format):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226035613.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226035809.png)

- Embedding the matching public key in the `jwk` header:

**Send a request containing a JWT to Burp Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226035834.png)

In Repeater, switch to **JSON Web Token** tab:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040246.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040258.png)

**Modify the payload's `sub` value to `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040310.png)

Click **Attack**, then select **Embedded JWK**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040354.png)

**Select the newly generated RSA key:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040423.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040603.png)

The JWT header has changed to our public RSA key.

**Now, let's send the request and see what happen:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040715.png)

We're user `administrator`!

**Let's copy and paste that new JWT string to our session cookie, and refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040802.png)

We can finally go to the admin panel, and delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040820.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-4/images/Pasted%20image%2020221226040828.png)

Nice!

# What we've learned:

1. JWT authentication bypass via jwk header injection