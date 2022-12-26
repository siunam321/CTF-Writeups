# JWT authentication bypass via kid header path traversal

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal), you'll learn: JWT authentication bypass via kid header path traversal! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. In order to verify the signature, the server uses the `kid` parameter in [JWT](https://portswigger.net/web-security/jwt) header to fetch the relevant key from its filesystem.

To solve the lab, forge a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226054237.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226054257.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226054317.png)

```
eyJraWQiOiI4ODJkMTIwMC02MTk1LTRkYzEtYTBmNS05NTMyMmUyYjBhMjEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA1NDk2N30.7cv6vxO0J1BBocVXBQlmDrKdXDGKmQsvQ-4A7Du46PY
```

In the previous labs, we found that the session cookie is using JWT(JSON Web Token) to handle sessions.

**Let's copy and paste that to [token.dev](https://token.dev/), which is encode or decode JWT string:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226054500.png)

As you can see, in the header's `alg`, it's using an algorithm called HS256(HMAC + SHA-256), which is a [symmetric algorithm](https://portswigger.net/web-security/jwt/algorithm-confusion#symmetric-vs-asymmetric-algorithms).

**In the lab's background, it said:**

> In order to verify the signature, the server uses the `kid` parameter in [JWT](https://portswigger.net/web-security/jwt) header to fetch the relevant key from its filesystem.

Armed with above information, now we know that the `kid` parameter is from the web server's filesystem.

**Hmm... What if that parameter is vulnerable to directory traversal?**

If in that case, an attacker could potentially **force the server to use an arbitrary file from its filesystem as the verification key**.

To do so, we can point the `kid` parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file. For example, in Linux, `/dev/null` is an empty file, fetching it returns null. Therefore, signing the token with a Base64-encoded null byte will result in a valid signature.

- Base64 encode a null byte:

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/JWT]
└─# python3        
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from base64 import b64encode
>>> 
>>> print(b64encode(b'\x00'))
b'AA=='
```

**A base64 encoded null byte: `AA==`.**

- Sign a valid signature:

**In here, I'll use an online tool called [jwt.io](https://jwt.io/) to do that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226055736.png)

- Modify payload's `sub` claim to `administrator`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226055802.png)

- Modify header's `kid` claim to a directory traversal payload, which point to `/dev/null`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226060114.png)

- Copy newly created JWT string and paste that to our session cookie:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226060129.png)

- Refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226060148.png)

We're user `administrator`, let's go to the admin panel and delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226060209.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-6/images/Pasted%20image%2020221226060219.png)

# What we've learned:

1. JWT authentication bypass via kid header path traversal