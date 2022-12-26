# JWT authentication bypass via unverified signature

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature), you'll learn: JWT authentication bypass via unverified signature! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226014653.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226014702.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226014727.png)

```jwt
eyJraWQiOiI0NWQyYmU4Zi03MmNjLTRiYjQtOGQyNy1jY2FmODU0MjA5Y2UiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA0MDgxNX0.oMDhwyF-Cd6DxHjPxlfZ1_7PJqLT-6PtDaNXtZs2bFVN3HvIS_xidTq8KX7OuQGSng9FtZhijD_DV16Xw0axAMasA4_Gqj3rBqUEE_I_KVt51qQ1VvDMxcx4mhQGi_wGXs3oyv8_Rhiz4uYHvryKDL5mS7AWzmL-ObmhWc3XOhzZ8TsksZkRMjiIJ3vKhIIhqtX8P-NLEp8k-eY0CR9OcVQAFzhirYD97Ul4b3aD05DY6qD_bKycL8hbGKP9vYKLwUuPH08MTVZGkk77ggGzvKbWcEV2hxZt6KF_XOQx3NBTotR_Ds-slBtd-XmpSgtmIeSMMiJJpA3oPaERCEK9Ew
```

As you can see, this session cookie is a JWT(JSON Web Token), as a **JWT consists of 3 parts: a header, a payload, and a signature**. They are each **separated by a dot**.

**Let's copy and paste that to [token.dev](https://token.dev/), which is an online tool that encode or decode JWTs:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226015041.png)

As you can see, in the header part, the signature's algorithm is RS256(RSA + SHA-256), and it has a kid(Key ID). In the payload part, it has an issuer(`portswigger`), subject(`wiener`), and expires(`1672040815`).

**Now, in the lab's background, it said:**

> Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

Armed with above information, **we can just simply modify payload's subject to `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226015650.png)

**Then we copy and paste the modified JWT string to the session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226015745.png)

**Finally, refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226015801.png)

We're `administrator`, and have access to the admin panel!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226015830.png)

Let's delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-1/images/Pasted%20image%2020221226015844.png)

Nice!

# What we've learned:

1. JWT authentication bypass via unverified signature