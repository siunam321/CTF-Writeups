# JWT authentication bypass via weak signing key

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key), you'll learn: JWT authentication bypass via weak signing key! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a [wordlist of common secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list).

To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226024759.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226024806.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226024824.png)

```
eyJraWQiOiJiN2JiYzViMS1hYTNhLTQ1NDYtODFlZi1kNTdkYzRlN2JkYmQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA0NDQ4MH0.6F8-9Bnb0sqQDK2iDVGiKrMFULKk58KRj6RBBu3kYDk
```

In the previous labs, we found that the session cookie is using JWT(JSON Web Token) to handle sessions.

**Let's copy and paste that to [token.dev](https://token.dev/), which is an online tool to encode or decode JWT:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226025035.png)

As you can see, the algorithm is HS256(HMAC + SHA-256), which uses an arbitrary, standalone string as the secret key.

So, **what if we know the secret key**? If we know that, **we can create JWTs with any header and payload values, then use the key to re-sign the token with a valid signature!**

**To do so, we can use `john`(John The Ripper) to brute force the secret key.**

Also, we'll need to provide a [wordlist](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list), which contains a list of common secret key.

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/JWT]
└─# echo -n "eyJraWQiOiJiN2JiYzViMS1hYTNhLTQ1NDYtODFlZi1kNTdkYzRlN2JkYmQiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA0NDQ4MH0.6F8-9Bnb0sqQDK2iDVGiKrMFULKk58KRj6RBBu3kYDk" > JWT-3.txt
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/JWT]
└─# john --wordlist=/opt/jwt.secrets.list JWT-3.txt 
[...]
secret1          (?)     
[...]
```

Nice! **It found secret key: `secret1`.**

Next, we now can **use the secret key to generate a valid signature for any JWT header and payload**!

**To do so, I'll use another online tool called [jwt.io](https://jwt.io/), which allows us to generate a valid signature:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226025907.png)

**After that, we can change the payload's `sub` to `administrator`, so that we can access to the admin panel:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226025945.png)

**Let's copy and paste that newly generated JWT string to our session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226030013.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226030027.png)

We're now user `administrator`! Let's go to the admin panel and delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226030053.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-3/images/Pasted%20image%2020221226030102.png)

# What we've learned:

1. JWT authentication bypass via weak signing key