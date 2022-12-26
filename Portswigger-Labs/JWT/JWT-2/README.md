# JWT authentication bypass via flawed signature verification

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification), you'll learn: JWT authentication bypass via flawed signature verification! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226021044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226021053.png)

**Session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226021118.png)

```
eyJraWQiOiJkODQ3YzY3OS1iNThjLTQyOTAtYWI5MC0xZjY0NWM0NDc0Y2YiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY3MjA0MjI0N30.q4Bw5Wtt55NN4ZVIHLihoqWxi2OPIIFXXIIR8uKfvoo-ehcW5Mz-k_HTBS5ZzpuCThyvtDYJRq_ADK2OLDQlBLgKjSIUkB26APQ-SCLI5Hmoj20PTS7dbNhFgcn-mekYFu5D1AxyBgPUYNC8hSToX87LjcgJAIBnPCUe-KHJFvjC2drBBXtkRWYvIN7NR_ZigfIgAW75aipS9GHPIUdxRct0l-KTmFuFcbXIBEuBzNy3YzOR1lTxXracMP355jB6asr069tRUZHfjUjBhjv1QvH9JX_5ND45kKNOjEj76JxPJx5FkQXbFB-UDw-kZ9SOc25cBihWkPNG1VIQ_mY9HA
```

Let's copy and paste to [token.dev](https://token.dev/), which is an online tool that encode or decode JWTs.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226021220.png)

**We can try to go to the admin panel(`/admin`):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226022318.png)

It's only available to user `administrator`.

**In the [token.dev](https://token.dev/), let's change the payload's `sub` to `administrator`:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226022507.png)

**Then, copy and paste the newly modified JWT string to our session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226022541.png)

And refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226022558.png)

Hmm... Our session cookie is gone.

**Now, in the lab's background, it said:**

> The server is insecurely configured to accept unsigned JWTs.

**To exploit that, we can change the header's `alg`(algorithm) to `none`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226023836.png)

**However, we're not done yet. We have to add a trailing dot(`.`) after the payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226023921.png)

This is because the server will know that we have no signature.

**Then, we can copy and paste the newly modified JWT string to our session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226024012.png)

After that, refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226024117.png)

We now can delete user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/JWT/JWT-2/images/Pasted%20image%2020221226024140.png)

Nice!

# What we've learned:

1. JWT authentication bypass via flawed signature verification