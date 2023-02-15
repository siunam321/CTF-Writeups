# CL.0 request smuggling

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/browser/cl-0/lab-cl-0-request-smuggling), you'll learn: CL.0 request smuggling! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to CL.0 request smuggling attacks. The back-end server ignores the `Content-Length` header on requests to some endpoints.

To solve the lab, identify a vulnerable endpoint, smuggle a request to the back-end to access to the admin panel at `/admin`, then delete the user `carlos`.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks#cl.0).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215191633.png)

**In the home page, we see there is a "Admin panel":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215191658.png)

However, it's blocked.

Maybe we can bypass that via HTTP request smuggling?

In `/`, we can try to test **CL.0 HTTP request smuggling**.

Request smuggling vulnerabilities are the result of discrepancies in how chained systems determine where each request starts and ends. This is typically due to [inconsistent header parsing](https://portswigger.net/web-security/request-smuggling#how-do-http-request-smuggling-vulnerabilities-arise), leading to one server using a request's `Content-Length` and the other treating the message as chunked. However, it's possible to perform many of the same attacks without relying on either of these issues.

In some instances, servers can be persuaded to ignore the `Content-Length` header, meaning they assume that each request finishes at the end of the headers. This is effectively the same as treating the `Content-Length` as `0`.

If the back-end server exhibits this behavior, but the front-end still uses the `Content-Length` header to determine where the request ends, we can potentially exploit this discrepancy for HTTP request smuggling. This vulnerability is called "CL.0".

To probe for CL.0 vulnerabilities, first send a request containing another partial request in its body, then send a normal follow-up request. We can then check to see whether the response to the follow-up request was affected by the smuggled prefix.

Armed with above information, we can use Burp Suite's Repeater to test it.

- Create one tab containing the setup request and another containing an arbitrary follow-up request:

From the **HTTP history**, send the `GET /` request to Burp Repeater twice:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193201.png)

**Then, in the attack request, change the method to POST:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193236.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193240.png)

**After that, add the smuggle data in the body:**
```http
POST / HTTP/1.1
Host: 0ad000d80492cc59c16181d20040007a.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /404pls HTTP/1.1
X-Foo: x
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193354.png)

- Add the two tabs to a group in the correct order:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193506.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193531.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193539.png)

- Using the drop-down menu next to the **Send** button, change the send mode to **Send group in sequence (single connection)**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193610.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193615.png)

- Change the **attack request**'s `Connection` header to `keep-alive`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193647.png)

- Send the sequence and **check the normal request's response**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215193729.png)

If the server responds to the second request as normal, this endpoint is not vulnerable.

**If the response to the second request matches what you expected from the smuggled prefix, like 404 response, the back-end server is ignoring the `Content-Length` of requests.** Which means it's vulnerable to CL.0 HTTP request smuggling.

After some testing, I found that **stuff that are in `/resources/` are vulnerable to CL.0 HTTP request smuggling**:

Attack request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194129.png)

Normal request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194143.png)

Nice!

**Now, we can try to bypass the access control in `/admin` by modifiying the smuggled path:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194249.png)

**Finally, send the requests in group:**

Normal request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194328.png)

Oh! No more 404 response!

Then scroll down:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194401.png)

Nice! We successfully bypassed the access control in `/admin`!

**Let's delete user `carlos`!**

Attack request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194441.png)

Normal request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194450.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-15/images/Pasted%20image%2020230215194506.png)

# What we've learned:

1. CL.0 request smuggling