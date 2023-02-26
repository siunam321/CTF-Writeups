# Web cache poisoning via HTTP/2 request tunnelling

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling/lab-request-smuggling-h2-web-cache-poisoning-via-request-tunnelling), you'll learn: Web cache poisoning via HTTP/2 request tunnelling! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

This lab is vulnerable to request smuggling because the front-end server downgrades HTTP/2 requests and doesn't consistently sanitize incoming headers.

To solve the lab, poison the cache in such a way that when the victim visits the home page, their browser executes `alert(1)`. A victim user will visit the home page every 15 seconds.

The front-end server doesn't reuse the connection to the back-end, so isn't vulnerable to classic request smuggling attacks. However, it is still vulnerable to [request tunnelling](https://portswigger.net/web-security/request-smuggling/advanced/request-tunnelling).

> Note:
>  
> This lab supports HTTP/2 but doesn't advertise this via ALPN. To send HTTP/2 requests using Burp Repeater, you need to enable the [Allow HTTP/2 ALPN override](https://portswigger.net/burp/documentation/desktop/http2#allow-http-2-alpn-override) option and manually [change the protocol to HTTP/2 using the Inspector](https://portswigger.net/burp/documentation/desktop/http2#changing-the-protocol-for-a-request).
>  
> Please note that this feature is only available from [Burp Suite Professional / Community 2021.9.1](https://portswigger.net/burp/releases).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226124315.png)

In here, we can try to send a HTTP/2 request to see the web application accept it or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226124448.png)

It accepts HTTP/2 requests.

**Then, we can try to smuggle an arbitrary header in the `:path` pseudo-header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226125029.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226125057.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226125257.png)

As you can see, we still receive a normal response, which means we're able to inject arbitrary headers via the `:path`.

Then, we can use the request tunnelling to perform web cache poisoning.

**First, change the request method to HEAD:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226125450.png)

**Next, use the `:path` pseudo-header to tunnel a request for another arbitrary endpoint:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226125918.png)

**Send the request, and we should able to view our tunnelled request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226125959.png)

> Note: If you recieved timed out response, try to change different `postId`.

```

```

**Now, what if we remove everything except the path and cachebuster query parameter from the `:path` pseudo-header and resend the request?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226130351.png)

As you can see, we successfully poisoned the cache with the tunnelled response!

Now we need to find a gadget that reflects an HTML-based [XSS](https://portswigger.net/web-security/cross-site-scripting) payload without encoding or escaping it.

**When we send a GET request to `/resources`, it'll redirect us to `/resources/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226130715.png)

**Hmm... What if we tunnelling this request via the `:path` pseudo-header?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226130840.png)

Timed out... Which means the `Content-Length` header in the main response is longer than the nested response to our tunnelled request.

**In the normal GET `/` request, we can see that the `Content-Length` header's value is `8512`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226131154.png)

**We can append a padding to the `/resources` path:**
```shell
┌[siunam♥earth]-(~/ctf/Portswigger-Labs/HTTP-Request-Smuggling)-[2023.02.26|13:11:04(HKT)]
└> python3 -c "print('A'*8512)"
AAA[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226131249.png)

Nice! it's reflected in the tunnelled response.

**Now, what if I add a XSS payload in the `/resources` path?**
```shell
┌[siunam♥earth]-(~/ctf/Portswigger-Labs/HTTP-Request-Smuggling)-[2023.02.26|13:15:52(HKT)]
└> python3
[...]
>>> payload = '<script>alert(1)</script>'
>>> print(payload + 'A' * (8512 - len(payload)))
<script>alert(1)</script>AAAAAAAAAAAAA[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226131829.png)

**After the cache is hitted, go to `/?cachebuster=1`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226131907.png)

Nice! We successfully triggered our XSS payload!

**Finally, remove the cache buster:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226132035.png)

The victim should see:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226132045.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-19/images/Pasted%20image%2020230226132056.png)

# What we've learned:

1. Web cache poisoning via HTTP/2 request tunnelling