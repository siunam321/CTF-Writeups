# HTTP request smuggling, basic CL.TE vulnerability

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te), you'll learn: HTTP request smuggling, basic CL.TE vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the front-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method.

To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method `GPOST`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127175856.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127180117.png)

In here, we can send this request to Burp Suite's Repeater, and try to smuggle a request using method GPOST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127180221.png)

First, we can try to directly modify the method to GPOST:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127180254.png)

As you can see, **the front-end server rejects requests that aren't using the GET or POST method.**

Now, we can try to smuggle a request that using GPOST in the back-end server.

- **Using POST method and add 2 HTTP header**:

1. `Content-Length`
2. `Transfer-Encoding`

> The `Transfer-Encoding` header can be used to specify that the message body uses chunked encoding. This means that the message body contains one or more chunks of data. Each chunk consists of the chunk size in bytes (expressed in hexadecimal), followed by a newline, followed by the chunk contents. The message is terminated with a chunk of size zero.

In here, we can try to **assume the front-end server uses `Transfer-Encoding` header, and the back-end server uses the `Content-Length` header. (AKA TE.CL)**

We can perform a simple HTTP request smuggling attack as follows:

```http
POST / HTTP/1.1
Host: 0a3b0040037bbd6cc1086ccb0028004f.web-security-academy.net
Content-Length: 3
Transfer-Encoding: chunked

5
GPOST
0
```

This request will let the front-end server processes the `Transfer-Encoding` header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be 5 bytes long, up to the start of the line following `GPOST`. It processes the second chunk, which is stated to be zero length, and so is treated as terminating the request. This request is forwarded on to the back-end server.

The back-end server processes the `Content-Length` header and determines that the request body is 3 bytes long, up to the start of the line following `5`. The following bytes, starting with `GPOST`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127182754.png)

> Note: To send the request, you will first need to go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127181834.png)
>  
> You need to include the trailing sequence `\r\n\r\n` following the final `0`.

However, when we send the request, we get a HTTP status 500 Internal Server Error. Which means the front-end uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header. (AKA CL.TE)

**To smuggle a request via CL.TE, we can send the following POST request:**
```http
POST / HTTP/1.1
Host: 0a3b0040037bbd6cc1086ccb0028004f.web-security-academy.net
Content-Length: 10
Transfer-Encoding: chunked

0

GPOST
```

The front-end server processes the `Content-Length` header and determines that the request body is 10 bytes long, up to the end of `SMUGGLED` (`0\r\n\r\nGPOST`). This request is forwarded on to the back-end server.

The back-end server processes the `Transfer-Encoding` header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be zero length, and so is treated as terminating the request. The following bytes, `GPOST`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

**Let's send that smuggled request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127183331.png)

> Note: You need to send the smuggled request twice.

As you can see, we successfully smuggled the GPOST method request!

However, the back-end doesn't know what is GPOSTPOST method.

**To fix that, we can add the following request and header:**
```http
POST / HTTP/1.1
Host: 0a3b0040037bbd6cc1086ccb0028004f.web-security-academy.net
Content-Length: 31
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1
Origin: 
```

**This will smuggle:**
```http
GPOST / HTTP/1.1
Origin: 
```

Which is using GPOST method, send the request to `/` using HTTP version 1.1, and add an `Origin` HTTP header to append the back-end's POST method:

**The back-end server will see:**
```http
GPOST / HTTP/1.1
Origin: POST
```

**Let's send the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-1/images/Pasted%20image%2020230127183852.png)

Boom! We successfully smuggled a GPOST method request!

# What we've learned:

1. HTTP request smuggling, basic CL.TE vulnerability