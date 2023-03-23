# Persistence

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Thousands of years ago, sending a GET request to **/flag** would grant immense power and wisdom. Now it's broken and usually returns random data, but keep trying, and you might get lucky... Legends say it works once every 1000 tries.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319134012.png)

## Find the flag

According to the challenge's description, we need to send a GET request to `/flag` **1000 times**??

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Persistence)-[2023.03.19|13:41:01(HKT)]
└> curl http://104.248.169.175:30048/flag
szTzdfvnzT<FN}sWFA6#L$|S
```

Yep, it just returns random data.

**Hmm... Let's write a Python script to automate this process:**
```py
#!/usr/bin/env python3
import requests
from threading import Thread
from time import sleep

class Requester:
    def __init__(self, URL):
        self.URL = URL

    def sendRequest(self, tryNumber):
        requestResult = requests.get(self.URL)
        requestText = requestResult.text.strip()
        print(f'[*] Trying {tryNumber}: {requestText}')

        if 'HTB' in requestText:
            print(f'[+] We found the flag! {requestText}')

def main():
    URL = 'http://104.248.169.175:30048/flag'
    requester = Requester(URL)

    # Create 1000 jobs
    for job in range(1000):
        thread = Thread(target=requester.sendRequest, args=(job + 1,))
        thread.start()

        # You can adjust how fast of each thread
        sleep(0.02)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Misc/Persistence)-[2023.03.19|13:47:38(HKT)]
└> python3 solve.py
[...]
[*] Trying 464: |`BHJlB+}@#Ld{b7q"V}?qn~0gCFN
[*] Trying 463: nA|r`|sv=KN)s@8+>sYM&y)TQ
[*] Trying 466: %<i!csA1H$`xh2[\E6*:wCd
[*] Trying 465: _NXLy>kRX=-H0]Q+pW-
[*] Trying 467: <=)(\*!j@/1=C+0>vZ
[*] Trying 468: HTB{y0u_h4v3_p0w3rfuL_sCr1pt1ng_ab1lit13S!}
[+] We found the flag! HTB{y0u_h4v3_p0w3rfuL_sCr1pt1ng_ab1lit13S!}
```

We found the flag!

- **Flag: `HTB{y0u_h4v3_p0w3rfuL_sCr1pt1ng_ab1lit13S!}`**

## Conclusion

What we've learned:

1. Writing A Python Script To Send HTTP Request