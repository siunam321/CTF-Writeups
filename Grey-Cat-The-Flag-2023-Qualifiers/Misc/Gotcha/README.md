# Gotcha

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 89 solves / 50 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I have designed my own Captcha. If you solve it fast enough I'll give you my flag. Can you help me test it?

- Junhua

Link for Europe instance: [http://34.116.250.170:5003](http://34.116.250.170:5003)

[http://34.124.157.94:5003](http://34.124.157.94:5003)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520133934.png)

In here, we need to solve 100 custom Captcha within 2 minutes.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520134120.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230520134126.png)

So... We need to automate this...

**To do so, I'll write a Python script:**
```python
#!/usr/bin/env python3
import requests
from base64 import b64decode
from PIL import Image
import pytesseract
import io
import os
from time import time
from bs4 import BeautifulSoup

class SolveCaptcha:
    def __init__(self, url):
        self.url = url
        self.requestSession = requests.Session()

    def sendCaptcha(self):
        requestResult = self.requestSession.get(self.url)
        sessionCookie = requestResult.headers['Set-Cookie'].split(';')[0].split('=')[1]
        # Decode the session cookie via `flask-unsign`, as I couldn't find a better way decode that
        # The eval() is to convert JSON data into dictionary data type
        decodedSessionCookie = eval(os.popen(f'/home/siunam/.local/bin/flask-unsign --decode --cookie "{sessionCookie}"').read().strip())
        expiryTime = decodedSessionCookie['expiry']
        remainingTime = expiryTime - time()

        # Using OCR to convert image to text
        # The implementation of OCR is generated from ChatGPT
        captchaImageBytes = b64decode(decodedSessionCookie['img'])
        captchaImage = Image.open(io.BytesIO(captchaImageBytes))
        captchaText = pytesseract.image_to_string(captchaImage).strip().upper()

        data = {'captcha': captchaText}
        requestResult = self.requestSession.post(f'{self.url}/submit', data=data)

        if 'Oh no, you got it wrong' in requestResult.text:
            print(f'[-] Captcha failed: {captchaText}')
            return
        
        if 'Congrats you got it right' in requestResult.text:
            print(f'[+] Score: {decodedSessionCookie["score"]}, ID: {decodedSessionCookie["id"]}, Remaining time: {remainingTime:.2f}s\n')
            if int(decodedSessionCookie["score"]) >= 100:
                soup = BeautifulSoup(requestResult.text, 'html.parser')
                print(soup.text.strip())
                return

if __name__ == '__main__':
    url = 'http://34.124.157.94:5003'
    solveCaptcha = SolveCaptcha(url)

    while True:
        solveCaptcha.sendCaptcha()
```

```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Misc/Gotcha)-[2023.05.20|15:25:03(HKT)]
└> python3 solve.py
[...]
[-] Captcha failed: EFWFE
[+] Score: 99, ID: 9f1ba4dff5dca800993fe11281d7b64a5848923a8d3ece54e565d581e111ed5c5f4c8a53483cf2b123dc08d7e9409b70f9cc78649c911dd59f4df1e94a8936d8259f8399bc2bc7fa2131710ee6d15dfe9a98862fc13ee78815a2532e9c9db94d5cf619aa456da217cc374e0820051c2a3e29cd3fa943dfd37121ede5c553a5b860e1b50ea7c023d4f1bc5b320bfa7c2e481f5660baca56eef3b633c3d6f1814dee5e85992cf606d09006f7bd4961aa59fad61eef29e51bb1864baaa00237d2287eeea4e0970ea29e1de522e02c30a904f69e0a28db172ec2f39a1bab5f7bee29d5b24ecaae05806459ed656863fd00882372c0ab393d8e65f191e38083f1dc2464cffea26dd0c4fc5707abcd8c71b04beb9de27cf8b984c2ac79e0c031b5dd6d30e076a4c658ff4094cbff70bddb6a3ef8d4409b304f8226a3758359e1e00dad5ba76ad78ad79b874f2acbb6288b2077a812c477adc52ac12352b694fefd999983de0c7daeb82a485cc42b78cac9f772edf86fee3a8735a616ee65e35c27dfa1a2d3a6a6c92aaf6f197816adc140f1bbf2aac395993c524d228fa9d0a1ef5f15b3c3c215fe3eec439010f5ab86ed011d9abb29e3f8363ee6b4d4151f1ae10aada58ffb3a1329d8cc4482f8580b43d793125d6b408f12ea0ad869b57e4c2fb4138869b3b4e5f7593c62656aae92c4c57ce7a452d0d8e5e07282c5af70617dd657, Remaining time: 17.13s

[+] Score: 100, ID: 9f1ba4dff5dca800993fe11281d7b64a5848923a8d3ece54e565d581e111ed5c5f4c8a53483cf2b123dc08d7e9409b70f9cc78649c911dd59f4df1e94a8936d8259f8399bc2bc7fa2131710ee6d15dfe9a98862fc13ee78815a2532e9c9db94d5cf619aa456da217cc374e0820051c2a3e29cd3fa943dfd37121ede5c553a5b860e1b50ea7c023d4f1bc5b320bfa7c2e481f5660baca56eef3b633c3d6f1814dee5e85992cf606d09006f7bd4961aa59fad61eef29e51bb1864baaa00237d2287eeea4e0970ea29e1de522e02c30a904f69e0a28db172ec2f39a1bab5f7bee29d5b24ecaae05806459ed656863fd00882372c0ab393d8e65f191e38083f1dc2464cffea26dd0c4fc5707abcd8c71b04beb9de27cf8b984c2ac79e0c031b5dd6d30e076a4c658ff4094cbff70bddb6a3ef8d4409b304f8226a3758359e1e00dad5ba76ad78ad79b874f2acbb6288b2077a812c477adc52ac12352b694fefd999983de0c7daeb82a485cc42b78cac9f772edf86fee3a8735a616ee65e35c27dfa1a2d3a6a6c92aaf6f197816adc140f1bbf2aac395993c524d228fa9d0a1ef5f15b3c3c215fe3eec439010f5ab86ed011d9abb29e3f8363ee6b4d4151f1ae10aada58ffb3a1329d8cc4482f8580b43d793125d6b408f12ea0ad869b57e4c2fb4138869b3b4e5f7593c62656aae92c4c57ce7a452d0d8e5e07282c5af70617dd657, Remaining time: 16.56s

Gotcha




Congrats you got it right
grey{I_4m_hum4n_n0w_059e3995f03a783dae82580ec144ad16}

Gotcha
Score: 101


        Solve 100 challenges within 2 minutes to get the flag. All letters are uppercase for now.
      



Captcha

Submit
```

> Note: You'll need to keep the script running. Sometimes it doesn't have enough time to solve 100 captcha.

- **Flag: `grey{I_4m_hum4n_n0w_059e3995f03a783dae82580ec144ad16}`**

## Conclusion

What we've learned:

1. Writing A Script To Solve Captcha With OCR