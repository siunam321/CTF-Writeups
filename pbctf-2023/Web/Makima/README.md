# Makima

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

- 15 solves / 285 points

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230219093455.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/Web/Makima/dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/Makima)-[2023.02.19|09:30:35(HKT)]
└> file dist.zip    
dist.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/Makima)-[2023.02.19|09:30:38(HKT)]
└> unzip dist.zip   
Archive:  dist.zip
   creating: chall/
  inflating: chall/docker-compose.yml  
   creating: chall/cdn/
  inflating: chall/cdn/app.py        
  inflating: chall/cdn/Dockerfile    
   creating: chall/web/
   creating: chall/web/php/
   creating: chall/web/php/uploads/
  inflating: chall/web/php/uploads/makima.png  
  inflating: chall/web/php/index.php  
 extracting: chall/web/flag.txt      
   creating: chall/web/nginx/
  inflating: chall/web/nginx/www.conf  
  inflating: chall/web/nginx/default.conf  
  inflating: chall/web/Dockerfile
```

Right of the bat, we see `cdn`, `php`, `uploads`. **Does that mean this challenge is about CDN (Content Delivery Network) and file upload in PHP?**

**docker-compose.yml:**
```shell
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/Makima/chall)-[2023.02.19|09:38:29(HKT)]
└> cat docker-compose.yml 
version: '3.7'

services:
  web:
    build: ./web/
    ports:
        - "127.0.0.1:80:8080"

  cdn:
    build: ./cdn/
```

So this challenge has 2 services, web and cdn.

**web/Dockerfile:**
```bash
┌[siunam♥earth]-(~/ctf/pbctf-2023/Web/Makima/chall/web)-[2023.02.19|09:39:48(HKT)]
└> cat Dockerfile 
FROM debian:bullseye

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx \
        php7.4-fpm \
        php7.4-gd \
    && rm -rf /var/lib/apt/lists/

# nginx + fastcgi
RUN rm -rf /var/www/html/*
COPY nginx/default.conf /etc/nginx/sites-enabled/default
COPY nginx/www.conf /etc/php/7.4/fpm/pool.d/www.conf

RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

# php
RUN mkdir -p /var/www/html/uploads && \
    chmod 703 /var/www/html/uploads

COPY php/uploads/makima.png /var/www/html/uploads/makima.png
COPY php/index.php /var/www/html/index.php

COPY flag.txt /flag

USER root
EXPOSE 8080

CMD /etc/init.d/php7.4-fpm start && \
    nginx -g 'daemon off;'
```

The flag is in `/flag`.

**web/php/index.php:**
```php
<?php
function makeimg($data, $imgPath, $mime) {
    $img = imagecreatefromstring($data);
    switch($mime){
        case 'image/png':
            $with_ext = $imgPath . '.png';
            imagepng($img, $with_ext);
            break;
        case 'image/jpeg':
            $with_ext = $imgPath . '.jpg';
            imagejpeg($img, $with_ext);
            break;
        case 'image/webp':
            $with_ext = $imgPath . '.webp';
            imagewebp($img, $with_ext);
            break;
        case 'image/gif':
            $with_ext = $imgPath . '.gif';
            imagegif($img, $with_ext);
            break;
        default:
            $with_ext = 0;
            break;
        }
    return $with_ext;
}

if(isset($_POST["url"])){ 
    $cdn_url = 'http://localhost:8080/cdn/' . $_POST["url"];
    $img = @file_get_contents($cdn_url);
    $f = finfo_open();
    $mime_type = finfo_buffer($f, $img, FILEINFO_MIME_TYPE);
    $fileName = 'uploads/' . substr(md5(rand()), 0, 13);
    $success = makeimg($img, $fileName, $mime_type);
    if ($success !== 0) {
        $msg = $success;
    }
} 
?>
[...]
            <h3> Submit Makima fan art: </h3>
            <?php if (isset($msg)) { ?>
                <p>Message: <?= htmlspecialchars($msg) ?></p>
            <?php } ?>
            <form method="post">
            <label>Upload Image:</label>
            <input type="text" name="url">
            </form>
[...]
```

Let's break it down!

- If POST parameter `url` is set:
    - Append our supplied `url` to `http://localhost:8080/cdn/` (`$cdn_url`)
    - Get `$cdn_url`'s uploaded file content `$img`, and suppress error messages (`@`)
    - Read MIME type for `$cdn_url`'s uploaded file (`$mime_type`)
    - `$fileName` is `uploads/<1 - 12 characters long random MD5 hash>`
    - Then call function `makeimg($img, $fileName, $mime_type)`
        - First, it'll return an image identifier representing the image obtained from the given `$data`
        - Then, using `switch` statement to check the MIME type is `image/png`, or `image/jpeg` or `image/webp`, or `image/gif`
        - In `image/png`, it'll output our uploaded image from `uploads/<1 - 12 characters long random MD5 hash>.png` in HTML encoding (`htmlspecialchars($msg)`)

Hmm... At the first galance, **I think it suffers path traversal and file upload vulnerability?** Maybe we can try to upload a PHP webshell.

**cdn/app.py:**
```py
from flask import *
import requests

app = Flask(__name__)

@app.errorhandler(requests.exceptions.MissingSchema)
@app.errorhandler(requests.exceptions.InvalidSchema)
def bad_schema(e):
    return 'no HTTP/S?', 400

@app.errorhandler(requests.exceptions.ConnectionError)
def no_connect(e):
    print("CONNECT ERR")
    return 'I did not understand that URL', 400


    
@app.route("/cdn/<path:url>")
def cdn(url):
    mimes = ["image/png", "image/jpeg", "image/gif", "image/webp"]
    r = requests.get(url, stream=True)
    if r.headers["Content-Type"] not in mimes:
        print("BAD MIME")
        return "????", 400
    img_resp = make_response(r.raw.read(), 200)
    for header in r.headers:
        if header == "Date" or header == "Server":
            continue
        img_resp.headers[header] = r.headers[header]
    return img_resp
# ZoneMinder

if __name__ == "__main__":
    app.run(debug=False, port=8081)
```

It's a Flask back-end.

**In here, it has a route `/cdn/<url>`:**

- It checks the MIME type is `image/png`, or `image/jpeg`, or `image/gif` or `image/webp`
- Then, return raw content of the file, and ignore `Date` and `Server` header

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/pbctf-2023/images/Pasted%20image%2020230219150225.png)

Armed with above information, we could try to exploit the file upload.

## Exploitation

First, how do we upload a file?

In `index.php`, the image is from `/cdn/<url>`.

How can we reach there? It's an **internal service**!

I tried figure that out, but still no dice...