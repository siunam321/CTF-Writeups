# Ez ⛳

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

Heard 'bout that new 🏌️-webserver? Apparently HTTPS just works(!), but seems like _someone_ managed to screw up the setup, woops. The flag.txt is deleted until I figure out that HTTPS and PHP stuff \#hacker-proof

[https://caddy.chal-kalmarc.tf](https://caddy.chal-kalmarc.tf)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304120436.png)

## Enumeration

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/web/Ez⛳)-[2023.03.04|12:06:30(HKT)]
└> file source-dummy-flag.zip 
source-dummy-flag.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/KalmarCTF-2023/web/Ez⛳)-[2023.03.04|12:06:32(HKT)]
└> unzip source-dummy-flag.zip 
Archive:  source-dummy-flag.zip
   creating: ⛳-server/
  inflating: ⛳-server/docker-compose.yaml  
   creating: ⛳-server/files/
   creating: ⛳-server/files/php.caddy.chal-kalmarc.tf/
 extracting: ⛳-server/files/php.caddy.chal-kalmarc.tf/flag.txt  
  inflating: ⛳-server/files/php.caddy.chal-kalmarc.tf/index.php  
  inflating: ⛳-server/files/Caddyfile  
   creating: ⛳-server/files/www.caddy.chal-kalmarc.tf/
  inflating: ⛳-server/files/www.caddy.chal-kalmarc.tf/index.html  
   creating: ⛳-server/files/static.caddy.chal-kalmarc.tf/
  inflating: ⛳-server/files/static.caddy.chal-kalmarc.tf/logo_round.svg
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304120741.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304120813.png)

In here, we see ***the SSL certificate issuer is unknown***.

**Let's view the certificate by clicking the "View Certificate" link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304120948.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304121238.png)

Hmm... The issuer is "Caddy Local Authority - ECC Intermediate".

**Caddy Local Authority - ECC Intermediate:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304121348.png)

**Now, we can go back and accept the certificate:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304121427.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304121447.png)

Then, we'll see there's a subdomain called `www`, and the SSL certificate is **self-signed**.

Again, continue and accept the certificate:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304121554.png)

**View source page:**
```html
<html>
  <body>
    <h1>Hello world</h1>
    <img src="https://static.caddy.chal-kalmarc.tf/logo_round.svg" />
  </body>
</html>
```

In here, we see there's an `<img>` element, and it's `src` attribute is pointing to **`static` subdomain**.

It seems empty. Let's look at the source code we've just downloaded.

**docker-compose.yaml:**
```yaml
version: '3.7'

services:
  caddy:
    image: caddy:2.4.5-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./files/Caddyfile:/etc/caddy/Caddyfile:ro
      - ./files:/srv
      - caddy_data:/data
      - caddy_config:/config
    command: sh -c "apk add --update openssl nss-tools && rm -rf /var/cache/apk/ && openssl req -x509 -batch -newkey rsa:2048 -nodes -keyout /etc/ssl/private/caddy.key -days 365 -out /etc/ssl/certs/caddy.pem -subj '/C=DK/O=Kalmarunionen/CN=*.caddy.chal-kalmarc.tf' && mkdir -p backups/ && cp -r *.caddy.chal-kalmarc.tf backups/ && rm php.caddy.chal-kalmarc.tf/flag.txt && sleep 1 && caddy run"

volumes:
  caddy_data:
    external: true
  caddy_config:
```

**As you can see, it runs a command:**
```bash
apk add --update openssl nss-tools
rm -rf /var/cache/apk/
openssl req -x509 -batch -newkey rsa:2048 -nodes -keyout /etc/ssl/private/caddy.key -days 365 -out /etc/ssl/certs/caddy.pem -subj '/C=DK/O=Kalmarunionen/CN=*.caddy.chal-kalmarc.tf'
mkdir -p backups/
cp -r *.caddy.chal-kalmarc.tf backups/
rm php.caddy.chal-kalmarc.tf/flag.txt
sleep 1
caddy run
```

The `openssl` command is to create a new private RSA key (2048 bit) and the certificate file. Then, use those keys to do a self-signed certificate. (Country=DK, Organization=Kalmarunionen, Common Name=`*.caddy.chal-kalmarc.tf`).

Also, it's using a service called "Caddy".

> [Caddy](https://www.caddyserver.com?rel=nofollow,noopener,noreferrer&target=_blank), also known as the Caddy web server, is an alternative to the classic Apache. It is an [open source](https://github.com/mholt/caddy?rel=nofollow,noopener,noreferrer&target=_blank) web server written in Go.
>   
> The **Caddyfile** is a convenient Caddy configuration format for humans. It is most people's favorite way to use Caddy because it is easy to write, easy to understand, and expressive enough for most use cases.

**files/Caddyfile:**
```batch
{
    admin off
    local_certs  # Let's not spam Let's Encrypt
}

caddy.chal-kalmarc.tf {
    redir https://www.caddy.chal-kalmarc.tf
}

#php.caddy.chal-kalmarc.tf {
#    php_fastcgi localhost:9000
#}

flag.caddy.chal-kalmarc.tf {
    respond 418
}

*.caddy.chal-kalmarc.tf {
    encode zstd gzip
    log {
        output stderr
        level DEBUG
    }

    # block accidental exposure of flags:
    respond /flag.txt 403

    tls /etc/ssl/certs/caddy.pem /etc/ssl/private/caddy.key {
        on_demand
    }

    file_server {
        root /srv/{host}/
    }
}
```

Let's break it down!

**Global options:**
- `admin off`
    - Customizes the [admin API endpoint](https://caddyserver.com/docs/api). Accepts placeholders. If `off`, then the admin endpoint will be disabled.
- `local_certs`
    - Causes all certificates to be issued internally by default, rather than through a (public) ACME CA such as Let's Encrypt. This is useful in development environments.

**General options:**
- `caddy.chal-kalmarc.tf`:
    - `redir`
        - Issues an HTTP redirect to `https://www.caddy.chal-kalmarc.tf` to the client.
- `php.caddy.chal-kalmarc.tf`: (Commented out)
    - `php_fastcgi`
        - An opinionated directive that proxies requests to a PHP FastCGI server `localhost:9000`.
- `flag.caddy.chal-kalmarc.tf`:
    - `respond`
        - Writes a hard-coded/static response to the client. (`418` in our case)
- `*.caddy.chal-kalmarc.tf`:
    - `encode`
        - Encodes responses using the configured encoding(s). A typical use for encoding is compression. `zstd` to enable Zstandard compression, `gzip` to enable Gzip compression.
    - `log`
        - Enables and configures HTTP request logging (also known as access logs). `output stderr`, outputs logs to standard error
        - `level` is the minimum entry level to log
    - `respond`
        - Writes a hard-coded/static response to the client. (`403` to block accidental exposure of flags)
    - `tls`
        - Configures TLS for the site. **Caddy's default TLS settings are secure. Only change these settings if you have a good reason and understand the implications.**
        - Certificate file = `/etc/ssl/certs/caddy.pem`, private key PEM file = `/etc/ssl/private/caddy.key`
        - ***`on_demand` enables [On-Demand TLS](https://caddyserver.com/docs/automatic-https#on-demand-tls)*** for the hostnames given in the site block's address(es). **Security warning:** Doing so in production is insecure unless you also configure the [`on_demand_tls` global option](https://caddyserver.com/docs/caddyfile/options#on-demand-tls) to mitigate abuse.
    - `file_server`
        - A static file server that supports real and virtual file systems. It forms file paths by appending the request's URI path to the [site's root path](https://caddyserver.com/docs/caddyfile/directives/root).
        - `root` sets the path to the site root. It's similar to the [`root`](https://caddyserver.com/docs/caddyfile/directives/root) directive except it applies to this file server instance only and overrides any other site root that may have been defined. (`/srv/{host}`)

**files/php.caddy.chal-kalmarc.tf/index.php:**
```php
<?php

echo "I can't get this to work :/";
echo system("cat flag.txt");

?>
```

As you can see, **the flag is in the `php` subdomain**, and when we reach to `index.php`, it'll echos out the flag for us.

Armed with above information, we can try to go to `php` subdomain:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2023/images/Pasted%20image%2020230304124409.png)

Nope. It returns "404 Not Found", as this subdomain is commented out in `Caddyfile`.

With that said, this challenge should be about ***HTTPS***?

In `Caddyfile`'s General TLS option, we see that `on_demand` is enabled, and it's insecure.

According to [Caddy documentation](https://caddyserver.com/docs/automatic-https#on-demand-tls), it said:

> Caddy pioneered a new technology we call **On-Demand TLS**, which dynamically obtains a new certificate during the first TLS handshake that requires it, rather than at config load. Crucially, this does not require specifying the domain names in your configuration ahead of time.
>  
> When on-demand TLS is enabled, you do not need to specify the domain names in your config in order to get certificates for them. Instead, when a TLS handshake is received for a server name (SNI) that Caddy does not yet have a certificate for, the handshake is held while Caddy obtains a certificate to use to complete the handshake. The delay is usually only a few seconds, and only that initial handshake is slow. All future handshakes are fast because certificates are cached and reused, and renewals happen in the background. Future handshakes may trigger maintenance for the certificate to keep it renewed, but this maintenance happens in the background if the certificate hasn't expired yet.

However, On-Demand TLS is vulnerable to **DDoS** via infinitely issuing certificates, filling storage up with certificate/key pairs, which is not what we want.

After that, I wasn't able to figure out the vulnerable part of this challenge...