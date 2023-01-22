# TakeOver

## Introduction

Welcome to my another writeup! In this TryHackMe [TakeOver](https://tryhackme.com/room/takeover) room, you'll learn: Subdomain enumeration, virtual host enumeration, inspecting SSL certificate in the browser! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

> This challenge revolves around subdomain enumeration.
>  
> Difficulty: Easy

---

Hello there,  
  
I am the CEO and one of the co-founders of futurevera.thm. In Futurevera, we believe that the future is in space. We do a lot of space research and write blogs about it. We used to help students with space questions, but we are rebuilding our support.  

Recently blackhat hackers approached us saying they could takeover and are asking us for a big ransom. Please help us to find what they can takeover.  
  
Our website is located at [https://futurevera.thm](https://futurevera.thm)

Hint: Don't forget to add the MACHINE_IP in `/etc/hosts` for `futurevera.thm` ; )

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|12:02:55(HKT)]
└> export RHOSTS=10.10.182.53  
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|12:03:01(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dd29a70c05691ff6260ad928cd40f020 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJYXIbsuzRQDZhDmxc3ysgKo1zGHLwFIgTVOUzY7mUBk6pvX9WRlNRq/QE/I2AcViSdL99H7XGs2AE1yQBvE5z2abvIvRhAnViXcTMTMg0jwXuEN8FJMMK7PLFZTI+BoUmHH+aNKKGEOtpqM8IlBcujC9fkHsfcTuEUOsf1oB4rh56MRXgk1BI0G0HZ1tATZ0oka+JdQo3q092bjnhB78Jt636GfRSlRtFeW9XWsLX9/inRe1xw0r6l7QkN3Q0eTohHLEhQBoEVoxJ2duc/Nx/BZDWK101eI9OW4wG3Mt169HE4QuU0G7XhkskQZnmDhqjtmrqrQ3TEsX9PrGVc6UHrdqj7ylLhshz1sYqPj6xb1uANZk5FExEQe9D3vbS5Z0Nrnopo4jMokCii8t/ZY8iHn3aWcPlnf3mT7vLOcbKt8Q/bUyxptOfoTwb+4qx5rwC9uPK5yH74XhQ165R7wBwywmzW3RX9tl1YnL+uzs93PZ69u1Iatdcdp5VgZRcN8M=
|   256 cb2ea86d0366e970eb96e1f5ba25cb4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKQJTJFkvkwNTQLf9L+hjby2vSMriTeszWldCj+y2TDnTJpyvG1KvBlbzOPuFai3cxpZS/Y0/yU3JxK37I9T6cI=
|   256 50d34ba8a24d1d79e17dacbbff0b2413 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF1HW9ff2E4eEhE6FZYXtcpuWX46Kg80Hl22peqirx25
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://futurevera.thm/
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: FutureVera
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US/localityName=Portland/organizationalUnitName=Thm
| Issuer: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US/localityName=Portland/organizationalUnitName=Thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-13T10:05:19
| Not valid after:  2023-03-13T10:05:19
| MD5:   2e8d60976b23188c06d5f2cd8defdd3a
| SHA-1: 8023fcfc5e63a29b3d5eeaaf8f708b35d8ebc120
| -----BEGIN CERTIFICATE-----
| MIIDuzCCAqOgAwIBAgIUMx0OgCh/xob6nWlsHR+iKDXKZRkwDQYJKoZIhvcNAQEL
| BQAwbTELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
| dGxhbmQxEzARBgNVBAoMCkZ1dHVyZXZlcmExDDAKBgNVBAsMA1RobTEXMBUGA1UE
| AwwOZnV0dXJldmVyYS50aG0wHhcNMjIwMzEzMTAwNTE5WhcNMjMwMzEzMTAwNTE5
| WjBtMQswCQYDVQQGEwJVUzEPMA0GA1UECAwGT3JlZ29uMREwDwYDVQQHDAhQb3J0
| bGFuZDETMBEGA1UECgwKRnV0dXJldmVyYTEMMAoGA1UECwwDVGhtMRcwFQYDVQQD
| DA5mdXR1cmV2ZXJhLnRobTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AKZio9bT9ebOivcm+9xKKCUAobE2cdU5VFbi1Ve7oxsSGKWWEcsQlUn7tFj1jjKq
| hWDMZXxEW6aN3jU5p5zF6ATmwIuvNQqwZOaK8iKjXs8IWEBIQyz/iKBF6deWrN+8
| II+whTaSberFaND2G0VchB7OrOu/mlP1KNhm2kEKwak7YHxvFkSp7Nmu2yTQAnyp
| WK2CBh3tdeGSq7/lyo8W3la/kPKhb4lmtBMS/tKPFslMxlOv0cSbNsvFVgJQ7jti
| OZKPo/DAeaFIFB/32HocscQXM2VdQNXnQQ6M1cbBNskYWzvwp6di+wYzjjCWtM4o
| Rg+3c/k5hqkEftEiwV7xAXcCAwEAAaNTMFEwHQYDVR0OBBYEFD23WEwlBMTDTpWI
| 0eMU0IMaJyPJMB8GA1UdIwQYMBaAFD23WEwlBMTDTpWI0eMU0IMaJyPJMA8GA1Ud
| EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACu3W2VV8zRdD4M7oUWN8S6f
| lM1z8aCkSckgFDEX7jtyJjWMQVwPizKkX17XQs6EgnWqD/PVt2Tf9dRhUH6FQmTK
| qh35hnsSOdO3sQB8CnQ3SnlbeUYXY2mY/aUhz/lAkx6mURGuSen8BSbuL4mcm5Dk
| AXxfa+SHc5XAjuYSlXVUSPy8noqFOLxvcGz+zPN2RQYwQkMDgQtUX2n0VcjwgTLN
| bEuEm210+IGPX+ZEQWsnSSmz0SyUryBwc5BsjMaFUdAncxEBKCn1p4oN8gm6NQ32
| FHFbghTgLgMTahuLWpXdeuVF87+pHUlroRHdgblQtb2wSwqVaDGHaLFiZcUMv/Y=
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22                | OpenSSH 8.2p1 Ubuntu          |
|80                | Apache httpd 2.4.41 ((Ubuntu))|
|443               | Apache httpd 2.4.41 ((Ubuntu))|

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|12:03:39(HKT)]
└> echo "$RHOSTS futurevera.thm" >> /etc/hosts
```

**Home page:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|12:05:30(HKT)]
└> curl -v http://futurevera.thm/ 
*   Trying 10.10.182.53:80...
* Connected to futurevera.thm (10.10.182.53) port 80 (#0)
> GET / HTTP/1.1
> Host: futurevera.thm
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Sun, 22 Jan 2023 04:05:31 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: https://futurevera.thm/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
<
```

When we go to `/`, it redirects me to the HTTPS one.

### HTTPS on Port 443

**Home page:**

**Accept the SSL self signed certificate:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122120727.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122120811.png)

It seems like this website is a Bootstrap template page.

**In the `rustscan` + `nmap` scanning result, we found this:**
```shell
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US/localityName=Portland/organizationalUnitName=Thm
| Issuer: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US/localityName=Portland/organizationalUnitName=Thm
```

Hmm... **No "Subject Alt Names"**? (A common method to enumerate subdomains)

**Speaking of subdomain, let's fuzz subdomains via `ffuf` in HTTP port:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:22:12(HKT)]
└> ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://futurevera.thm/ -H "Host: FUZZ.futurevera.thm" -fw 1 -t 100
[...]
portal                  [Status: 200, Size: 69, Words: 9, Lines: 2, Duration: 4620ms]
payroll                 [Status: 200, Size: 70, Words: 9, Lines: 2, Duration: 240ms]
```

- Found 2 subdomains in **HTTP port**: `portal`, `payroll`

**Let's add those 2 subdomains to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:24:02(HKT)]
└> nano /etc/hosts                               
10.10.182.53 futurevera.thm portal.futurevera.thm payroll.futurevera.thm
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:24:56(HKT)]
└> curl http://portal.futurevera.thm/    
<h1> portal.futurevera.thm is only availiable via internal VPN </h1>
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:25:00(HKT)]
└> curl http://payroll.futurevera.thm/
<h1> payroll.futurevera.thm is only availiable via internal VPN </h1>
```

Umm... Those 2 subdomains only availiable via internal VPN...

Now, we can fuzz subdomains in **HTTPS port**.

**Since the website is related to "space research", "blog", etc. Let's build a custom wordlist via `cewl`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|12:57:03(HKT)]
└> cewl https://relatedwords.io/space-research -d 1 -w wordlist.txt
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|12:58:16(HKT)]
└> cewl https://relatedwords.io/space -d 1 >> wordlist.txt
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:00:07(HKT)]
└> cewl https://futurevera.thm/ -d 1 >> wordlist.txt
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:10:02(HKT)]
└> cewl https://relatedwords.io/blog -d 1 >> wordlist.txt                 
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:12:36(HKT)]
└> cewl https://relatedwords.io/rebuilding -d 1 >> wordlist.txt
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:14:01(HKT)]
└> cewl https://relatedwords.io/support -d 1 >> wordlist.txt   
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:15:35(HKT)]
└> cewl https://relatedwords.io/future -d 1 >> wordlist.txt 
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:34:23(HKT)]
└> ffuf -w wordlist.txt -u https://$RHOSTS/ -H "Host: FUZZ.futurevera.thm" -fs 4605 -t 100 
[...]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 267ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 251ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 245ms]
Blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 247ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 242ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 240ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 284ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 241ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 245ms]
Support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 239ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 239ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 241ms]
```

> Note: Don't use `https://futurevera.thm/` in `-u` flag.

- Found 2 subdomains in **HTTPS port**: `blog`, `support`

**Again, add those 2 subdomains to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:36:46(HKT)]
└> nano /etc/hosts
10.10.182.53 futurevera.thm portal.futurevera.thm payroll.futurevera.thm blog.futurevera.thm support.futurevera.thm
```

**`blog`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122133736.png)

In this subdomain, we can see there is a blog post:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122133758.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122133823.png)

However, nothing weird.

**`support`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122133921.png)

Hmm... Nothing.

**We can also use `cewl` again to build a new custom wordlist:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:36:49(HKT)]
└> cewl https://blog.futurevera.thm/ -w wordlist_1.txt
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:41:21(HKT)]
└> cewl https://support.futurevera.thm/ >> wordlist_1.txt
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:40:42(HKT)]
└> ffuf -w wordlist_1.txt -u https://$RHOSTS/ -H "Host: FUZZ.futurevera.thm" -fs 4605 -t 100 
[...]
Blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 243ms]
blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 247ms]
Support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 238ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 242ms]
```

Nothing new.

Now, just like how we inspect the SSL cert in `https://futurevera.thm`, we can see is there any **"Subject Alt Names"** field:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122135227.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122135239.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122135250.png)

Nothing in `blog`.

**How about `support`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/TakeOver/images/Pasted%20image%2020230122135325.png)

Found "Subject Alt Names" field!

- Found 1 subdomain: `secrethelpdesk934752`

**Finally, add that subdomain to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:54:08(HKT)]
└> cat /etc/hosts
10.10.182.53 futurevera.thm portal.futurevera.thm payroll.futurevera.thm blog.futurevera.thm support.futurevera.thm secrethelpdesk934752.support.futurevera.thm
```

**After fumbling around, the `secrethelpdesk934752` subdomain in `support` in top level domain `futurevera.thm` is in HTTP port:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/TakeOver)-[2023.01.22|13:58:47(HKT)]
└> curl -v http://secrethelpdesk934752.support.futurevera.thm 
*   Trying 10.10.182.53:80...
* Connected to secrethelpdesk934752.support.futurevera.thm (10.10.182.53) port 80 (#0)
> GET / HTTP/1.1
> Host: secrethelpdesk934752.support.futurevera.thm
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Sun, 22 Jan 2023 05:58:52 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: http://flag{Redacted}.s3-website-us-west-3.amazonaws.com/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
```

We found the flag!

# Conclusion

What we've learned:

1. Enumerating Subdomains/Virtual Hosts Via `ffuf`
2. Creating Custom Wordlist Via `cewl`
3. Inspecting SSL Certificate In The Browser