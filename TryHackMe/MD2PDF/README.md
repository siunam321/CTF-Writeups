# MD2PDF

## Introduction

Welcome to my another writeup! In this TryHackMe [MD2PDF](https://tryhackme.com/room/md2pdf) room, you'll learn: Exploiting PDF generator, SSRF (Server-Side Request Forgery) and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Conclusion](#conclusion)**

## Background

> TopTierConversions LTD is proud to present its latest product launch.
>  
> Difficulty: Easy

---

Hello Hacker!

TopTierConversions LTD is proud to announce its latest and greatest product launch: MD2PDF.

This easy-to-use utility converts markdown files to PDF and is totally secure! Right...?

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/MD2PDF)-[2023.02.13|17:39:52(HKT)]
└> export RHOSTS=10.10.23.90            
┌[siunam♥earth]-(~/ctf/thm/ctf/MD2PDF)-[2023.02.13|17:39:58(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 383467947befbc164e461f6f15c5b814 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDnD7lBp26CwEmGpb1+K0Gu4JxqOT84igkOLGM/T7UFJCpjemg5lnFUK1aoD35ZvtdRRaikudWKurUkL7HJOjZfnf5RRH9I+NYhbJtUBP1ST4GE5BzlYfTmlQKa2tCo9b7wXLYj5AcT6Q9lC0QQ5qVhDclKUTeOxvKWEyeRj7/CcxILWRjb8e+xaz+Z5W/bu3viihyUxWyzlIWW6aafWpXOYIgK+CeLJ68uArMeY2eSX4WnL3NlbM/Gh8/m/TaZr81h3WQQdek59avYxH82QbaopNWV53JBvvT5OJMwO5YYPhk1OH+J8CqDSjFHJi14tpON4xow18Xfc7Nf5h2pKghvltnpnGvkhVDOpxg0H3R3nT7ClB5nNlmIKOT1GjbENp2sgtNEP0RWuH7kKa5EwxbXTBIDWlOKJSRGJ6jqa+9P9RD9DmbeiZJQWxTgZuuv2aocdGpNgcD3sN9WNa/N3HAbrkaRyNoiZ46juFM8pMWjr2aFCl1tjlXRjMXZ0LraQ+E=
|   256 4b7d925352b3bb5d1a22bbb8b0c00797 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM9WqdD9tCKaRX9krGCQaOst8PjsbR7yAWzmK5Dsf5RGy2nS0FAhggq8cYAx0IVP1nAPc+YX9/iCGwV+N0nUH3E=
|   256 bf695439bf5168324b2b984ed5a8b3c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILomzRONv0mJvluQPxlebU6npuplJzP6m6p09buBtX76
80/tcp   open  rtsp    syn-ack
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
| fingerprint-strings: 
|   FourOhFourRequest: 
[...]
|_http-title: MD2PDF
5000/tcp open  rtsp    syn-ack
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   FourOhFourRequest: 
[...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22                | OpenSSH 8.2p1 Ubuntu          |
|80                | HTTP                          |
|5000              | HTTP                          |

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/MD2PDF)-[2023.02.13|17:46:31(HKT)]
└> echo "$RHOSTS md2pdf.thm" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213174737.png)

Hmm... Markdown to PDF?

**View source page:**
```html
[...]
  <script>
    $(document).ready(function () {
      var editor = CodeMirror.fromTextArea(document.getElementById("md"), {
        mode: "markdown",
        lineNumbers: true,
        tabSize: 2,
        lineWrapping: true,
      })
      $("#convert").click(function () {
        const data = new FormData()
        data.append("md", editor.getValue())
        $("#progress").show()
        fetch("/convert", {
          method: "POST",
          body: data,
        })
          .then((response) => response.blob())
          .then((data) => window.open(URL.createObjectURL(data)))
          .catch((error) => {
            $("#progress").hide()
            console.log(error)
          })
      })
    })
  </script>
[...]
```

Let's try to convert something:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213174951.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213175006.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213175040.png)

When we clicked the "Convert to PDF" button, it'll send a POST request to `/convert`, with our Markdown form's data.

Then, when it's process finished, it'll open up a pop up window, with a UUID version 1 link and using blob object instance, which is a a file-like object of immutable, raw data.

Hmm... I remember NahamSec has a tweet that says **99% of all PDF generators are vulnerable to something, like SSTI (Server-Side Template Injection) / CSTI (Client-Side Template Injection), XSS (Cross-Site Scripting), SSRF (Server-Side Request Forgery) and more.**

**But before we test that, let's enumerate hidden directories and files via `gobuster`:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/MD2PDF)-[2023.02.13|18:02:55(HKT)]
└> gobuster dir -u http://md2pdf.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100 
[...]
┌[siunam♥earth]-(~/ctf/thm/ctf/MD2PDF)-[2023.02.13|18:05:00(HKT)]
└> gobuster dir -u http://md2pdf.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100
[...]
/admin                (Status: 403) [Size: 166]
/convert              (Status: 405) [Size: 178]
```

**Oh! The `/admin` route (path) looks sussy:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/MD2PDF)-[2023.02.13|18:07:18(HKT)]
└> curl -vv http://md2pdf.thm/admin
*   Trying 10.10.23.90:80...
* Connected to md2pdf.thm (10.10.23.90) port 80 (#0)
> GET /admin HTTP/1.1
> Host: md2pdf.thm
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 FORBIDDEN
< Content-Type: text/html; charset=utf-8
< Content-Length: 166
< 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>This page can only be seen internally (localhost:5000)</p>
```

Hmm... 403 Forbidden, and it's internal only...

**Armed with above information, if we can perform a SSRF or XSS attack to localhost on port 5000, we can bypass the admin panel's restriction!!**

**Since most Markdown to PDF generators accept raw HTML codes, we can basically inject any HTML codes:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213182124.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213182130.png)

So, it seems like the **our injected HTML code is parsed directly** to the back-end!

***Now, what if I create an `<iframe>` element, and it's `src` attribute is set to `http://localhost:5000/admin`?***

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213182302.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/MD2PDF/images/Pasted%20image%2020230213182311.png)

Boom! We successfully bypassed the admin panel's restriction, and got the flag!!

# Conclusion

What we've learned:

1. Enumerating Hidden Directoreis & Files
2. Exploiting Markdown To PDF Generator Via SSRF