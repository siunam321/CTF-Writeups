# digitalworld.local: VENGEANCE

## Introduction

Welcome to my another writeup! In this VulnHub [digitalworld.local: VENGEANCE](https://www.vulnhub.com/entry/digitalworldlocal-vengeance,704/) box, you'll learn: Enumerating SMB, cracking password hash with custom wordlist, password spraying, privilege escalation via misconfigurated TFTP share, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: qinyi to root](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

2021 brings us the VENGEANCE of digitalworld.local! A box born out of COVID-19. This machine was built whilst the author was mulling over life in infosec whilst doing his PEN-300 course. But the author always has a heart for the OSCP, which explains yet another OSCP-like box, full of enumeration goodness.

If you MUST have hints for this machine (even though they will probably not help you very much until you root the box!): VENGEANCE is (#1): all about users making use of other users, (#2): broken hearts, (#3): broken minds.

Note: Always think like a user when enumerating target machine.

Feel free to contact the author at [https://donavan.sg/blog](https://donavan.sg/blog) if you would like to drop a comment.

## Service Enumeration

**Host discovery:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823103826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823103906.png)

- Target IP address: `10.69.96.77`
- Attacker IP address: `10.69.96.100`

**Create 2 environment variables for future use:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823103946.png)

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104039.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104536.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104553.png)

**`nmap` UDP port scan:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104055.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823105216.png)

According to `rustscan` and `nmap` result, the target machine has 2 ports are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|80/TCP            | nginx 1.18.0 (Ubuntu)         |
|110/TCP           | POP3 (Dovenull)               |
|113/TCP/UDP       | Ident                         |
|139/TCP           | Samba smbd 4.6.2              |
|143/TCP           | Dovecot imapd (Ubuntu)        |
|443/TCP           | nginx 1.18.0 (Ubuntu)         |
|445/TCP           | Samba smbd 4.6.2              |
|993/TCP           | IMAPS                         |
|995/TCP           | POP3S                         |
|22222/TCP         | OpenSSH 8.2p1 Ubuntu          |

### SMB on TCP port 445

**Listing shares via `smbmap`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104233.png)

Oh! The SMB is using null credentials, which means **we can access the SMB as a guest.**

- Found shares with null credential: `sarapublic$`, `print$`

**Enumerate those shares:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104450.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823104501.png)

In share `sarapublic$`, we can see that there're a few interesting files.

**Download all those files:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110044.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110053.png)

**`blurb.txt`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110323.png)

- Why do workers always set passwords related to their jobs?

**Maybe users' password is set to their related jobs?**

**`essay.txt`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110521.png)

In here, we can see that the server got compromised because of an insider job, and we found 2 users: `Qinyi` and `Govindasamy`.

**`profile.txt`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110707.png)

Hmm... This text file contains the profile of user `Giovanni`. It seems like **this user worked in nanotechnological fields.**

**`gio.zip`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110755.png)

Nope. It requires password.

**We can try to crack it via `zip2john` and `john`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110921.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823110942.png)

No dice in using `rockyou.txt`.

**Based on the downloaded text files from SMB, we can build a custom password wordlist and crack the password hash again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111231.png)

Nice! It's cracked!

**Unzip it again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111312.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111320.png)

After unzipped, it extracted 3 files, `pass_reminder.txt`, `ted_talk.pptx`, and `tryharder.png`.

**`gio/pass_reminder.txt`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111344.png)

Oh, looks like we found a password?

**`gio/ted_talk.pptx` metadata:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111545.png)

In the "Creator" field, it has user `Donavan`.

**`gio/ted_talk.pptx`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823111717.png)

In the first slide, we found user `Giovanni Berlusconi`

**We can also use `enum4linux` to enumerate the SMB and even the system users:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823112214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823112246.png)

- Found system user: `sara`, `qinyi`

### HTTP/S on TCP port 80, 443

**Adding a new host to `/etc/hosts` from `nmap`'s script scan result:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823112438.png)

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823112505.png)

Accept the self-signed SSL certificate.

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823112515.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823112524.png)

**In the footer, we can see that the web application is powered by "WordPress".**

> WordPress is a web content management system (CMS). It was originally created as a tool to publish blogs but has evolved to support publishing other web content, including more traditional websites, mailing lists and Internet forum, media galleries, membership sites, learning management systems and online stores. (From [https://en.wikipedia.org/wiki/WordPress](https://en.wikipedia.org/wiki/WordPress))

Let's enumerate it!

**Found "Wrath" blog post:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823113025.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823113031.png)

In here, we found:

- WordPress user: `sara`, `qinyi`
- User: `Patrick`

**We can also use `wpscan` to scan for vulnerabilities in this WordPress:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823113537.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823113548.png)

- WordPress core version: **5.6.1**

**But after scanning, when I go to the web application, it'll direct me to `https://www.offensive-security.com/offsec/say-try-harder/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823113206.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823113215.png)

Hmm... Maybe I triggered something that blocks us? Weird.

### POP3/S on TCP port 110, 995

Try to login a user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823114547.png)

However, it requires SSL/TLS connection.

To solve that, we can use `openssl` to connect to POP3S (POP3 with SSL/TLS connection), the commands can be found in [https://doc.dovecot.org/configuration_manual/dovecot_ssl_configuration/](https://doc.dovecot.org/configuration_manual/dovecot_ssl_configuration/).

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823120033.png)

But no luck.

## Initial Foothold

Hmm... What should I do...

After fumbling around, I realized that the `gio/pass_reminder.txt` file's text is actually not the password! It's telling us the ***password format***! 

**In the third slide of the PowerPoint (`ted_talk.pptx`), we can find the circuit name!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122301.png)

That being said, we found a password!

**Armed with above information, we can try to perform password spraying via `hydra`:**

> Password spraying is a brute force technique that attempt to access multiple users with a known password.

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122457.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122529.png)

Nice! We found that the user `qinyi` is using that password!

**Let's SSH into user `qinyi`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122630.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122640.png)

I'm user `qinyi`!

**local.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122709.png)

## Privilege Escalation

### qinyi to root

After gaining initial foothold in a target machine, we need to escalate our privilege. To do so, we need to enumerate the system.

**Sudo permission:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122738.png)

**Oh! User `qinyi` allows to run `/bin/systemctl restart nginx` and `/home/sara/private/eaurouge` as root without password!**

**Find system users:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823122844.png)

- System user: `sara`, `qinyi`

**`reminder` file in `qinyi`'s home directory:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823123333.png)

Hmm? Push config file to `sara` via **private channel**?

**`sara` home directory:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823123500.png)

Is that `private` directory is the "private channel"?

**Listing all listening ports:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823125014.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823125211.png)

**UDP port 69 TFTP is listening? We didn't get this information in the `nmap` UDP port scan.**

**List all the processes about TFTP:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823125257.png)

As you can see, the TFTP service is running as `root`, and the share directory is `/home/sara/private`.

**Hmm... Let's `get` the `/home/sara/private/eaurouge` file and see what is it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823125642.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823125651.png)

In this `eaurouge` Bash script, it'll create a text file at `/home/sara/public/test.txt`, and only user `sara` can access it.

Now, since the TFTP service is running as `root`, we should have write permission to the `/home/sara/private/` directory.

**Let's overwrite the `eaurouge` Bash script:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823130222.png)

This modified Bash script will add SUID (setuid) sticky bit to `/bin/bash`, which means we can spawn a Bash shell as `root`.

**Run the overwritten `eaurouge` Bash script with `sudo`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823130317.png)

It worked! The `/bin/bash` binary now has the SUID sticky bit.

**Spawn a `root` Bash shell:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823130340.png)

I'm root! :D

## Rooted

**proof.txt:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VulnHub/digitalworld.local:VENGEANCE/images/Pasted%20image%2020230823130354.png)

## Conclusion

What we've learned:

1. Enumerating SMB
2. Cracking password hash with custom wordlist
3. Password spraying
4. Vertical privilege escalation via misconfigurated TFTP share