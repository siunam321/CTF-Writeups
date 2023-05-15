# IMF#0 - 1

## Table of Contents

1. [IMF#0: Your mission, should you choose to accept it](#imf0:-Your mission,-should-you-choose-to-accept-it)
	1. [Background](#background)
	2. [Overview](#overview)
2. [IMF#1: Bug Hunting](#imf1:-Bug-Hunting)
	1. [Background](#background)
	2. [Overview](#overview)
	3. [Enumeration](#enumeration)
3. [Conclusion](#conclusion)

## IMF#0: Your mission, should you choose to accept it

### Overview

- 368 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

The Infamous Mother Fluckers have been hired to take down a guy named Dave. I think his sister's husband's cousin's wife's brother's son had an affaire with our client's wife, and for some reason he want's to take it out on him. But who are we to judge right ? We're getting paid, that's enough for me.  
  
I got you a job in the same development start-up as Dave. In fact, you are his team mate. I asked around in some underground circles, and word is on the streets that our guy is selling customer information. If you can get proof of that and send it to his boss, he'll get fired and we'll get paid. I'm counting on you.  
  
And keep you eyes opened, you might find some other interseting stuff on the company's network.  
  
For this mission, you are bob. Your ssh credentials are `bob:password`.  
  
Enter this flag to accept the mission : `Hero{I_4cc3pt_th3_m1ss10n}`  
  
_This message will self-destruct in 5 seconds._  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Log_s**

- **Flag: `Hero{I_4cc3pt_th3_m1ss10n}`**

## IMF#1: Bug Hunting

### Overview

- 99 solves / 68 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Tracking bugs can be tidious, if you're not equiped with the right tools of course...  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Log_s**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514191443.png)

### Enumeration

**In this challenge, we can SSH into user `bob` with password `password`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/IMF#0-#4)-[2023.05.14|18:56:37(HKT)]
└> ssh bob@dyn-01.heroctf.fr -p 11386
[...]
bob@dyn-01.heroctf.fr's password: 
[...]
bob@dev:~$ 
```

```
bob@dev:~$ cat welcome.txt 
Hi Bob!

Welcome to our firm. I'm Dave, the tech lead here. We are going to be working together on our app.

Unfortunately, I will be on leave when you arrive. So take the first few days to get familiar with our infrastructure, and tools.

We are using YouTrack as our main issue tracker. The app runs on this machine (port 8080). We are both going to use the "dev" account at first, but I will create a separate account for you later. There is also an admin account, but that's for our boss. The credentials are: "dev:aff6d5527753386eaf09".

The development server with the codebase is offline for a few days due to a hardware failure on our hosting provider's side, but don't worry about that for now.

We also have a backup server, that is supposed to backup the main app's code (but it doesn't at the time) and also the YouTrack configuration and data.

Only I have an account to access it, but you won't need it. If you really have to see if everything is running fine, I made a little utility that run's on a web server.

The command to check the logs is:
curl backup

The first backups might be messed up a bit, a lot bigger than the rest, they occured while I was setting up YouTrack with it's administration account.

Hope you find everything to you liking, and welcome again!

Dave
```

**So, there's a "YouTrack" Project Management Tool, and we can login with credentials: `dev:aff6d5527753386eaf09`.**

**Since the instance machine doesn't have `netstat`, I'll upload it via `scp`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/IMF#0-#4)-[2023.05.14|19:01:54(HKT)]
└> scp -P 11386 -r /usr/bin/netstat bob@dyn-01.heroctf.fr:/tmp/netstat
bob@dyn-01.heroctf.fr's password: 
netstat                                                              100%  152KB 192.1KB/s   00:00    
```

```shell
bob@dev:~$ /tmp/netstat -tunlp
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:35533         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.11:45091        0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.11:58050        0.0.0.0:*                           -                   
```

Can confirm port 8080 is listening on all interface. Also, there's a weird 35533 port open?

Anyway, to access the YouTrack application, we can use a port forwarding tool.

**To do so, I'll use `chisel`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/IMF#0-#4)-[2023.05.14|19:03:20(HKT)]
└> scp -P 11386 -r /opt/chisel/chiselx64 bob@dyn-01.heroctf.fr:/tmp/chisel  
bob@dyn-01.heroctf.fr's password: 
chiselx64                                                            100% 7888KB 317.8KB/s   00:24    
```

**Setup a port forwarding service, like Ngrok:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/System/IMF#0-#4)-[2023.05.14|19:12:03(HKT)]
└> ngrok tcp 4444 
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:16442 -> localhost:4444                              
[...]
```

**Setup a reverse port forwarding server:**
```shell
┌[siunam♥earth]-(/opt/chisel)-[2023.05.14|19:04:57(HKT)]
└> ./chiselx64 server -p 4444 --reverse
2023/05/14 19:05:42 server: Reverse tunnelling enabled
2023/05/14 19:05:42 server: Fingerprint MNPD78StKIbLJT5I39BqUCw190PpkWyXRkPyhKPnxMM=
2023/05/14 19:05:42 server: Listening on http://0.0.0.0:4444
```

**Connect to server from the client:**
```shell
bob@dev:~$ /tmp/chisel client 0.tcp.ap.ngrok.io:16442 R:5001:0.0.0.0:8080&
[2] 1197
11:19:01 client: Connecting to ws://0.tcp.ap.ngrok.io:16442
11:19:03 client: Connected (Latency 270.048918ms)
```

**That way, we can access it from `localhost:5001`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514192058.png)

**As we have a credential, let's login!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514192129.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514192145.png)

**In here, we can view "Issues":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514192329.png)

**In "ST-5 Is that..." issue, we can find the flag!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514192432.png)

- **Flag: `Hero{1_tr4ck_y0u_tr4ck_h3_tr4ck5}`**

## Conclusion

What we've learned:

1. Port Forwarding With `chisel` & Enumerating YouTrack