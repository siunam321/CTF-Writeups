# Neighbour

## Introduction

Welcome to my another writeup! In this TryHackMe [Neighbour](https://tryhackme.com/room/neighbour) room, you'll learn: IDOR (Insecure Direct Object References)! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Check out our new cloud service, Authentication Anywhere -- log in from anywhere you would like! Users can enter their username and password, for a totally secure login process! You definitely wouldn't be able to find any secrets that other people have in their profile, right?

---

> Check out our new cloud service, Authentication Anywhere. Can you find other user's secrets?

> Difficulty: Easy

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Neighbour]
└─# export RHOSTS=10.10.235.95

┌──(root🌸siunam)-[~/ctf/thm/ctf/Neighbour]
└─# rustscan --ulimit 5000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 66dcb6bd39ff852f979d25192c8c6090 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCb1r/9K4CTlOWHFvDYYhQJbDBTLkoFm/BpKNFv/fOYwXSJ/IyJhfim7/JaHpzUPgDQw9kcMo04FotjBF94S0Mqs8LG8LhJmkOTrzYK3Xhqa1Lw2LJhqJ4I3dLP5oj+/5D/1xOSqSC/NXaXH+3cYVDdmBMnKw5kdoxuOzbc+Qrc3KdVzn2tVebdLFrvrh+ZlCZdXdikawgBboKg2ZBSvqVrtbwJfOxt7MzglEGhDPlcdKfijqCH0Gfhi/1ogtao+ud32SHEDJsR+1AJPU33lTdZxDXjAvfY54V9aNvgCc2zlMiKHnVmvHX5/OFZ289jN+ub3Vfic/o5jZJPFFhIdBsCOkfQmJ8scecRKX5P68CzYOpes9jt/TEZoMEbdWuYKRSt93QjB7+6z3p5i9JnrDZTlv6lQaS8RhPePNSdgYwhhk6VOy0uBCPfecjDkQIwKd5fnmAZ/90bmTowGinqF3+0UTuNHuNSOmimQlkkitM5bjJaKBLRPPD38xNkCA5UhKU=
|   256 c148b585f76c5bfb224be026c34c3a7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD1jjca5HRam9iQADWLUankj6e7fknu1/Y3gayCqNoI5GhVYvgUv/UQ/WdQkihCH1jW1BzpUVGoFD65yfpFgOf4=
|   256 5bc9f848beff43b8d3e979732c16c7cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICujkkB30pvZxf4jIIK4L23c4uKlohaSHgueev06veMX
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.53 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.53 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` and `nmap` result, we have 4 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.2p1 Ubuntu
80                | Apache httpd 2.4.53 ((Debian))

### HTTP on Port 80

**Adding a new domain to `/etc/hosts`:** (Optional, but it's a good practice to do so)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Neighbour]
└─# echo "$RHOSTS neighbour.thm" >> /etc/hosts
```

**Home page:**
```html
┌──(root🌸siunam)-[~/ctf/thm/ctf/Neighbour]
└─# curl http://neighbour.thm/ 
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>

        
        <form action="/index.php" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control " value="">
                <span class="invalid-feedback"></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control ">
                <span class="invalid-feedback"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? Use the guest account! (<code>Ctrl+U</code>)</p>
            <!-- use guest:guest credentials until registration is fixed. "admin" user account is off limits!!!!! -->
        </form>
    </div>
</body>
</html>                                                                                                    
```

**In here, we can see there is a credentials:**

- Username: guest
- Password: guest

**Let's login!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Neighbour/images/Pasted%20image%2020221115070648.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Neighbour/images/Pasted%20image%2020221115070656.png)

**`profile.php`:**
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <!-- admin account could be vulnerable, need to update -->
    <link rel="stylesheet" href="[https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css](view-source:https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css)">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5">Hi, <b>guest</b>. Welcome to our site. Try not to peep your neighbor's profile.</h1>
    <p>
        <a href="logout.php" class="btn btn-danger ml-3">Sign Out of Your Account</a>
    </p>
</body>
</html>
```

**Again, we can see there is a HTML comment: `admin account could be vulnerable, need to update`**

Now, we have to **think like a real attacker**: How can we exploit this website? Are there any vulnerabilities that we can take advantage of?

The `Sign Out of Your Account` seems useless for us.

**How about the GET parameter `user`??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Neighbour/images/Pasted%20image%2020221115071028.png)

Hmm... Since the HTML comment said that the `admin` account could be vulnerable, **what if we change the `user` value from `guest` to `admin`??**

**If we could authenticated as user `admin`, it's an IDOR (Insecure Direct Object References) vulnerability!!**

Let's do this!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Neighbour/images/Pasted%20image%2020221115071521.png)

Boom! We sucessfully authenticated as `admin` and got the flag!

# Conclusion

What we've learned:

1. IDOR (Insecure Direct Object References) Vulnerability