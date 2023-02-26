# Blue Baby Shark

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225155515.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark)-[2023.02.25|15:54:42(HKT)]
└> file Blue\ Baby\ Shark.pcapng 
Blue Baby Shark.pcapng: pcapng capture file - version 1.0
```

It's a packet capture file!

**Let's open it in WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Network-Security/Blue-Baby-Shark)-[2023.02.25|15:55:32(HKT)]
└> wireshark Blue\ Baby\ Shark.pcapng
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160047.png)

**Let's look at the "Protocol Hierarchy" in "Statistics" tab:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160126.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160143.png)

In here, we see there are 3 protocols: **Dropbox LAN sync Discovery**, TCP, ICMP.

The Dropbox protocol looks very interesting, as sometimes bad actors will use Dropbox to host their C2 (Command and Control) infrastructure:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160321.png)

Hmm... No idea what we can do with that at the moment.

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160353.png)

In the bottom of the packet capture, I saw that very sussy data.

**Let's follow it's TCP stream:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160434.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160442.png)

Oh! Looks like we found some commands traffic's data!

**When you scroll down, we can see the flag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225160546.png)

- **Flag: `VU{b4by_5h4rk_fly_4w4y}`**

# Conclusion

What we've learned:

1. Analyzing How A Bad Actor Infiltrate A System Via Inspecting Packets In WireShark