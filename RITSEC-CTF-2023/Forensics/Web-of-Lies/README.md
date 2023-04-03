# Web of Lies

- 98 Points / 79 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

We found more weird traffic. We're concerned he's connected to a web of underground criminals.

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402133408.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies)-[2023.04.02|13:34:41(HKT)]
└> file weboflies.pcapng 
weboflies.pcapng: pcapng capture file - version 1.0
```

It's a packet capture file!

**We can open it via WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies)-[2023.04.02|13:34:42(HKT)]
└> wireshark weboflies.pcapng
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402133535.png)

In "Statistcs" -> "Protocol Hierarchy", we can view which protocol is being captured:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402133548.png)

As you can see, it has some HTTP packets.

**Let's "Follow HTTP Stream"!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134151.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134200.png)

Hmm... "Flag's not here".

In WireShark, we can export all the HTTP object via:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134422.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230402134448.png)

**Then `cat` all of them:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Forensics/Web-of-Lies/http)-[2023.04.02|13:42:59(HKT)]
└> cat *              
Flag Not Found
[...]
Flag's not here
[...]
```

Umm... All of them are not the real flag...

After fumbling around, I still don't know what can I do with those packets...