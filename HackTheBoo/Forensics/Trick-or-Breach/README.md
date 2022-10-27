# Trick or Breach

## Background

> Our company has been working on a secret project for almost a year. None knows about the subject, although rumor is that it is about an old Halloween legend where an old witch in the woods invented a potion to bring pumpkins to life, but in a more up-to-date approach. Unfortunately, we learned that malicious actors accessed our network in a massive cyber attack. Our security team found that the hack had occurred when a group of children came into the office's security external room for trick or treat. One of the children was found to be a paid actor and managed to insert a USB into one of the security personnel's computers, which allowed the hackers to gain access to the company's systems. We only have a network capture during the time of the incident. Can you find out if they stole the secret project?

> Difficulty: Easy

- Overall difficulty for me: Easy

**In this challenge, we can [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Trick-or-Breach/forensics_trick_or_breach.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Trick-or-Breach/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# unzip forensics_trick_or_breach.zip    
Archive:  forensics_trick_or_breach.zip
  inflating: capture.pcap

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# file capture.pcap    
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

It's a `pcap` (Packet Capture) file!

## Find the flag

**Let's inspect that in WireShark!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# wireshark capture.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Trick-or-Breach/images/a2.png)

As you can see, there are lots of **DNS queries**!

**Let's click one of those queries, and follow UDP stream!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Trick-or-Breach/images/a3.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Trick-or-Breach/images/a4.png)

- Found domain: `pumpkincorp.com`

**Hmm... Why the subdomain is a weird random hexed string??**

Well, this kind of weird actions are the **indicators of DNS exfiltration activities**.

**Now, we can extract all the subdomain via `tshark` (Command line version of WireShark):**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# tshark -Y "dns.flags.response == 0" -T fields -e "dns.qry.name" -e "dns.qry.name" -r capture.pcap | cut -d '.' -f1
Running as user "root" and group "root". This could be dangerous.
	504b0304140008080800a52c47550000000000000000000000
	0018000000786c2f64726177696e67732f64726177696e6731
	2e786d6c9dd05d6ec2300c07f013ec0e55de695a181343145e
	d04e300ee0256e1b918fca0ea3dc7ed14a36697b011e6dcb3f
	f9efcd6e74b6f84462137c23eab212057a15b4f15d230eef6f
	b395283882d76083c7465c90c56efbb41935adcfbca722ed7b
	5ea7b2117d8cc35a4a563d3ae0320ce8d3b40de420a6923aa9
	09ce497656ceabea45f240089a7bc4b89f26e2eac1039a03e3
	[...]
```

**Hmm... Those hex strings look sussy, let's convert it to ASCII via `xxd`!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# tshark -Y "dns.flags.response == 0" -T fields -e "dns.qry.name" -e "dns.qry.name" -r capture.pcap | cut -d '.' -f1 | tr -d '\n' | xxd -r -p
Running as user "root" and group "root". This could be dangerous.
�,GUxl/drawings/drawing1.xml��]n�0
                                  ��U�iZC^�N0�%n����~�J6i{m�?���nt��Db|#�z��]#�o��(8��`��F\��n��5�ϼ�"�{^��}��ZJV=:�2
� ��:�  �IvVΫ�E��{ĸ�&�������Mׄ�5
�A��8!�b��f଩�Q=P���3��6�*��)�HB�<	8�����R���_���O�,�Czȇ�&^��eFwh��ȸ8��ݱ*�6�(+l�^ޭ̳"�_Pbi�,GUxl/drawings/drawing2.xml��]n�0
                    ��U�iZC^�N0�%n����~�J6i{m�?���nt��Db|#�z��]#�o��(8��`��F\��n��5�ϼ�"�{^��}��ZJV=:�2
� ��:�  �IvVΫ�E��{ĸ�&�������Mׄ�5                                                                       �Ӵ
�A��8!�b��f଩�Q=P���3��6�*��)�HB�<	8�����R���_���O�,�Czȇ�&^��eFwh��ȸ8��ݱ*�6�(+l�^ޭ̳"�_Pbi�,GUxl/worksheets/sheet1.xml�X�r�8}�}ד��cc��@'`�I�
[...]
```

**`xml`??**

**Let's output it to a file:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# tshark -Y "dns.flags.response == 0" -T fields -e "dns.qry.name" -e "dns.qry.name" -r capture.pcap | cut -d '.' -f1 | tr -d '\n' | xxd -r -p > dns_subdomains
Running as user "root" and group "root". This could be dangerous.
                                                                                                           
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Forensics/Trick-or-Breach]
└─# file dns_subdomains 
dns_subdomains: Microsoft Excel 2007+
```

**Oh! Microsoft Excel file!**

**Let's open it!**

> Note: Since I'm in a Linux machine, I'll open it in `LibreOffice Calc`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Forensics/Trick-or-Breach/images/a5.png)

Boom! We got the flag!!

# Conclusion

What we've learned:

1. Inspecting DNS Queries