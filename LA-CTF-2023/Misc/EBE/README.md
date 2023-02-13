# EBE

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

- 426 solves / 183 points

## Background

> Author: burturt

I was trying to send a flag to my friend over UDP, one character at a time, but it got corrupted! I think someone else was messing around with me and sent extra bytes, though it seems like they actually abided by RFC 3514 for once. Can you get the flag?

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211202123.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/raw/main/LA-CTF-2023/Misc/EBE/EBE.pcap):**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Misc/EBE)-[2023.02.11|20:20:55(HKT)]
└> file EBE.pcap     
EBE.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

**It's a Packet Capture file! Let's open it via WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Misc/EBE)-[2023.02.11|20:20:57(HKT)]
└> wireshark EBE.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211202322.png)

As you can see, it's full of UDP traffics.

In the challenge's description, those UDP traffics are abided by RFC 3514.

> The evil bit is a fictional IPv4 packet header field proposed in RFC 3514, a humorous April Fools' Day RFC from 2003 authored by Steve Bellovin.

**If you look at the "Data" field, you'll see a 1 byte data:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211202500.png)

**However, if you take a look at the [RFC 3514](https://www.ietf.org/rfc/rfc3514.txt):**

```
[...]
2. Syntax

   The high-order bit of the IP fragment offset field is the only unused
   bit in the IP header.  Accordingly, the selection of the bit position
   is not left to IANA.





Bellovin                     Informational                      [Page 1]

RFC 3514          The Security Flag in the IPv4 Header      1 April 2003


   The bit field is laid out as follows:

             0
            +-+
            |E|
            +-+

   Currently-assigned values are defined as follows:

   0x0  If the bit is set to 0, the packet has no evil intent.  Hosts,
        network elements, etc., SHOULD assume that the packet is
        harmless, and SHOULD NOT take any defensive measures.  (We note
        that this part of the spec is already implemented by many common
        desktop operating systems.)

   0x1  If the bit is set to 1, the packet has evil intent.  Secure
        systems SHOULD try to defend themselves against such packets.
        Insecure systems MAY chose to crash, be penetrated, etc.
[...]
```

**Armed with above information, If the IP "Reserved bit" is set to 1 (0x1), it's an evil packet:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211204355.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211204406.png)

***Hence, to extract the flag, we need to find all the not set Reserved bit!***

**To do so, I'll use `tshark`, a command line version of WireShark:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Misc/EBE)-[2023.02.11|20:53:46(HKT)]
└> tshark -r EBE.pcap -Y "ip.flags.rb == 0x0" -T fields -e data | xxd -r -p 
lactf{3V1L_817_3xf1l7R4710N_4_7H3_W1N_51D43c8000034d0c}
```

Nice!

- **Flag: `lactf{3V1L_817_3xf1l7R4710N_4_7H3_W1N_51D43c8000034d0c}`**

# Conclusion

What we've learned:

1. Extracting Evil Bit's Hidden Data