# ST Code (I)

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the Flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 198 solves / 50 points
- Author: ozetta
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112201153.png)

Flag 1: Can you read the flag from ST Code?

Web: [http://stcode-3983gi.hkcert23.pwnable.hk:28211](http://stcode-3983gi.hkcert23.pwnable.hk:28211)

**Note:** There is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-ii-en-4e6150a89a1ff32c).

## Find the Flag

**In this challenge, we can go the web application at [http://stcode-3983gi.hkcert23.pwnable.hk:28211](http://stcode-3983gi.hkcert23.pwnable.hk:28211):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112201630.png)

In here, we can see that there're 3 routes (endpoints): `/flag`, `/flag2`, and `/source`.

**Let's go to `/flag` first:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112201853.png)

In here, there's a QR code. However, it looks a bit odd? **Like some of those squares are rounded**.

**Let's view the source page and take a look at what is it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112202440.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112202452.png)

Oh! It's an SVG (Scalable Vector Graphics) image!

Hmm?? Wait a minute, why there're some random `rx` attribute?

According to [mdn web docs](https://developer.mozilla.org/en-US/docs/Web/SVG/Attribute/rx), the `rx` attribute is to define a radius on the x-axis.

Ah ha! That explain why the QR code looks weird.

Also, the `rx` attribute's value is just 1s and 0s... Which means it's a binary data!

**Let's download the SVG and decode it!**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:30:23(HKT)]
└> wget http://stcode-3983gi.hkcert23.pwnable.hk:28211/flag1 -O flag1.svg
[...]
```

**First, we need to grab all the `<rect>` element with `rx` attribute:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:31:59(HKT)]
└> cat flag1.svg | grep "<rect rx="                                      
  <rect rx="0" x="31.03030303030303" y="31.03030303030303" width="7.757575757575758" height="7.757575757575758" style="fill:#000000;shape-rendering:crispEdges;"/>
  <rect rx="1" x="38.78787878787879" y="31.03030303030303" width="7.757575757575758" height="7.757575757575758" style="fill:#000000;shape-rendering:crispEdges;"/>
  <rect rx="1" x="46.54545454545455" y="31.03030303030303" width="7.757575757575758" height="7.757575757575758" style="fill:#000000;shape-rendering:crispEdges;"/>
[...]
```

**Then, using the `=` character as the delimiter and extract `rx`'s value:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:33:07(HKT)]
└> cat flag1.svg | grep "<rect rx=" | cut -d"=" -f2
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:33:25(HKT)]
└> cat flag1.svg | grep "<rect rx=" | cut -d"=" -f2
"0" x
"1" x
"1" x
"0" x
[...]
```

**Repeat it again, but this time with the `"` character as the delimiter:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:34:07(HKT)]
└> cat flag1.svg | grep "<rect rx=" | cut -d"=" -f2 | cut -d'"' -f2
0
1
1
0
[...]
```

**Next, we need to remove the newline (`\n`) character, so that we can decode the binary:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:34:08(HKT)]
└> cat flag1.svg | grep "<rect rx=" | cut -d"=" -f2 | cut -d'"' -f2 | tr -d "\n"                   
011010000110101101100011011001010111001001110100001100100011001101111011010100110101010001011111010100110101010000100110011100110011010001011111010100110101010001100101011001110110000101101110001100000110011101110010011000010111000001101000011110010010110100101101010100110101010001100101011001110011000001111101
```

**Finally, we can decode the binary via Perl (from [this StackExchange post](https://unix.stackexchange.com/questions/98948/ascii-to-binary-and-binary-to-ascii-conversion-tools)):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/misc/ST-Code-(I))-[2023.11.12|20:37:55(HKT)]
└> cat flag1.svg | grep "<rect rx=" | cut -d"=" -f2 | cut -d'"' -f2 | tr -d "\n" | perl -lpe '$_=pack"B*",$_'   
hkcert23{ST_ST&s4_STegan0graphy--STeg0}
```

- **Flag: `hkcert23{ST_ST&s4_STegan0graphy--STeg0}`**

## Conclusion

What we've learned:

1. Decoding binary inside a SVG file (steganography)