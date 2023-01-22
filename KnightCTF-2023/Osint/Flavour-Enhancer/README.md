# Flavour Enhancer

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

- Challenge static score: 50

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121191424.png)

**In the challenge's description, we can download an attachment. Let's download it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121191436.png)

## Find the flag

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/OSINT/Flavour-Enhancer)-[2023.01.21|19:14:45(HKT)]
└> file chall_1.jpg   
chall_1.jpg: JPEG image data, baseline, precision 8, 420x310, components 3
```

As you can see, it's an `jpg` image file.

In the image file, we can see there are some texts: "Valgomoji", "Joduotoji", "Druska", "Akmens".

Let's google that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121192337.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121192346.png)

Hmm... Google translate that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121192401.png)

Lithuanian...

Also, it seems like the product is "Iodized rock salt purified", and it was mined at "Artyomsol" salt mine?

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121193126.png)

Hmm... "Soledar Salt Mines". Let's search for "Soledar Salt Mines orchestra":

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121193224.png)

**In that [Wikipedia](https://en.wikipedia.org/wiki/Soledar_Salt_Mine), we can see this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121193410.png)

**If you click the "Donetsk Philharmonic Society" reference link:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121194256.png)

We found the the name of the organization?

By googling that organization name, we found [this website](http://philharmonic.lg.ua/en/):

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121195159.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121195216.png)

In this website, we can find many orchestra names, but it's seems like none of them are correct??