# Bridget's Back!

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find The Flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 655 solves / 100 points
- Author: Yo_Yo_Bro
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Bridget's travelling the globe and found this marvellous bridge, can you uncover where she took the photo from?

NOTE: Flag is case-insensitive and requires placing inside `DUCTF{}` wrapper! e.g `DUCTF{a_b_c_d_example}`

Author: Yo_Yo_Bro

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230904232318.png)

## Find The Flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/osint/Bridget's-Back!/BridgetsBack.jpg):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/osint/Bridget's-Back!)-[2023.09.05|19:00:36(HKT)]
└> file BridgetsBack.jpg  
BridgetsBack.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 96x96, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=4, xresolution=62, yresolution=70, resolutionunit=2, software=paint.net 5.0.9], baseline, precision 8, 4000x2923, components 3
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190058.png)

In this image, it shows an image of a bridge.

**Hmm... Let's use reverse image search to try to search the bridge's location.**

**To do so, I'll use [Google Lens](https://www.google.com/imghp?hl=en):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190537.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190550.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190604.png)

Oh! **Golden Gate Bridge**??

**Let's go to Google Maps to find the exact location of the image:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190838.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190905.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905190949.png)

> Note: Hold Shift key and drag the map to move around.

**After comparing the image and the map, I found that the exact location is "[H. Dana Bowers Memorial Vista Point](https://www.google.com/maps/place/H.+Dana+Bowers+Memorial+Vista+Point/@37.8333294,-122.4800244,40a,35y,169.31h,79.18t/data=!3m1!1e3!4m14!1m7!3m6!1s0x808586deffffffc3:0xcded139783705509!2sGolden+Gate+Bridge!8m2!3d37.8199286!4d-122.4782551!16zL20vMDM1cDM!3m5!1s0x80858426313ed5a7:0x182f416f571f51f4!8m2!3d37.8324927!4d-122.4796952!16s%2Fg%2F11jz5fx5gc?entry=ttu)":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905191552.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905191802.png)

- **Flag: `DUCTF{H._Dana_Bowers_Memorial_Vista_Point}`**

## Conclusion

What we've learned:

1. Reverse image search