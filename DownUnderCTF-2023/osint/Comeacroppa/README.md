# Comeacroppa

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find The Flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 544 solves / 100 points
- Author: Yo_Yo_Bro
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

I was sorting through my photo album and I cannot seem to place this picture. Can you let me know what suburb this is in?

Flag format DUCTF{suburb}

Author: Nosurf

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905191850.png)

## Find The Flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/osint/Comeacroppa/ComeACroppa.png):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/osint/Comeacroppa)-[2023.09.05|19:19:30(HKT)]
└> file ComeACroppa.png    
ComeACroppa.png: PNG image data, 1682 x 1238, 8-bit/color RGBA, non-interlaced
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905191946.png)

**In this image, we can actually see 1 big hint - the building on the left-hand side:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905192134.png)

**We can also upload this image to Google Lens for reverse image search:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905192249.png)

Right off the bat, the first result is very similar to the challenge's image!

Let's go to [that website](https://tours.maldonmuseum.com.au/index.php/mobile/walks/9) and **search for 1800, 1866, 1860**, etc.

**Upon searching, I found this "Scotch Pie House":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905192646.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905192707.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230905192723.png)

Which matches the challenge's image's left-hand side building! And **the suburb is "Maldon".**

- **Flag: `DUCTF{Maldon}`**

## Conclusion

What we've learned:

1. Reverse image search