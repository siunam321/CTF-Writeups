# findme

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

find the Coordinate ( be precise )

example : crew{19.3212,122.1235}

flag md5 : cbb510f471de8b8808890599e9893afa (example cmd: `echo -n "crew{19.3212,122.1235}" | md5sum`)

Author : st4rn

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708165816.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/Misc/findme/chall.png):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Misc/findme)-[2023.07.08|16:58:47(HKT)]
└> file chall.png  
chall.png: PNG image data, 1920 x 963, 8-bit/color RGB, non-interlaced
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708165900.png)

As you can see, **it's a road somewhere in Japan**. (As a Hongkonger, I can read traditional and simplify Chinese, as well as some kanji, so right off the bat I knew it's in Japan.)

During doing OSINT in finding a place, I always take a note of some characteristics of the picture:

1. Tall building on the top left
2. 2 road signs, 1 is brown, 1 is blue
3. It has an overpass, stair is on the right side
4. It has a shelter map on the left side (避難場所)
5. It has a mountain in the middle

Armed with the above information, we can start finding the abstract location of the picture.

**First, I wanna search where 甲斐 is:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708170910.png)

As you can see, there's mountains on the west side:

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708171018.png)

Therefore, the picture's location is somewhat near 甲斐.

**Then, I started looking for the tall building, and I found this:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708171509.png)

Which looks very similar to the picture's one.

**Then, I found the blue road sign:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708171632.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230708171715.png)

Nice! We found it!

**However, I couldn't find the exact coordinate, so I brute forced it lol:**
```python
#!/usr/bin/env python3
from hashlib import md5

if __name__ == '__main__':
    targetFlagMd5 = 'cbb510f471de8b8808890599e9893afa'
    latitude = '35'
    longitude = '138'
    try:
        for latitudeDecimal in range(6600, 10000):
            for longitudeDecimal in range(5000, 10000):
                coordinate = f'{latitude}.{latitudeDecimal:04d},{longitude}.{longitudeDecimal:04d}'
                flag = 'crew{' + coordinate + '}'
                hashed = md5(flag.encode('utf-8')).hexdigest()
                
                print(f'[*] Trying coordinate: {coordinate} ({flag}). Hashed: {hashed}', end='\r')
                if hashed == targetFlagMd5:
                    print(f'\n[+] Found correct coordinate: {coordinate}. Hashed: {hashed}')
                    exit(0)
    except KeyboardInterrupt:
        print('\n[*] Bye!')
```

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Misc/findme)-[2023.07.08|17:36:10(HKT)]
└> python3 solve.py
[*] Trying coordinate: 35.6682,138.5699 (crew{35.6682,138.5699}). Hashed: cbb510f471de8b8808890599e9893afa
[+] Found correct coordinate: 35.6682,138.5699. Hashed: cbb510f471de8b8808890599e9893afa
```

- **Flag: `crew{35.6682,138.5699}`**

## Conclusion

What we've learned:

1. Finding Location Via OSINT