# CATS!

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- 683 solves / 107 points

## Background

> Author: burturt

CATS OMG I CAN'T BELIEVE HOW MANY CATS ARE IN THIS IMAGE I NEED TO VISIT CAN YOU FIGURE OUT THE NAME OF THIS CAT HEAVEN?

Answer is the domain of the website for this location. For example, if the answer was ucla, the flag would be lactf{ucla.edu}.

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211121423.png)

## Find the flag

**In this challenge, we can download a jpeg [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/Misc/CATS!/CATS.jpeg):**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Misc/CAT!)-[2023.02.11|12:15:00(HKT)]
└> file CATS.jpeg 
CATS.jpeg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=12, manufacturer=Apple, model=iPhone SE (2nd generation), orientation=upper-right, xresolution=192, yresolution=200, resolutionunit=2, software=15.5, datetime=2022:06:17 12:52:05, hostcomputer=iPhone SE (2nd generation), GPS-Data], baseline, precision 8, 4032x3024, components 3
```

**Now, we can use `exiftool` to view it's metadata:**
```shell
┌[siunam♥earth]-(~/ctf/LA-CTF-2023/Misc/CAT!)-[2023.02.11|12:15:35(HKT)]
└> exiftool CATS.jpeg                                       
[...]
Sub-location                    : Lanai Cat Sanctuary
Province-State                  : HI
Country-Primary Location Code   : US
Country-Primary Location Name   : United States
[...]
Country Code                    : US
Location                        : Lanai Cat Sanctuary
Location Created City           : Lanai City
Location Created Country Code   : US
Location Created Country Name   : United States
Location Created Province State : HI
Location Created Sublocation    : Lanai Cat Sanctuary
City                            : Lanai City
Country                         : United States
State                           : HI
[...]
Thumbnail Image                 : (Binary data 11136 bytes, use -b option to extract)
GPS Latitude                    : 20 deg 47' 27.52" N
GPS Longitude                   : 156 deg 57' 50.03" W
GPS Latitude Ref                : North
GPS Longitude Ref               : West
Circle Of Confusion             : 0.004 mm
Field Of View                   : 65.5 deg
Focal Length                    : 4.0 mm (35 mm equivalent: 28.0 mm)
GPS Position                    : 20 deg 47' 27.52" N, 156 deg 57' 50.03" W
[...]
```

As you can see, we have lots of data.

In the `Location` field, we see: ***Lanai Cat Sanctuary***, which is the image's location!

**Let's google that:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211121909.png)

Right off the bat, we see [this website](https://lanaicatsanctuary.org/):

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2023/images/Pasted%20image%2020230211121930.png)

Hence, the flag is:

- **Flag: `lactf{lanaicatsanctuary.org}`**

# Conclusion

What we've learned:

1. View Image Metadata Via `exiftool`