# PNG-G

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 185 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Don't let appearances fool you.  
  
Good luck!  
  
Format : **Hero{}**  
Author : **Thibz**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514144301.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/Steganography/PNG-G/pngg.png):**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PNG-G)-[2023.05.14|14:43:24(HKT)]
└> file pngg.png 
pngg.png: PNG image data, 500 x 500, 8-bit/color RGB, non-interlaced
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PNG-G)-[2023.05.14|14:43:27(HKT)]
└> eog pngg.png                         

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514144341.png)

It's a PNG image file.

**According to [HackTricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks#stegoveritas-jpg-png-gif-tiff-bmp), we can use a tool called `stegoveritas.py`, which checks file metadata, create transformed images, brute force LSB, and more.check file metadata, create transformed images, brute force LSB, and more.**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PNG-G)-[2023.05.14|14:40:20(HKT)]
└> stegoveritas pngg.png 
Running Module: SVImage
+---------------------------+------+
|        Image Format       | Mode |
+---------------------------+------+
| Portable network graphics | RGB  |
+---------------------------+------+
Found something worth keeping!
DOS executable (COM), maybe with interrupt 22h, start instruction 0xeb33eb11 77c93fed
Found something worth keeping!
DOS executable (COM), start instruction 0xeb678fb5 c13af9f8
Found something worth keeping!
DOS executable (COM), start instruction 0xeb2cf23e 8ae61385
Found something worth keeping!
DOS executable (COM), start instruction 0xeb2f9e5c fa2d7341
Found something worth keeping!
DOS executable (COM), start instruction 0xeb2f33cb c3e8bab9
Found something worth keeping!
DOS executable (COM), maybe with interrupt 22h, start instruction 0xeb2f3e79 79cfa2ef
Found something worth keeping!
DOS executable (COM), start instruction 0xeb2f38cf 2f383e8b
Extracting 2 PNG frames.
Running Module: MultiHandler

Exif
====
+---------------------+----------------------------------------------------------+
| key                 | value                                                    |
+---------------------+----------------------------------------------------------+
| SourceFile          | /home/siunam/ctf/HeroCTF-v5/Steganography/PNG-G/pngg.png |
| ExifToolVersion     | 12.57                                                    |
| FileName            | pngg.png                                                 |
| Directory           | /home/siunam/ctf/HeroCTF-v5/Steganography/PNG-G          |
| FileSize            | 512 kB                                                   |
| FileModifyDate      | 2023:05:13 16:24:16+08:00                                |
| FileAccessDate      | 2023:05:13 16:24:36+08:00                                |
| FileInodeChangeDate | 2023:05:13 16:24:35+08:00                                |
| FilePermissions     | -rw-r--r--                                               |
| FileType            | APNG                                                     |
| FileTypeExtension   | png                                                      |
| MIMEType            | image/apng                                               |
| ImageWidth          | 500                                                      |
| ImageHeight         | 500                                                      |
| BitDepth            | 8                                                        |
| ColorType           | RGB                                                      |
| Compression         | Deflate/Inflate                                          |
| Filter              | Adaptive                                                 |
| Interlace           | Noninterlaced                                            |
| AnimationFrames     | 2                                                        |
| AnimationPlays      | inf                                                      |
| Transparency        | 0 0 16                                                   |
| ImageSize           | 500x500                                                  |
| Megapixels          | 0.25                                                     |
+---------------------+----------------------------------------------------------+
Found something worth keeping!
PNG image data, 500 x 500, 8-bit/color RGB, non-interlaced
+---------+------------------+----------------------------------------+------------+
| Offset  | Carved/Extracted | Description                            | File Name  |
+---------+------------------+----------------------------------------+------------+
| 0x75    | Carved           | Zlib compressed data, best compression | 75.zlib    |
| 0x75    | Extracted        | Zlib compressed data, best compression | 75         |
| 0x7c377 | Carved           | Zlib compressed data, best compression | 7C377.zlib |
| 0x7c377 | Extracted        | Zlib compressed data, best compression | 7C377      |
+---------+------------------+----------------------------------------+------------+
```

**After the check, we can view it's extracted contents:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PNG-G)-[2023.05.14|14:43:44(HKT)]
└> ls -lah results 
total 12M
drwxr-xr-x 4 siunam nam 4.0K May 14 14:40 .
drwxr-xr-x 3 siunam nam 4.0K May 14 14:40 ..
drwxr-xr-x 2 siunam nam 4.0K May 14 14:40 exif
drwxr-xr-x 2 siunam nam 4.0K May 14 14:40 keepers
-rw-r--r-- 1 siunam nam 527K May 14 14:40 pngg.png_autocontrast.png
-rw-r--r-- 1 siunam nam  51K May 14 14:40 pngg.png_Blue_0.png
-rw-r--r-- 1 siunam nam  52K May 14 14:40 pngg.png_Blue_1.png
-rw-r--r-- 1 siunam nam  52K May 14 14:40 pngg.png_Blue_2.png
-rw-r--r-- 1 siunam nam  52K May 14 14:40 pngg.png_Blue_3.png
-rw-r--r-- 1 siunam nam  51K May 14 14:40 pngg.png_Blue_4.png
-rw-r--r-- 1 siunam nam  45K May 14 14:40 pngg.png_Blue_5.png
-rw-r--r-- 1 siunam nam  31K May 14 14:40 pngg.png_Blue_6.png
-rw-r--r-- 1 siunam nam  13K May 14 14:40 pngg.png_Blue_7.png
-rw-r--r-- 1 siunam nam 248K May 14 14:40 pngg.png_blue_plane.png
-rw-r--r-- 1 siunam nam 599K May 14 14:40 pngg.png_Edge-enhance_More.png
-rw-r--r-- 1 siunam nam 677K May 14 14:40 pngg.png_Edge-enhance.png
-rw-r--r-- 1 siunam nam 261K May 14 14:40 pngg.png_enhance_sharpness_-100.png
-rw-r--r-- 1 siunam nam 252K May 14 14:40 pngg.png_enhance_sharpness_100.png
-rw-r--r-- 1 siunam nam 517K May 14 14:40 pngg.png_enhance_sharpness_-25.png
-rw-r--r-- 1 siunam nam 472K May 14 14:40 pngg.png_enhance_sharpness_25.png
-rw-r--r-- 1 siunam nam 369K May 14 14:40 pngg.png_enhance_sharpness_-50.png
-rw-r--r-- 1 siunam nam 347K May 14 14:40 pngg.png_enhance_sharpness_50.png
-rw-r--r-- 1 siunam nam 299K May 14 14:40 pngg.png_enhance_sharpness_-75.png
-rw-r--r-- 1 siunam nam 285K May 14 14:40 pngg.png_enhance_sharpness_75.png
-rw-r--r-- 1 siunam nam 580K May 14 14:40 pngg.png_equalize.png
-rw-r--r-- 1 siunam nam 419K May 14 14:40 pngg.png_Find_Edges.png
-rw-r--r-- 1 siunam nam 497K May 14 14:40 pngg.png_frame_0.png
-rw-r--r-- 1 siunam nam 3.5K May 14 14:40 pngg.png_frame_1.png
-rw-r--r-- 1 siunam nam 274K May 14 14:40 pngg.png_GaussianBlur.png
-rw-r--r-- 1 siunam nam 182K May 14 14:40 pngg.png_grayscale.png
-rw-r--r-- 1 siunam nam  54K May 14 14:40 pngg.png_Green_0.png
-rw-r--r-- 1 siunam nam  54K May 14 14:40 pngg.png_Green_1.png
-rw-r--r-- 1 siunam nam  54K May 14 14:40 pngg.png_Green_2.png
-rw-r--r-- 1 siunam nam  54K May 14 14:40 pngg.png_Green_3.png
-rw-r--r-- 1 siunam nam  53K May 14 14:40 pngg.png_Green_4.png
-rw-r--r-- 1 siunam nam  48K May 14 14:40 pngg.png_Green_5.png
-rw-r--r-- 1 siunam nam  36K May 14 14:40 pngg.png_Green_6.png
-rw-r--r-- 1 siunam nam  21K May 14 14:40 pngg.png_Green_7.png
-rw-r--r-- 1 siunam nam 250K May 14 14:40 pngg.png_green_plane.png
-rw-r--r-- 1 siunam nam 527K May 14 14:40 pngg.png_inverted.png
-rw-r--r-- 1 siunam nam 316K May 14 14:40 pngg.png_Max.png
-rw-r--r-- 1 siunam nam 417K May 14 14:40 pngg.png_Median.png
-rw-r--r-- 1 siunam nam 305K May 14 14:40 pngg.png_Min.png
-rw-r--r-- 1 siunam nam 531K May 14 14:40 pngg.png_Mode.png
-rw-r--r-- 1 siunam nam  54K May 14 14:40 pngg.png_Red_0.png
-rw-r--r-- 1 siunam nam  54K May 14 14:40 pngg.png_Red_1.png
-rw-r--r-- 1 siunam nam  55K May 14 14:40 pngg.png_Red_2.png
-rw-r--r-- 1 siunam nam  55K May 14 14:40 pngg.png_Red_3.png
-rw-r--r-- 1 siunam nam  55K May 14 14:40 pngg.png_Red_4.png
-rw-r--r-- 1 siunam nam  49K May 14 14:40 pngg.png_Red_5.png
-rw-r--r-- 1 siunam nam  38K May 14 14:40 pngg.png_Red_6.png
-rw-r--r-- 1 siunam nam  22K May 14 14:40 pngg.png_Red_7.png
-rw-r--r-- 1 siunam nam 250K May 14 14:40 pngg.png_red_plane.png
-rw-r--r-- 1 siunam nam 621K May 14 14:40 pngg.png_Sharpen.png
-rw-r--r-- 1 siunam nam 439K May 14 14:40 pngg.png_Smooth.png
-rw-r--r-- 1 siunam nam 523K May 14 14:40 pngg.png_solarized.png
```

**In `result/pngg.png_frame_1.png`, we can see the flag:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Steganography/PNG-G)-[2023.05.14|14:45:39(HKT)]
└> eog results/pngg.png_frame_1.png 

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514144619.png)

- **Flag: `Hero{Not_Just_A_PNG}`**

## Conclusion

What we've learned:

1. Extracting Hidden Frames In PNG