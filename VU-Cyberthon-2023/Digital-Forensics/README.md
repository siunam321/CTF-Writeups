# What is SHA1 checksum of image file blk0_mmcblk0.bin ?

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225161806.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Digital-Forensics)-[2023.02.25|16:18:42(HKT)]
└> file blk0_mmcblk0.7z            
blk0_mmcblk0.7z: 7-zip archive data, version 0.4
```

**It's a 7zip file, let's unzip it:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Digital-Forensics)-[2023.02.25|16:18:44(HKT)]
└> 7z e blk0_mmcblk0.7z
[...]
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Digital-Forensics)-[2023.02.25|16:23:37(HKT)]
└> file blk0_mmcblk0.bin; ls -lah blk0_mmcblk0.bin 
blk0_mmcblk0.bin: DOS/MBR boot sector; partition 1 : ID=0xee, start-CHS (0x0,0,0), end-CHS (0x0,0,0), startsector 1, 15269887 sectors, extended partition table (last)
-rw-r--r-- 1 siunam nam 7.3G Jan 15 07:21 blk0_mmcblk0.bin
```

**Then, we can use `sha1sum` to get it's SHA1 checksum value:**
```shell
┌[siunam♥earth]-(~/ctf/VU-Cyberthon-2023/Digital-Forensics)-[2023.02.25|16:23:56(HKT)]
└> sha1sum blk0_mmcblk0.bin 
5377521a476be72837053390b24bc167d8f9182c  blk0_mmcblk0.bin
```

- **Flag: `VU{5377521a476be72837053390b24bc167d8f9182c}`**

## What is the name of the largest partition?

In here, we can use a forensic tool called "AccessData FTK", which is a tool to view disk images:

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225174920.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225174928.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225174936.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225174822.png)

As you can see, the `userdata` partition is the largest one.

- **Flag: `VU{userdata}`**

## What is the brand (vendor) of phone?

**After digging around in AccessData FTK, I found this directory:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225175937.png)

Found the vendor!

- **Flag: `VU{samsung}`**

## What is the model of phone?

**After some digging, I found that in the `userdata` partition, there's a WPA wireless config file, which has the phone's model:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225181924.png)

- **Flag: `VU{SM-G530FZ}`**

## What was the Bluetooth MAC Address of the device?

**In the `efs` partition, we can find the Bluetooth MAC address:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/VU-Cyberthon-2023/images/Pasted%20image%2020230225181014.png)

- **Flag: `VU{E0:99:71:8E:05:D0}`**

# Conclusion

What we've learned:

1. SHA1 Checksum
2. Viewing Phone Disk Image