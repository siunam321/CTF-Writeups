# Encrypt10n

## Table of Contents

1. [Encrypt10n (Part 1)](#encrypt10n-part-1)
    - [Overview](#overview)
    - [Background](#background)
    - [Find the flag](#find-the-flag)
2. [Encrypt10n (Part 2)](#encrypt10n-part-2)
    - [Overview](#overview-1)
    - [Background](#background-1)
    - [Find the flag](#find-the-flag)
3. [Conclusion](#conclusion)

## Encrypt10n (Part 1)

### Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

### Background

We made a memory dump on the criminal machine after entering the crime scene. Our investigator thought he was using encryption software to hide the secret. can you help me to detect it?

Q1 : crew{password}

[Link](https://drive.google.com/file/d/1NuQXOdmXbCGVwL5HIO0DDOlFQ-ZuJnB3/view?usp=share_link)

Author : 0xSh3rl0ck

### Find the flag

**In this challenge, we can download a [file](https://drive.google.com/file/d/1NuQXOdmXbCGVwL5HIO0DDOlFQ-ZuJnB3/view?usp=share_link):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:10:29(HKT)]
└> ls -lah dump.raw && file dump.raw 
-rw-r--r-- 1 siunam nam 1.0G Jul  8 20:49 dump.raw
dump.raw: Windows Event Trace Log
```

As you can see, it's a memory dump file.

To perform memory forensic, we can use a tool called **Volatility**. Through out this challenge, I'll use Volatility version 2 (volatility2).

**First, we need to know the machine's profile:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:12:15(HKT)]
└> python2 /opt/volatility/vol.py imageinfo -f dump.raw 
[...]
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
[...]
```

- Found profile: `Win7SP1x86_23418`

**Then, we can find all the processes in the memory dump:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:13:38(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f dump.raw pslist
[...]
0x85c596c0 TrueCrypt.exe          3196   1384      2       67      1      0 2023-02-16 12:02:07 UTC+0000                                 
[...]
```

In here, we can found that there's a `TrueCrypt.exe` process.

> **TrueCrypt** is a discontinued [source-available](https://en.wikipedia.org/wiki/Source-available "Source-available") [freeware](https://en.wikipedia.org/wiki/Freeware "Freeware") [utility](https://en.wikipedia.org/wiki/Utility_software "Utility software") used for [on-the-fly encryption](https://en.wikipedia.org/wiki/On-the-fly_encryption "On-the-fly encryption") (OTFE). It can create a virtual encrypted disk within a file, or encrypt a [partition](https://en.wikipedia.org/wiki/Disk_partitioning "Disk partitioning") or the whole [storage device](https://en.wikipedia.org/wiki/Data_storage_device "Data storage device") ([pre-boot authentication](https://en.wikipedia.org/wiki/Pre-boot_authentication "Pre-boot authentication")). (From [https://en.wikipedia.org/wiki/TrueCrypt](https://en.wikipedia.org/wiki/TrueCrypt))

**In volatility2, there's a plugin called `truecryptsummary`, which will display TrueCrypt summary information:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:15:29(HKT)]
└> python2 /opt/volatility/vol.py --profile=Win7SP1x86_23418 -f dump.raw truecryptsummary
[...]
Registry Version     TrueCrypt Version 7.0a
Password             Strooooong_Passwword at offset 0x8d23de44
Process              TrueCrypt.exe at 0x85c596c0 pid 3196
Service              truecrypt state SERVICE_RUNNING
Kernel Module        truecrypt.sys at 0x8d20a000 - 0x8d241000
Symbolic Link        Volume{a2e4e949-a9a8-11ed-859c-50eb71124999} -> \Device\TrueCryptVolumeZ mounted 2023-02-16 12:02:56 UTC+0000
Driver               \Driver\truecrypt at 0x3f02fc98 range 0x8d20a000 - 0x8d240980
Device               TrueCrypt at 0x84e2a9d8 type FILE_DEVICE_UNKNOWN
```

Nice! We found the password!

- **Flag: `crew{Strooooong_Passwword}`**

## Encrypt10n (Part 2)

### Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

### Background

Congrats Investigator for finding the first part can you use it to get the secret message?

[Link](https://drive.google.com/file/d/1x-857VSldVBR-ieF0bFqAD5cewLNuxVF/view?usp=sharing)

Author : 0xSh3rl0ck

### Find the flag

**In this challenge, we can download a [file](https://drive.google.com/file/d/1x-857VSldVBR-ieF0bFqAD5cewLNuxVF/view?usp=sharing):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:21:39(HKT)]
└> ls -lah flag && file flag
-rw-r--r-- 1 siunam nam 10M Jul  8 21:18 flag
flag: data
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:21:52(HKT)]
└> head -n 3 flag
K��3-��J,K�}��W��)29[|d ���C�6k��A�~�)���DA29Kw����`�u���6�B�?}����0e�]UbƢLj���!�!w.�W|z�'���;������1��F�-��q�y����ԝD&�o�e�{J#�%�|���\D�����&��%+}����ʖ�V��vl˾�����4���_ ���P:���o�P���=Βr��s�XD��av闐�L��j� �1og���@��ye�e{�
��p4�~,�dшkٙ�s�5��܏��:�y��rН�����l|�2�=J�?�[�Θ��n���vZލ�����Q����"�����{��<v]w+��>�Ǜ�JA�6��o���3��_����./6����F�ܽ
����/��е�`�����ɍ�Z$����>K�P~ꦓh������N�:�6�/��;{$^���SԮ�ɒ|��S�����^z�'DJQ7�N�Xl��M�3ơ\���لj�>���q�
```

As you can see, the `flag` file is just some raw bytes.

Based on the previous part, the `flag` file should be encrypted with TrueCrypt.

**So, we can use `truecrypt2john` to crack it:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:20:00(HKT)]
└> truecrypt2john flag > flag.truecrypt
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:20:07(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt orestis_id_rsa_hash.txt
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:20:10(HKT)]
└> nano password.txt
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:20:23(HKT)]
└> john --wordlist=password.txt flag.truecrypt 
[...]
Strooooong_Passwword (flag)     
```

Can confirm the password is `Strooooong_Passwword`.

**To decrypt the `file` file, we can use `cryptsetup`.** (All steps are from [https://kenfavors.com/code/how-to-open-a-truecrypt-container-using-cryptsetup/](https://kenfavors.com/code/how-to-open-a-truecrypt-container-using-cryptsetup/))

- Open the encrypted file container:

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:31:31(HKT)]
└> sudo cryptsetup --type tcrypt open flag flag 
Enter passphrase for flag: 
```

> Note: The first `flag` is the encrypted `flag`, the second one is a name of your choice.

- Create a folder for the volume:

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:37:26(HKT)]
└> mkdir /mnt/flag
```

- Mount the volume:

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:32:33(HKT)]
└> sudo mount -o uid=1000 /dev/mapper/flag /mnt/flag 
```

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n/file)-[2023.07.08|21:32:40(HKT)]
└> ls -lah /mnt/flag  
total 12K
drwxrwxrwx 1 siunam root 4.0K Feb 16 19:38 .
drwxr-xr-x 3 root   root 4.0K Jul  8 21:30 ..
-rwxrwxrwx 2 siunam root 2.4K Feb 12 01:08 flaaaaaaaaaaaaaaaaaaaaaaaag.txt
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n/file)-[2023.07.08|21:32:44(HKT)]
└> cat /mnt/flag/flaaaaaaaaaaaaaaaaaaaaaaaag.txt 
Vm0wd2QyUXlVWGxWV0d4V1YwZDRXRmxVU205V01WbDNXa2M1VjFac2JETlhhMk0xVjBaS2MySkVUbGhoTWsweFZtcEJlRll5U2tWVWJHaG9UV3N3ZUZadGNFdFRNVWw1VTJ0V1ZXSkhhRzlVVmxaM1ZsWmFkR05GWkZwV01VcEpWbTEwYTFkSFNrZGpSVGxhVmpOU1IxcFZXbUZrUjA1R1UyMTRVMkpIZHpGV1ZFb3dWakZhV0ZOcmJGSmlSMmhZV1d4b2IwMHhXbGRYYlhSWFRWZDBObGxWV2xOVWJGcFlaSHBDVjAxdVVuWlZha1pYWkVaT2MxZHNhR2xTTW1oWlYxWmtNRmxXVWtkV1dHaFlZbGhTV0ZSV2FFTlNiRnBZWlVoa1YwMUVSbGRaTUZaM1ZqSktWVkpZWkZkaGExcFlXa1ZhVDJNeFpITmhSMnhUVFcxb1dsWXhaRFJWTVZsNFUydGthbEp0VWxsWmJGWmhZMVpzY2xkdFJteFdia0pIVmpKNFQxWlhTa2RqUm14aFUwaENSRlpxU2tabFZsSlpZVVprVTFKWVFrbFhXSEJIVkRKU1YxZHVUbFJpVjJoeldXeG9iMWRXV1hoYVJGSnBUV3RzTkZkclZtdFdiVXB5WTBac1dtSkhhRlJXTVZwWFkxWktjbVJHVWxkaWEwcElWbXBLZWs1V1dsaFRhMXBxVWxkb1dGUlhOVU5oUmxweFVtMUdUMkpGV2xwWlZWcGhZVWRGZUdOSE9WaGhNVnBvVmtSS1QyTXlUa1phUjJoVFRXMW9lbGRYZUc5aU1XUnpWMWhvWVZKR1NuQlVWM1J6VFRGU1ZtRkhPVmhTTUhCNVZHeGFjMWR0U2toaFJsSlhUVVp3VkZacVJuZFNWa1p5VDFkc1UwMHlhRmxXYlhCTFRrWlJlRmRzYUZSaVJuQnhWV3hrVTFsV1VsWlhiVVpPVFZad2VGVXlkREJXTVZweVkwWndXR0V4Y0hKWlZXUkdaVWRPU0U5V1pHaGhNSEJ2Vm10U1MxUnRWa2RqUld4VllsZG9WRlJYTlc5V1ZtUlhWV3M1VWsxWFVucFdNV2h2V1ZaS1IxTnNaRlZXYkZwNlZGUkdVMk15UmtaUFYyaHBVbGhDTmxkVVFtRmpNV1IwVTJ0a1dHSlhhRmhaVkVaM1ZrWmFjVkp0ZEd0U2EzQXdXbFZhYTJGV1NuTmhNMmhYWVRGd2FGWlVSbFpsUm1SMVUyczFXRkpZUW5oV1Z6QjRZakZaZUZWc2FFOVdlbXh6V1d0YWQyVkdWWGxrUkVKWFRWWndlVll5ZUhkWGJGcFhZMGhLVjJGcldreFdha3BQVWpKS1IxcEdaRTVOUlhCS1ZqRmFVMU14VlhoWFdHaFlZbXhhVjFsc2FHOVdSbXhaWTBaa1dGWnNjRmxaTUZVMVlWVXhXRlZ1Y0ZkTlYyaDJWMVphUzFJeFRuTmFSbFpYWWtadmVsWkdWbUZaVjFKR1RsWmFVRll5YUhCVmJHaENaREZrVjFadE9WVk5WbkF3VlcwMVMxWkhTbGhoUm1oYVZrVmFNMVpyV21GalZrcDFXa1pPVGxacmIzZFhiRlpyWXpGVmVWTnVTbFJoTTFKWVZGYzFiMWRHYkZWU2EzQnNVbTFTZWxsVldsTmhSVEZaVVc1b1YxWXphSEpXVkVaclVqRldjMkZGT1ZkaGVsWjVWMWQwWVdReVZrZFdibEpyVWtWS2IxbFljRWRsVmxKelZtNU9XR0pHY0ZoWk1GSlBWMnhhV0ZWclpHRldNMmhJV1RJeFIxSXlSa2hoUlRWWFYwVktSbFpxU2pSV01XeFhWVmhvWVZKWFVsWlpiWFIzWWpGV2NWTnRPVmRTYlhoNVZtMDFhMVl4V25OalNHaFdWak5vY2xaclZYaFhSbFp6WVVaa1RtRnNXazFXYWtKclV6Rk9SMVp1VWxCV2JGcFlXV3RvUTJJeFdrZFdiVVphVm14c05WVnRkRzlWUmxsNVlVWm9XbGRJUWxoVk1GcGhZMVpPY1ZWc1drNVdNVWwzVmxSS05GWXhWWGxUYTJSVVlsVmFWbFp0ZUhkTk1WcHlWMjFHYWxacmNEQlZiVEV3VmpKS2NsTnJiRmROYmxKeVdYcEdWbVF3TVVsaVIwWnNZVEZ3V1ZkWGVHOVJNVkpIVld4YVlWSldjSE5WYlRGVFYyeHNjbGRzVG1oU1ZFWjZWVEkxYjFZeFdYcGhSMmhoVWtWYVlWcFZXbXRrVmxaMFpVWk9XRkpyY0ZwV2ExcGhXVlpzVjFSclpGZGlhelZYV1cxek1WWXhXblJsUjBaWFlrWktWMVpYTlV0VlZsWlZUVVJyUFE9PQ==
```

Uhh... The `flaaaaaaaaaaaaaaaaaaaaaaaag.txt` file is in base64 encoding. (You can tell it's base64 encoded is because the last 2 characters are `=`, which is a padding character in base64)

**Let's base64 decode it:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:39:58(HKT)]
└> nano flag.b64 
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:40:08(HKT)]
└> base64 -d flag.b64 
Vm0wd2QyUXlVWGxWV0d4WFlUSm9WMVl3Wkc5V1ZsbDNXa2M1V0ZKc2JETlhhMk0xVmpBeFYySkVUbGhoTWsweFZtcEtTMUl5U2tWVWJHaG9UVlZ3VlZadGNFZFpWMUpJVm10a1dHSkdjRTlaVjNSR1pVWmFkR05GU214U2JHdzFWVEowVjFaWFNrbFJiR2hYWWxob00xWldXbXRXTVd0NllVWlNUbFpYZHpCV01uUnZVakZXZEZOc1dsaGlSMmhZV1ZkMFlWUkdWWGhYYlhSWFRWaENSbFpYZUhkV01ERldZMFZ3VjJKVVJYZFdha1pYWkVaT2MxZHNhR2xTTW1oWlYxZDRVMVl4U2tkalJtUllZbFZhY1ZscldtRmxWbkJHVjJ4T1ZXSkdjRmxhU0hCRFZqSkZlVlJZYUZkU1JYQklXWHBHVDJSV1duTlRiV2hzWWxob1dWWXhaRFJpTWtsNFdrVmtWbUpyY0ZsWmJHaFRWMVpXY1ZKcmRGUldia0pIVmpKek5WWlhTa1pqUldoWFRXNUNhRlpxUm1GT2JFWlpZVVphYUdFeGNHOVhhMVpoVkRKT2MyTkZaR2hTTW1oeldXeG9iMWRzV1hoYVJGSnBUV3RzTTFSVmFHOVhSMHB5VGxac1dtSkhhRlJXTUZwVFZqRndSVkZyT1dsU00yaFlWbXBLTkZReFdsaFRiRnBxVWxkU1lWUlZXbUZOTVZweFUydDBWMVpyY0ZwWGExcHJZVWRGZUdOSE9WZGhhMHBvVmtSS1RtVkdjRWxVYldoVFRXNW9WVmRXVWs5Uk1XUnpWMWhvWVZKR1NsZFVWbFp6VFRGU2MyRkZPV2hpUlhCNldUQmFjMWR0U2tkWGJXaFhZVEZ3VkZacVJtdGtSa3AwWlVaa2FWSnNhM2hXYTFwaFZURlZlRmR1U2s1WFJYQnhWVzB4YjFZeFVsaE9WemxzWWtad2VGVXlkREJXTVZweVYyeHdXbFpXY0hKV2FrWkxWakpPUjJKR1pGZE5NRXBKVjFaU1MxVXhXWGhYYmxaV1lsaG9WRmxZY0ZkWFZscFlZMFU1YVUxWFVucFdNV2h2V1ZaS1IxTnNaRlZXYkZvelZGVmFZV1JGTlZaUFYyaHBVbGhCZDFkV1ZtOVVNVnAwVW01S1ZHSlhhRmhaVkVaM1ZrWmFjVkp1WkZOTlZrb3dXbFZrYzFVeVNuSlRhM1JYVFc1b1dGbFVSa3BsUm1SellVWlNhRTFZUW5oV1YzaHJWVEZrUjFWc2FFOVdhelZ5V1d0YWQyVkdWblJrUkVKb1lYcEdlVlJzVm5OWGJGcFhZMFJPV2xaWFVrZGFWM2hIWTIxR1IyRkhhRTVXV0VKRlZqSjRWMWxXVVhoYVJXUlZZbXR3YjFWcVNtOVdSbXh5Vm01a1YxWnNjSGhWVjNoclZrVXhXRlZzYUZkTmFsWk1WakJrUzFOR1ZuUlBWbFpYWWtoQ2IxWkdWbUZaVmxsNVVtdG9VRll5YUZoWldIQlhVMFphY1ZOcVVsWk5WMUl3VlRKNFYxVXlTa2RUYlVaVlZteHdNMVpyV21GalZrcDBVbTEwVjJKclNrbFdNblJyWXpGVmQwMUliR0ZsYTFwWVdXeG9RMVJHVWxaYVJWcHNVbTFTV2xscldsTmhSVEZ6VTI1b1YxWXphR2hhUkVaYVpVWmtkVlZ0ZUZOWFJrcFpWa1phWVZsV1RrZFdiazVXWW1zMVYxWnRlR0ZXYkZKV1ZXNUtVVlZVTURrPQ==
```

Bruh, base64 heaven...

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/Encrypt10n)-[2023.07.08|21:41:16(HKT)]
└> base64 -d flag.b64 | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d | base64 -d
crew{Tru33333_Crypt_w1th_V014t1l1ty!}
```

You could write a script to automate it, but I'm lazy :D

- **Flag: `crew{Tru33333_Crypt_w1th_V014t1l1ty!}`**

## Conclusion

What we've learned:

1. Memory Forensic With Volatility
2. Decrypting TrueCrypt Encrypted File