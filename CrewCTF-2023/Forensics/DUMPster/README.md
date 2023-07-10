# DUMPster

## Overview

- 26 solves / 775 points
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

[https://mega.nz/file/nuYCwLAA#44X9MnxYu4Cjk04hhUrg2a9KBNWYkC8Hx8R04XTZYdo](https://mega.nz/file/nuYCwLAA#44X9MnxYu4Cjk04hhUrg2a9KBNWYkC8Hx8R04XTZYdo)

![](https://github.com/siunam321/CTF-Writeups/blob/main/CrewCTF-2023/images/Pasted%20image%2020230710143029.png)

## Find the flag

**In this challenge, we can download a [file](https://mega.nz/file/nuYCwLAA#44X9MnxYu4Cjk04hhUrg2a9KBNWYkC8Hx8R04XTZYdo):**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:46:34(HKT)]
└> file thc-frn-chall-KhXsy1qlzoSDSF9M.zip   
thc-frn-chall-KhXsy1qlzoSDSF9M.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:47:03(HKT)]
└> unzip thc-frn-chall-KhXsy1qlzoSDSF9M.zip
Archive:  thc-frn-chall-KhXsy1qlzoSDSF9M.zip
  inflating: Debian_5.10.0-20-amd64_profile.zip  
  inflating: memory                  
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:47:11(HKT)]
└> file *
Debian_5.10.0-20-amd64_profile.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
memory:                             ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style
thc-frn-chall-KhXsy1qlzoSDSF9M.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

As you can see, it's a memory dump file.

We can try to use a memory forensic tool called Volatility.

**However, I wanna try `strings` first:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:50:22(HKT)]
└> strings memory | grep -nE 'crew{.*'
222308:crew{k3yc7l_us3r_kk
```

Wait... It actually worked? lol

```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:54:56(HKT)]
└> strings memory | grep -n '' | grep -E '^222308'
222308:crew{k3yc7l_us3r_kk
^C
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:55:00(HKT)]
└> strings memory | grep -n '' | grep -E '^222309'
222309:3y5_are
^C
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.08|23:55:02(HKT)]
└> strings memory | grep -n '' | grep -E '^222310'
222310:7_s3cur3}
```

So the flag should be: `crew{k3yc7l_us3r_kk3y5_are7_s3cur3}`. However, I tried that, and it's wrong.

**Then, I dumped the `.bash_history` in the memory dump:**
```
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.09|14:52:01(HKT)]
└> python2 /opt/volatility/vol.py --plugin=. --profile=LinuxDebian_5_10_0-20-amd64_profilex64 -f memory linux_bash            
Volatility Foundation Volatility Framework 2.6.1
WARNING : volatility.debug    : Overlay structure cpuinfo_x86 not present in vtypes
WARNING : volatility.debug    : Overlay structure cpuinfo_x86 not present in vtypes
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
     511 bash                 2022-12-28 10:34:19 UTC+0000   cat > flag.txt
     511 bash                 2022-12-28 10:34:51 UTC+0000   sudo apt update
     511 bash                 2022-12-28 10:34:56 UTC+0000   sudo apt upgrade
     511 bash                 2022-12-28 10:35:02 UTC+0000   sudo apt install keyutils
     511 bash                 2022-12-28 10:35:23 UTC+0000   head -c 16 /dev/urandom | keyctl padd user key @s
     511 bash                 2022-12-28 10:36:01 UTC+0000   keyctl pipe 267809713 | openssl enc -pbkdf2 -iter 1000000 -aes-256-cbc -in flag.txt -out flag.txt.enc -pass stdin
     511 bash                 2022-12-28 10:36:08 UTC+0000   shred flag.txt
     511 bash                 2022-12-28 10:36:12 UTC+0000   UH??HH??t?????H??]?????D
     511 bash                 2022-12-28 10:36:12 UTC+0000   rm -rf flag.txt
```

In here, we can see that the `flag.txt` is created, `shred`, `rm`. However, the `flag.txt.enc`, which is encrypted via AES 256 CBC mode with 1000000 iteration, didn't get `shred` or `rm`.

**That being said, we can try to recover the `flag.txt.enc`, and decrypt it:**
```shell
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.09|15:44:24(HKT)]
└> python2 /opt/volatility/vol.py --plugin=. --profile=LinuxDebian_5_10_0-20-amd64_profilex64 -f memory linux_enumerate_files
[...]
0xffff9dbbddae2ae0                    393238 /home/alice/flag.txt.enc
[...]
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.09|15:45:18(HKT)]
└> python2 /opt/volatility/vol.py --plugin=. --profile=LinuxDebian_5_10_0-20-amd64_profilex64 -f memory linux_find_file -i 0xffff9dbbddae2ae0 -O 'flag.txt.enc'
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.09|15:45:26(HKT)]
└> file flag.txt.enc             
flag.txt.enc: openssl enc'd data with salted password
┌[siunam♥Mercury]-(~/ctf/CrewCTF-2023/Forensics/DUMPster)-[2023.07.09|15:45:28(HKT)]
└> cat flag.txt.enc             
Salted__���K(�%n�)�|_,�;�p�¸��g���nnhx�Fcj���8D�e�
```

But, the password is grabbed from 16 bytes of `/dev/urandom`, and stored in the kernel user session keyring (`keyctl padd user key @s`).

I wonder if it is possible to recover the password by extracting the user session keyring...

Unfortunately, I couldn't find any way to do that...