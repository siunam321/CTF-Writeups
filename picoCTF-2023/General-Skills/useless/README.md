# useless

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Description

Author: Geoffrey Njogu

Description

Can you read files in the root file?

The system admin has provisioned an account for you on the main server: `ssh -p 64378 picoplayer@saturn.picoctf.net` Password: `Sd9KYTm5kr` Can you login and read the root file?

## Find the flag

**In this challenge, we can connect to the instance via SSH:**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Web-Exploitation/Java-Code-Analysis!?!/src)-[2023.03.16|15:15:08(HKT)]
└> ssh -p 51324 picoplayer@saturn.picoctf.net
The authenticity of host '[saturn.picoctf.net]:51324 ([13.59.203.175]:51324)' can't be established.
ED25519 key fingerprint is SHA256:ves7M6DhshpiJSsScBWo3n34oOFTUXvLZqPyqLWeTHk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[saturn.picoctf.net]:51324' (ED25519) to the list of known hosts.
picoplayer@saturn.picoctf.net's password: 
[...]
picoplayer@challenge:~$ 
```

**In the home directory, we found Bash script file called `useless`:**
```shell
picoplayer@challenge:~$ ls -lah
total 16K
drwxr-xr-x 1 picoplayer picoplayer   20 Mar 16 07:16 .
drwxr-xr-x 1 root       root         24 Mar 16 02:30 ..
-rw-r--r-- 1 picoplayer picoplayer  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 picoplayer picoplayer 3.7K Feb 25  2020 .bashrc
drwx------ 2 picoplayer picoplayer   34 Mar 16 07:16 .cache
-rw-r--r-- 1 picoplayer picoplayer  807 Feb 25  2020 .profile
-rwxr-xr-x 1 root       root        517 Mar 16 01:30 useless
```

**useless:**
```bash
#!/bin/bash
# Basic mathematical operations via command-line arguments

if [ $# != 3 ]
then
  echo "Read the code first"
else
	if [[ "$1" == "add" ]]
	then 
	  sum=$(( $2 + $3 ))
	  echo "The Sum is: $sum"  

	elif [[ "$1" == "sub" ]]
	then 
	  sub=$(( $2 - $3 ))
	  echo "The Substract is: $sub" 

	elif [[ "$1" == "div" ]]
	then 
	  div=$(( $2 / $3 ))
	  echo "The quotient is: $div" 

	elif [[ "$1" == "mul" ]]
	then
	  mul=$(( $2 * $3 ))
	  echo "The product is: $mul" 

	else
	  echo "Read the manual"
	 
	fi
fi
```

This Bash script needs to provide 3 parameters:

```shell
./useless <add/sub/div/mul> <number_1> <number_2>
```

If we don't provide any parameter, it'll output: `Read the code first`.

If we provided 3 parameters but not `add/sub/div/mul`, it'll output: `Read the manual`.

Hmm... Read the manual?

**To do so, I'll use a command called `man`, which is a command to read manuals:**
```
picoplayer@challenge:~$ man useless

useless
     useless, — This is a simple calculator script

SYNOPSIS
     useless, [add sub mul div] number1 number2

DESCRIPTION
     Use the useless, macro to make simple calulations like addition,subtraction, multiplica‐
     tion and division.

Examples
     ./useless add 1 2
       This will add 1 and 2 and return 3

     ./useless mul 2 3
       This will return 6 as a product of 2 and 3

     ./useless div 6 3
       This will return 2 as a quotient of 6 and 3

     ./useless sub 6 5
       This will return 1 as a remainder of substraction of 5 from 6

Authors
     This script was designed and developed by Cylab Africa

     picoCTF{us3l3ss_ch4ll3ng3_3xpl0it3d_4373}
```

Oh! We found the flag!

- **Flag: `picoCTF{us3l3ss_ch4ll3ng3_3xpl0it3d_4373}`**

## Conclusion

What we've learned:

1. Reading The Manual Page Via `man`