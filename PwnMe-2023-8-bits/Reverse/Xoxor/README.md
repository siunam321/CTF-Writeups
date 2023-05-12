# Xoxor

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 230 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

> Author: Zerotistic#0001

I need to buy that super duper extra legendary item no matter what !  
But I can't access their store... Maybe you can help me?

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506141449.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/Reverse/Xoxor/xoxor):**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/Xoxor)-[2023.05.06|14:15:09(HKT)]
└> file xoxor         
xoxor: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3570981d58a4391cef708c82da49d36aa043ee90, for GNU/Linux 3.2.0, stripped
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/Xoxor)-[2023.05.06|14:15:11(HKT)]
└> chmod +x xoxor
```

It's an ELF 64-bit executable.

**Let's try to run that:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/Xoxor)-[2023.05.06|14:15:14(HKT)]
└> ./xoxor         
Hello! In order to access the shopping panel, please insert the password and do not cheat this time:
idk
Please excuse us, only authorized persons can access this panel.
```

As you can see, it requires a correct password.

**Now, we can fire up Ghidra to decompile the executable:**
```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/Xoxor)-[2023.05.06|14:16:22(HKT)]
└> ghidra
```

**After decompiled, we see function `FUN_00101268()`:**
```c
void FUN_00101268(void)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  char *__s2;
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  sVar2 = strlen("aezx$K+`mcwL<+_3/0S^84B^V8}~8\\TXWmnmFP_@T^RTJ");
  sVar3 = strlen("1245a0eP2475cr0Fpsg0grs02g0Mg4g02LOLg5gs2g0g7");
  __s2 = (char *)FUN_001011e9("aezx$K+`mcwL<+_3/0S^84B^V8}~8\\TXWmnmFP_@T^RTJ",
                              "1245a0eP2475cr0Fpsg0grs02g0Mg4g02LOLg5gs2g0g7",sVar2 & 0xffffffff,
                              sVar3 & 0xffffffff);
  puts(
      "Hello! In order to access the shopping panel, please insert the password and do not cheat thi s time:"
      );
  fgets(local_118,0xff,stdin);
  sVar2 = strlen(local_118);
  local_118[(int)sVar2 + -1] = '\0';
  iVar1 = strcmp(local_118,__s2);
  if (iVar1 == 0) {
    puts("Welcome, you now have access to the shopping panel.");
  }
  else {
    puts("Please excuse us, only authorized persons can access this panel.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This looks like the `main()` function.

**In here, there are 2 interesting strings:**
```
aezx$K+`mcwL<+_3/0S^84B^V8}~8\\TXWmnmFP_@T^RTJ
1245a0eP2475cr0Fpsg0grs02g0Mg4g02LOLg5gs2g0g7
```

**Those 2 strings and it's length are being parsed to function `FUN_001011e9()`:**
```c
void * FUN_001011e9(long param_1,long param_2,int param_3,int param_4)

{
  void *pvVar1;
  int local_14;
  
  pvVar1 = malloc((long)param_3);
  for (local_14 = 0; local_14 < param_3; local_14 = local_14 + 1) {
    *(byte *)((long)pvVar1 + (long)local_14) =
         *(byte *)(param_1 + local_14) ^ *(byte *)(param_2 + local_14 % param_4);
  }
  return pvVar1;
}
```

This function will XOR those 2 strings.

That being said, **we can find the correct password by XOR'ing those 2 strings!!**

To do so, we can write a Python script.

**However, instead of converting function `FUN_001011e9()` by hand, we can use LLM to help us, like ChatGPT!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/PwnMe-2023-8-bits/images/Pasted%20image%2020230506142948.png)

**Then after few modification, it XOR'ed the correct password!**
```py
#!/usr/bin/env python3

def FUN_001011e9(param_1, param_2, param_3, param_4):
    pvVar1 = bytearray(param_3)
    for local_14 in range(param_3):
        pvVar1[local_14] = ord(param_1[local_14]) ^ ord(param_2[local_14 % param_4])
    return bytes(pvVar1).decode()

if __name__ == '__main__':
    string1 = '''aezx$K+`mcwL<+_3/0S^84B^V8}~8\\TXWmnmFP_@T^RTJ'''
    string2 = '''1245a0eP2475cr0Fpsg0grs02g0Mg4g02LOLg5gs2g0g7'''
    string1Length = len(string1)
    string2Length = len(string2)

    print(FUN_001011e9(string1, string2, string1Length, string2Length))
```

```shell
┌[siunam♥earth]-(~/ctf/PwnMe-2023-8-bits/Reverse/Xoxor)-[2023.05.06|14:26:56(HKT)]
└> python3 solve.py
PWNME{N0_W@y_You_C4n_F1nd_M3_h3he!!!!e83f9b3}
```

- **Flag: `PWNME{N0_W@y_You_C4n_F1nd_M3_h3he!!!!e83f9b3}`**

## Conclusion

What we've learned:

1. Reversing XOR'ed Strings