# Secured Transfer

## Background

> Ghosts have been sending messages to each other through the aether, but we can't understand a word of it! Can you understand their riddles?

> Difficulty: Easy

- Overall difficulty for me: Easy

**In this challenge, we can [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/rev_securedtransfer.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# unzip rev_securedtransfer.zip 
Archive:  rev_securedtransfer.zip
  inflating: securetransfer          
  inflating: trace.pcap
```

## Find the flag

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# file trace.pcap 
trace.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

**Let's inspect that in WireShark!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# wireshark trace.pcap
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a2.png)

We can see there are 8 packets.

**How about the `securetransfer`?**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# file securetransfer       
securetransfer: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0457997eda987eb100de85a2954fc8b8fc660a53, for GNU/Linux 3.2.0, stripped

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# chmod +x securetransfer
```

**`strings`:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# strings securetransfer
[...]
someinitialvalue
ERROR: Socket creation failed
ERROR: Invalid input address '%s'
ERROR: Connection failed
ERROR: Can't open the file '%s'
ERROR: File too small
ERROR: File too large
ERROR: Failed reading the file
File send...
ERROR: Socket bind failed
ERROR: Listen failed
ERROR: Accept failed
ERROR: Reading secret length
ERROR: File send doesn't match length
File Received...
Sending File: %s to %s
Receiving File
Usage ./securetransfer [<ip> <file>]
[...]
```

**Let's reverse engineering it via `ghidra`:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# ghidra
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a3.png)

**In this function, we can see something:**
- Using `OPENSSL_init_crypto` to encrypt data
- If argument equals to 3, it'll send a file to the receiver, and run function `FUN_00101835`
- If argument equals to 1, it'll get the file from the sender, and run function `FUN_00101b37`

**Let's rename it to `send_and_receive` function:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a4.png)

**In the function `FUN_00101529`, it seems like it's a encrypting data:**
```c
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 's';
  local_2f = 0x65;
  local_2e = 0x74;
  local_2d = 0x6b;
  local_1d = 0x74;
  local_1c = 0x69;
  local_37 = 0x75;
  local_36 = 0x70;
  local_22 = 0x6e;
  local_21 = 99;
  local_1b = 0x6f;
  local_32 = 0x65;
  local_31 = 99;
  local_33 = 0x73;
  local_20 = 0x72;
  local_1f = 0x79;
  local_30 = 0x72;
  local_26 = 0x66;
  local_25 = 0x6f;
  local_24 = 0x72;
  local_1a = 0x6e;
  local_2c = 0x65;
  local_2b = 0x79;
  local_2a = 0x75;
  local_29 = 0x73;
  local_28 = 0x65;
  local_27 = 100;
  local_23 = 0x65;
  local_35 = 0x65;
  local_34 = 0x72;
  local_1e = 0x70;
  local_19 = 0x21;
  local_48 = "someinitialvalue";
  local_40 = EVP_CIPHER_CTX_new();
  if (local_40 == (EVP_CIPHER_CTX *)0x0) {
    iVar1 = 0;
  }
  else {
    cipher = EVP_aes_256_cbc();
    iVar1 = EVP_EncryptInit_ex(local_40,cipher,(ENGINE *)0x0,&local_38,(uchar *)local_48);
    if (iVar1 == 1) {
      iVar1 = EVP_EncryptUpdate(local_40,param_3,&local_50,param_1,param_2);
      if (iVar1 == 1) {
        local_4c = local_50;
        iVar1 = EVP_EncryptFinal_ex(local_40,param_3 + local_50,&local_50);
        if (iVar1 == 1) {
          local_4c = local_4c + local_50;
          EVP_CIPHER_CTX_free(local_40);
          iVar1 = local_4c;
        }
        else {
          iVar1 = 0;
        }
      }
      else {
        iVar1 = 0;
      }
    }
    else {
      iVar1 = 0;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```

**Let's break it down:**
- `local_48 = "someinitialvalue";`, maybe is the encryption key?
- `cipher` = AES 256 CBC

**In the function `FUN_001016af`, it's a decryption function:**
```c
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 's';
  local_2f = 0x65;
  local_37 = 0x75;
  local_36 = 0x70;
  local_26 = 0x66;
  local_25 = 0x6f;
  local_24 = 0x72;
  local_21 = 99;
  local_2e = 0x74;
  local_2d = 0x6b;
  local_1d = 0x74;
  local_1b = 0x6f;
  local_32 = 0x65;
  local_31 = 99;
  local_33 = 0x73;
  local_20 = 0x72;
  local_2b = 0x79;
  local_2a = 0x75;
  local_29 = 0x73;
  local_1c = 0x69;
  local_28 = 0x65;
  local_27 = 100;
  local_23 = 0x65;
  local_1f = 0x79;
  local_30 = 0x72;
  local_34 = 0x72;
  local_1e = 0x70;
  local_19 = 0x21;
  local_1a = 0x6e;
  local_2c = 0x65;
  local_35 = 0x65;
  local_22 = 0x6e;
  local_48 = "someinitialvalue";
  local_40 = EVP_CIPHER_CTX_new();
  if (local_40 == (EVP_CIPHER_CTX *)0x0) {
    iVar1 = 0;
  }
  else {
    cipher = EVP_aes_256_cbc();
    iVar1 = EVP_DecryptInit_ex(local_40,cipher,(ENGINE *)0x0,&local_38,(uchar *)local_48);
    if (iVar1 == 1) {
      iVar1 = EVP_DecryptUpdate(local_40,param_3,&local_50,param_1,param_2);
      if (iVar1 == 1) {
        local_4c = local_50;
        iVar1 = EVP_DecryptFinal_ex(local_40,param_3 + local_50,&local_50);
        if (iVar1 == 1) {
          local_4c = local_4c + local_50;
          EVP_CIPHER_CTX_free(local_40);
          iVar1 = local_4c;
        }
        else {
          iVar1 = 0;
        }
      }
      else {
        iVar1 = 0;
      }
    }
    else {
      iVar1 = 0;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar1;
}
```

Hmm... This got me thinking: **What if I capture the decryption key in GDB??**

**Let's fire up GDB!**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# gdb securetransfer 
[...]
```

**First, I wanna know where is the address of the decryption function:**
```
gef➤  info functions
All defined functions:
[...]
0x00005555555552f0  EVP_DecryptInit_ex@plt
[...]
```

The `EVP_DecryptInit_ex` function looks good!

**Let's set a breakpoint in that address:**
```
gef➤  break *EVP_DecryptInit_ex
Breakpoint 1 at 0x7ffff7d86cd0
```

**Run the executable:**
```
gef➤  run
[...]
Starting program: /root/ctf/HackTheBoo/Reversing/Secured-Transfer/securetransfer 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Receiving File

```

**Now, let's create a text file for transfer:**
```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# python3 -c "print('A' * 32)" > text.txt

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Reversing/Secured-Transfer]
└─# ./securetransfer 127.0.0.1 text.txt
```

**Check GDB:**
```
Breakpoint 1, 0x00007ffff7d86cd0 in EVP_DecryptInit_ex () from /lib/x86_64-linux-gnu/libcrypto.so.1.1

[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00555555574d30  →  0x0000000000000000
$rbx   : 0x0               
$rcx   : 0x007fffffffdbe0  →  "supersecretkeyusedforencryption!"
$rdx   : 0x0               
$rsp   : 0x007fffffffdb98  →  0x005555555557a1  →   cmp eax, 0x1
$rbp   : 0x007fffffffdc10  →  0x007fffffffdc80  →  0x007fffffffdca0  →  0x0000000000000001
$rsi   : 0x007ffff7ec8d40  →  0x00000010000001ab
$rdi   : 0x00555555574d30  →  0x0000000000000000
$rip   : 0x007ffff7d86cd0  →  <EVP_DecryptInit_ex+0> xor r9d, r9d
$r8    : 0x00555555556008  →  "someinitialvalue"
[...]
```

**Boom! We got the encryption key!**

- Encryption key: `supersecretkeyusedforencryption!`

**Let's go back to the pcap file:**

**In the fifth packet, you can see there is a 32 bytes hex data:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a5.png)

**This looks like the encrypted message, which is the flag!**

**Let's copy that and decrypt it!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a6.png)

**For AES 256 CBC decryption, I'll use an [online tool](https://www.devglan.com/online-tools/aes-encryption-decryption):** (I tried to use CyberChef, but no dice.)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a7.png)

We see half of the flag... Maybe we need the `IV`?

**Let's think back. In `ghidra`, we saw a weird string: `someinitialvalue`.**

**Let's use this as the `IV`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Reversing/Secured-Transfer/images/a8.png)

Yes! We got the flag!

# Conclusion

What we've learned:

1. Decrypting AES 256 CBC via Capturing Decryption Key in GDB