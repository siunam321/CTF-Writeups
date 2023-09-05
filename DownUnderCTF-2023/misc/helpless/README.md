# helpless

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Find The Flag](#find-the-flag)
4. [Conclusion](#conclusion)

## Overview

- Contributor: @Foo
- Solved by: @siunam
- 293 solves / 100 points
- Author: hashkitten
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

I accidentally set my system shell to the Python `help()` function! Help!!

The flag is at `/home/ductf/flag.txt`.

The password for the `ductf` user is `ductf`.

Author: hashkitten

`ssh ductf@2023.ductf.dev -p30022`

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230904220117.png)

## Find The Flag

**In this challenge, we can SSH into the challenge instance:**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/Misc/helpless)-[2023.09.04|22:01:49(HKT)]
└> ssh ductf@2023.ductf.dev -p30022 
ductf@2023.ductf.dev's password: 
[...]
Welcome to Python 3.10's help utility!

If this is your first time using Python, you should definitely check out
the tutorial on the internet at https://docs.python.org/3.10/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing
Python programs and using Python modules.  To quit this help utility and
return to the interpreter, just type "quit".

To get a list of available modules, keywords, symbols, or topics, type
"modules", "keywords", "symbols", or "topics".  Each module also comes
with a one-line summary of what it does; to list the modules whose name
or summary contain a given string such as "spam", type "modules spam".

help> 
```

As expected, our shell became Python's `help()` function.

According to [Python built-in function `help()` documentation](https://docs.python.org/3/library/functions.html#help), this function will **display a given module's details.**

**Let's say I wanna view `os` module details:**
```shell
help> os
Help on module os:

NAME
    os - OS routines for NT or Posix depending on what system we're on.

MODULE REFERENCE
    https://docs.python.org/3.10/library/os.html
    
    The following documentation is automatically generated from the Python
    source files.  It may be incomplete, incorrect or include features that
    are considered implementation detail and may vary between Python
    implementations.  When in doubt, consult the module reference at the
    location listed above.

DESCRIPTION
    This exports:
      - all functions from posix or nt, e.g. unlink, stat, etc.
      - os.path is either posixpath or ntpath
      - os.name is either 'posix' or 'nt'
      - os.curdir is a string representing the current directory (always '.')
      - os.pardir is a string representing the parent directory (always '..')
:
```

Wait... What's that interactive shell? Is that `less` shell?

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/less/#file-read), we can read arbitrary files via `:e` command:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230904225659.png)

**Let's read the flag!**
```shell
Examine: /home/ductf/flag.txt
DUCTF{sometimes_less_is_more}
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
~
/home/ductf/flag.txt (file 2 of 2) (END)
```

- **Flag: `DUCTF{sometimes_less_is_more}`**

## Conclusion

What we've learned:

1. Python built-in function `help()` shell escape