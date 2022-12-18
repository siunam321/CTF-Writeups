# catscii

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge difficulty: Easy

## Background

Author: @JohnHammond#6971  
  
Do you know what the [`cat`](https://en.wikipedia.org/wiki/Cat_(Unix)) command does in the Linux command-line?  
  
**Download the files below.**

**Attachments:**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/catscii]
└─# file catscii         
catscii: ASCII text
```

## Find The Flag

**In the challenge's background and the title, it's clear that we need to use Linux command `cat` to concatenate(read) the flag!**
```
┌──(root🌸siunam)-[~/ctf/NahamCon-EU-CTF-2022/Warmups/catscii]
└─# cat catscii     

    ,_     _
    |\\_,-~/
    / _  _ |    ,--.
   (  @  @ )   / ,-'
    \  _T_/-._( (      Your `cat` found a flag! 
    /         `. \     This is what the standard flag format looks like...
   |         _  \ |    Submit these on the scoreboard for points!
    \ \ ,  /      |
     || |-_\__   /
    ((_/`(____,-'      flag{258da40ab06be7c99099d603a3b3ccb1}
```

Found it!

- **Flag: `flag{258da40ab06be7c99099d603a3b3ccb1}`**

# Conclusion

What we've learned:

1. Linux Reading File via `cat`