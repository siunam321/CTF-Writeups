# Initialise Connection

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

In order to proceed, we need to start with the basics. Start an instance, connect to it via $ nc e.g. nc 127.0.0.1 1337 and send "1" to get the flag.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319130432.png)

## Find the flag

**As the challenge's descript said, `nc` to the instance machine, and send `1`:**
```
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023)-[2023.03.19|13:04:50(HKT)]
└> nc 165.22.116.7 32664          

▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣
▣                            ▣
▣  Enter 1 to get the flag!  ▣
▣                            ▣
▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣▣

>> 1
HTB{g3t_r34dy_f0r_s0m3_pwn}
```

- **Flag: `HTB{g3t_r34dy_f0r_s0m3_pwn}`**

## Conclusion

What we've learned:

1. How To Use `nc` (NetCat)