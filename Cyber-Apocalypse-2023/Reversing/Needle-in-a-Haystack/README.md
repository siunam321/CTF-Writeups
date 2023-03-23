# Needle in a Haystack

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

You've obtained an ancient alien Datasphere, containing categorized and sorted recordings of every word in the forgotten intergalactic common language. Hidden within it is the password to a tomb, but the sphere has been worn with age and the search function no longer works, only playing random recordings. You don't have time to search through every recording - can you crack it open and extract the answer?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230319135849.png)

## Find the flag

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Reversing/Needle-in-a-Haystack/rev_needle_haystack.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Needle-in-a-Haystack)-[2023.03.19|13:57:54(HKT)]
└> file rev_needle_haystack.zip 
rev_needle_haystack.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Needle-in-a-Haystack)-[2023.03.19|13:57:56(HKT)]
└> unzip rev_needle_haystack.zip 
Archive:  rev_needle_haystack.zip
   creating: rev_needle_haystack/
  inflating: rev_needle_haystack/haystack
```

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Needle-in-a-Haystack/rev_needle_haystack)-[2023.03.19|13:58:17(HKT)]
└> file haystack               
haystack: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4c6530f229889e6e1a1fe1e2f57add742ef51fd8, for GNU/Linux 3.2.0, not stripped
```

The `haystack` file is a 64-bit ELF executable, and it's not stripped.

Let's try to run that!

```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Needle-in-a-Haystack/rev_needle_haystack)-[2023.03.19|13:58:07(HKT)]
└> ./haystack            
Hit enter to select a recording: 
..."vayurjol"
```

Hmm... Looks like it's fetching some string from the executable??

**If so, we can use `strings` to list out all the strings in that executable:**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Reversing/Needle-in-a-Haystack/rev_needle_haystack)-[2023.03.19|13:58:13(HKT)]
└> strings haystack
[...]
cyunkro
kroucaloc,
HTB{d1v1ng_1nt0_th3_d4tab4nk5}
[...]
```

We found it!

- **Flag: `HTB{d1v1ng_1nt0_th3_d4tab4nk5}`**

## Conclusion

What we've learned:

1. Listing Strings In A File Via `strings` 