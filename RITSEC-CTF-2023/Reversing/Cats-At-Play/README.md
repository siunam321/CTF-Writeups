# Cats At Play

- 50 Points / 355 Solves

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆☆

## Background

My cat has decided to become a programmer. What a silly guy!

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401183827.png)

## Find the flag

**In this challenge, we can download a file:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Reversing/Cats-At-Play)-[2023.04.01|18:39:26(HKT)]
└> file meow.exe 
meow.exe: PE32 executable (console) Intel 80386, for MS Windows, 4 sections
```

It's an 32-bit executable for Windows.

**As the challenge's title suggested, let's use `strings` and `grep` to find the flag!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Reversing/Cats-At-Play)-[2023.04.01|18:40:44(HKT)]
└> strings meow.exe | grep -E '^RS'
RS{C4tsL1keStr1ng5}
```

The `strings <filename>` will list out all the strings inside that file.

The `grep -E '^RS'` will grab anything that starts with `RS`.

- **Flag: `RS{C4tsL1keStr1ng5}`**

## Conclusion

What we've learned:

1. Using `strings` To List Out All The Strings Inside A File