# Dirt

## Overview

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

- Challenge static score: 50

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121134117.png)

## Find the flag

**In the challenge's description, we can download an attachment. Let's download it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121134232.png)

```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Dirt)-[2023.01.21|13:42:50(HKT)]
└> file dirt.zip   
dirt.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

**It's a `zip` archive file. We can `unzip` that:**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023/Misc/Dirt)-[2023.01.21|13:42:52(HKT)]
└> unzip dirt.zip 
Archive:  dirt.zip
   creating: challenge/
   creating: challenge/}/
   creating: challenge/}/s/
   creating: challenge/}/s/r/
   creating: challenge/}/s/r/3/
   creating: challenge/}/s/r/3/d/
   creating: challenge/}/s/r/3/d/l/
   creating: challenge/}/s/r/3/d/l/0/
   creating: challenge/}/s/r/3/d/l/0/f/
   creating: challenge/}/s/r/3/d/l/0/f/_/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/f/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/f/{/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/f/{/F/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/f/{/F/T/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/f/{/F/T/C/
   creating: challenge/}/s/r/3/d/l/0/f/_/3/d/1/5/n/1/_/s/r/3/d/l/0/f/{/F/T/C/K/
```

**Oh! Looks like we found the flag??**
```
}sr3dl0f_3d15n1_sr3dl0f{FTCK
```

**However, it looks like it's reversed. Let's use `rev` to reverse it back:**
```shell
┌[root♥siunam]-(~/ctf/KnightCTF-2023)-[2023.01.21|13:44:58(HKT)]
└> echo '}sr3dl0f_3d15n1_sr3dl0f{FTCK' | rev
KCTF{f0ld3rs_1n51d3_f0ld3rs}
```

Nice! We found the flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/KnightCTF-2023/images/Pasted%20image%2020230121134614.png)

- **Flag: `KCTF{f0ld3rs_1n51d3_f0ld3rs}`**

# Conclusion

What we've learned:

1. Unziping File & Reversing Strings